"""Cooperative compiled-target authorization and attestation; O(N) event storage.

The linked target adapter is trusted to request authorization before its I/O.
This protocol does not confine arbitrary native programs that omit the adapter.
"""
from __future__ import annotations
import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets
import socket
import subprocess
import threading
import time
from types import SimpleNamespace
from verikernel.m2_enforcer.diff_engine import ContractEnforcer, ghost_diff
from verikernel.m5_ringbuf.native import library_path
from verikernel.omnibor import gitoid_sha256
from verikernel.rust_bridge import BatchEngine, rust_compute_site_key
from verikernel.schemas import KernelTelemetryEvent
from verikernel.type_boundaries import ContractDict, GhostDiffItemDict


def target_binary() -> Path:
    """Find the target beside the matching native library; O(1) space and time."""
    name = 'vk-target-bin.exe' if os.name == 'nt' else 'vk-target-bin'
    result = Path(str(library_path()._name)).parent/name
    if not result.is_file():
        raise FileNotFoundError('build the native workspace before target verification')
    return result


class NativeTargetSupervisor:
    """Authorize trusted native boundary requests; O(N) event/violation space."""
    def __init__(self, contract: ContractDict, mode: str = 'audit', fault_sites: set[int] | None = None, seed: int = 0) -> None:
        """Compile capability policy; O(C) time and space for C declared targets."""
        if mode not in {'audit', 'strict'}:
            raise ValueError('invalid enforcement mode')
        self.policy = ContractEnforcer(contract)
        self.mode, self.fault_sites, self.seed = mode, set(fault_sites or ()), seed

    def run(self, binary: str | Path, arguments: list[str], bundle: str | Path, timeout: float = 30) -> dict[str, object]:
        """Execute the real binary and seal authorized boundaries; O(N + B) work/space."""
        from verikernel.cli.main import pack_receipt
        binary = Path(binary).resolve(strict=True)
        identity = gitoid_sha256(binary.read_bytes())
        token = secrets.token_hex(32)
        events: list[KernelTelemetryEvent] = []
        violations: list[GhostDiffItemDict] = []
        failures: list[str] = []
        schedule: list[dict[str, int]] = []
        launched = threading.Event()
        stopped = threading.Event()
        pid = 0
        with socket.socket() as listener:
            listener.bind(('127.0.0.1', 0))
            listener.listen(8)
            listener.settimeout(0.1)
            def collect() -> None:
                """Service bounded authenticated requests; O(N + B) work and O(B) scratch."""
                launched.wait(timeout)
                while not stopped.is_set():
                    try:
                        stream, address = listener.accept()
                    except socket.timeout:
                        continue
                    try:
                        with stream:
                            stream.settimeout(5)
                            with stream.makefile('rb') as incoming:
                                raw = incoming.readline(65537)
                            if len(raw) > 65536 or not raw.endswith(b'\n'):
                                raise ValueError('invalid native IPC frame')
                            request = json.loads(raw)
                            if not isinstance(request, dict) or not isinstance(request.get('token'), str) or not hmac.compare_digest(request['token'], token):
                                raise ValueError('native IPC authentication failed')
                            if type(request.get('pid')) is not int or request['pid'] != pid or type(request.get('tid')) is not int or request['tid'] <= 0:
                                raise ValueError('native process identity mismatch')
                            operation, target = request.get('operation'), request.get('target')
                            if type(operation) is not int or operation not in {1, 2, 5, 9, 10} or not isinstance(target, str):
                                raise ValueError('unsupported native boundary request')
                            if operation in {1, 2, 9, 10}:
                                target = os.path.realpath(target)
                            violation = self.policy.violation(operation, target)
                            if violation:
                                violations.append(violation)
                            index = len(events)
                            stack = rust_compute_site_key(0, operation, 0, self.seed)
                            code = -13 if violation and self.mode == 'strict' else -28 if operation == 10 and index in self.fault_sites else 0
                            if code == -28:
                                schedule.append({'site_id':index, 'syscall_nr':operation, 'code':code, 'stack_hash':stack})
                            stat = Path(target).stat() if operation in {1, 2, 9, 10} and Path(target).exists() else None
                            events.append(KernelTelemetryEvent(seq_no=index, timestamp_ns=time.monotonic_ns(), pid=pid, tid=request['tid'], syscall_nr=operation, fault_injected=code,
                                dev_id=stat.st_dev if stat else 0, inode_nr=stat.st_ino if stat else 0, mtime_ns=stat.st_mtime_ns if stat else 0,
                                call_stack_hash=stack, target_digest=hashlib.sha256(target.encode()).digest()))
                            stream.sendall((str(code)+'\n').encode())
                    except (OSError, ValueError, TypeError) as error:
                        failures.append(str(error))
            collector = threading.Thread(target=collect, name='native-boundary-collector')
            collector.start()
            environment = os.environ.copy()
            environment.update(VK_NATIVE_IPC='127.0.0.1:'+str(listener.getsockname()[1]), VK_NATIVE_TOKEN=token)
            started = time.perf_counter()
            try:
                with subprocess.Popen([str(binary), *arguments], env=environment, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True) as process:
                    pid = process.pid
                    launched.set()
                    try:
                        stdout, stderr = process.communicate(timeout=timeout)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.communicate()
                        raise
                    returncode = process.returncode
            finally:
                launched.set()
                stopped.set()
                collector.join(timeout=6)
            if collector.is_alive() or failures:
                raise ValueError('incomplete native capture: '+str(failures))
        if not events or events[0].syscall_nr != 1:
            raise ValueError('target did not complete the native adapter handshake')
        packed = bytearray(b''.join(event.to_bytes() for event in events))
        seed = secrets.token_bytes(32)
        c0, kn = BatchEngine().seal(packed, seed)
        sealed = [KernelTelemetryEvent.from_bytes(packed[i:i+128]) for i in range(0, len(packed), 128)]
        manifest = {'backend':'cooperative-linked-native', 'scope':'trusted linked pre-operation adapter; records attempts, not successful kernel completions',
                    'target_gitoid':identity, 'returncode':returncode, 'patch':ghost_diff(violations), 'schedule':schedule, 'seed':self.seed,
                    'process_tree':[{'pid':pid, 'parent_pid':os.getpid()}]}
        pack_receipt(bundle, manifest, sealed, seed, SimpleNamespace(commitment=c0, terminal=kn, hash_algorithm='sha256'))
        return {'returncode':returncode, 'pid':pid, 'event_count':len(sealed), 'stdout':stdout, 'stderr':stderr,
                'elapsed_seconds':time.perf_counter()-started, 'target_gitoid':identity, 'bundle':str(bundle)}
