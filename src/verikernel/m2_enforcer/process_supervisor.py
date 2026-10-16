"""Cooperative Python process-tree telemetry; O(n log n) merge time and O(n) space."""
from __future__ import annotations
import atexit
import hashlib
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import threading
import time
from types import SimpleNamespace
from verikernel.schemas import KernelTelemetryEvent


def install_child(config_path: str) -> None:
    """Install inherited boundary hooks and append-only per-PID spooling; O(n) time/space."""
    from .hal import RuntimeInterceptorHAL
    from verikernel.m3_fault.injector import SyscallFaultInjector
    config = json.loads(Path(config_path).read_text(encoding='utf-8'))
    directory = Path(config_path).parent
    pid = os.getpid()
    spool = (directory/f'child_events_{pid}.bin').open('xb',buffering=0)
    node_path = directory/f'process_{pid}.json'
    role = Path(sys.argv[0]).name
    schedules = config['fault_schedule']
    schedule = schedules.get(role) if isinstance(schedules,dict) else schedules
    injector = SyscallFaultInjector(config['fault_seed'],config['probability'],schedule=schedule,syscall_types={2,3,4,7,9,10})
    root = Path(config['target_root'])

    class ChildHAL(RuntimeInterceptorHAL):
        """Spool each observed boundary once, under the session lock; O(1) per record."""
        def record(self, operation: int, target: str, apply_fault: bool = True) -> object:
            """Retain an observed event for the current execution receipt. Complexity: O(n + W) time and O(n + M) space; n is traversed data, W delegated work, M retained delegated state."""
            frame = sys._getframe(1)
            active = False
            while frame:
                filename = frame.f_code.co_filename
                if not filename.startswith('<') and Path(filename).resolve().is_relative_to(root):
                    active = True
                    break
                frame = frame.f_back
            if not active:
                return None
            with self.lock:
                before = len(self.events)
                try:
                    return super().record(operation,target,apply_fault)
                finally:
                    for event in self.events[before:]:
                        spool.write(event.to_bytes())

    hal = ChildHAL(config['contract'],config['enforcement_mode'],root,injector)
    start = KernelTelemetryEvent(timestamp_ns=time.monotonic_ns(),pid=pid,tid=threading.get_native_id()&0xffffffff,syscall_nr=1,target_digest=hashlib.sha256(role.encode()).digest())
    hal.events.append(start)
    spool.write(start.to_bytes())
    node = {'pid':pid,'parent_pid':int(os.environ.get('VK_PARENT_PID',str(os.getppid()))),'os_parent_pid':os.getppid(),'role':role,'complete':False,'fault_schedule':[]}
    os.environ['VK_PARENT_PID'] = str(pid)
    node_path.write_text(json.dumps(node),encoding='utf-8')
    hal.__enter__()

    def finish() -> None:
        """Close hooks before publishing completion; O(n) serialization time/space."""
        hal.__exit__(None,None,None)
        spool.close()
        node.update(complete=True,fault_schedule=injector.schedule,violations=hal.violations)
        temporary = node_path.with_suffix('.new')
        temporary.write_text(json.dumps(node),encoding='utf-8')
        os.replace(temporary,node_path)
    atexit.register(finish)


class MultiProcessSupervisor:
    """Supervise inherited Python startup hooks; O(n log n) merge, O(n) storage.

    Preload participation is cooperative: -S, isolated mode, cleared environments,
    native executables and force-killed children cannot provide complete coverage.
    """
    def __init__(self, contract: dict[str,object], mode: str = 'audit', fault_seed: int = 0,
                 probability: float = 0, fault_schedule: object = None) -> None:
        """Initialize the owned state and validate configuration limits. Complexity: O(n + W) time and O(n + M) space; n is traversed data, W delegated work, M retained delegated state."""
        if mode not in {'audit','strict'} or not 0<=probability<=1:
            raise ValueError('invalid supervisor policy')
        self.contract,self.mode,self.seed = contract,mode,fault_seed
        self.probability,self.schedule = probability,fault_schedule

    def run(self, script: str | Path, bundle: str | Path, timeout: float = 60) -> dict[str,object]:
        """Launch, collect, order and seal a process tree; O(n log n) time, O(n) space."""
        from verikernel.cli.main import pack_receipt
        from verikernel.m2_enforcer.diff_engine import ghost_diff
        from verikernel.rust_bridge import BatchEngine
        from verikernel.m5_ringbuf.zero_drop_v02 import ZeroDropRingBufferV02
        root = Path(__file__).resolve().parents[3]
        script = Path(script).resolve(strict=True)
        directory = root/'.tmp'/('ipc_'+secrets.token_hex(12))
        directory.mkdir(parents=True)
        config_path = directory/'ipc_config.json'
        config = {'contract':self.contract,'contract_path':str(directory/'contract.vk.json'),'target_root':str(script.parent),'fault_seed':self.seed,'probability':self.probability,'fault_schedule':self.schedule,'enforcement_mode':self.mode}
        (directory/'contract.vk.json').write_text(json.dumps(self.contract),encoding='utf-8')
        config_path.write_text(json.dumps(config),encoding='utf-8')
        bootstrap = 'import os\nif os.environ.get("VK_SUPERVISOR_ACTIVE")=="1":\n    try:\n        from verikernel.m2_enforcer.process_supervisor import install_child\n        install_child(os.environ["VK_IPC_CONFIG"])\n    except BaseException:\n        os._exit(125)\n'
        (directory/'sitecustomize.py').write_text(bootstrap,encoding='utf-8')
        environment = os.environ.copy()
        environment.update(VK_SUPERVISOR_ACTIVE='1',VK_IPC_CONFIG=str(config_path),VK_PARENT_PID=str(os.getpid()),PYTHONDONTWRITEBYTECODE='1')
        environment['PYTHONPATH'] = os.pathsep.join([str(directory),str(root/'src'),str(root),environment.get('PYTHONPATH','')])
        for name in ['TEMP','TMP','TMPDIR']:
            environment[name] = str(root/'.tmp')
        completed = subprocess.run([sys.executable,str(script)],env=environment,cwd=script.parent,capture_output=True,text=True,timeout=timeout)
        nodes = [json.loads(path.read_text(encoding='utf-8')) for path in directory.glob('process_*.json')]
        if not nodes or any(not node['complete'] for node in nodes):
            raise ValueError('incomplete child startup or shutdown telemetry')
        events: list[KernelTelemetryEvent] = []
        for path in directory.glob('child_events_*.bin'):
            raw = path.read_bytes()
            if len(raw)%128:
                raise ValueError('partial IPC telemetry record')
            events.extend(KernelTelemetryEvent.from_bytes(raw[i:i+128]) for i in range(0,len(raw),128))
        events.sort(key=lambda event:(event.timestamp_ns,event.pid,event.seq_no))
        ring = ZeroDropRingBufferV02(deduplicate=False)
        ordered: list[KernelTelemetryEvent] = []
        for index,event in enumerate(events):
            event.seq_no = index
            ring.push(event)
            if index%64==63:
                ordered.extend(ring.drain())
        ordered.extend(ring.drain())
        packed = bytearray(b''.join(event.to_bytes() for event in ordered))
        seed = secrets.token_bytes(32)
        c0,kn = BatchEngine().seal(packed,seed)
        ordered = [KernelTelemetryEvent.from_bytes(packed[i:i+128]) for i in range(0,len(packed),128)]
        ratchet = SimpleNamespace(commitment=c0,terminal=kn,hash_algorithm='sha256')
        violations = [violation for node in nodes for violation in node.get('violations',[])]
        manifest = {'backend':'cooperative-python-process-tree','process_tree':nodes,'patch':ghost_diff(violations,self.contract.get('contract_gitoid')),'returncode':completed.returncode,'scope':'inherited Python startup hooks; absence of escaped processes is not established'}
        pack_receipt(bundle,manifest,ordered,seed,ratchet)
        return {'returncode':completed.returncode,'stdout':completed.stdout,'stderr':completed.stderr,'process_count':len(nodes),'event_count':len(ordered),'bundle':str(bundle)}
