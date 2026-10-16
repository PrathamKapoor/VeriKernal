"""Linux hal."""
from __future__ import annotations
import hashlib
import hmac
import json
import os
import platform
import subprocess
import sys
import sysconfig
import tempfile
import threading
from pathlib import Path
from verikernel.schemas import KernelTelemetryEvent


def export_policy(contract: object, runtime_paths: object=None, machine: object=None) -> object:
    """Translate a dependency contract into native supervisor policy. Complexity: O(n + W) time and O(n + M) space; n is traversed data, W delegated work, M retained delegated state."""
    machine = machine or platform.machine()
    tables = {"aarch64": (0xC00000B7, [56, 221, 203, 63, 64, 113, 278]), "arm64": (0xC00000B7, [56, 221, 203, 63, 64, 113, 278]), "x86_64": (0xC000003E, [257, 59, 42, 0, 1, 228, 318]), "amd64": (0xC000003E, [257, 59, 42, 0, 1, 228, 318])}
    if machine.lower() not in tables:
        raise ValueError("unsupported Linux syscall architecture")
    architecture, numbers = tables[machine.lower()]
    if runtime_paths is None:
        runtime_paths = [str(Path(sys.executable).resolve()), sys.base_prefix, sys.prefix, "/lib", "/usr/lib", "/usr/local/lib", "/dev/null", "/dev/urandom", "/proc"]
    writable = sorted({str(Path(path).resolve(strict=True)) for path in contract.get("filesystem", [])})
    readable = sorted({str(Path(path).resolve(strict=True)) for path in runtime_paths if Path(path).exists()})
    return {"architecture": architecture, "notify_syscalls": numbers, "read_only": readable, "read_write": writable, "network": list(contract.get("network", []))}


def verify_kernel_stream(events: object, seeds: object, expected_terminal: object) -> bool:
    """Authenticate a captured native telemetry stream. Complexity: O(n + W) time and O(n + M) space; n is traversed data, W delegated work, M retained delegated state."""
    if len(seeds) != len(expected_terminal) or not seeds or any(len(seed) != 32 for seed in seeds):
        return False
    states = list(seeds)
    for index, event in enumerate(events):
        if event.seq_no != index:
            return False
        matched = []
        for cpu, key in enumerate(states):
            tag = hashlib.blake2b(b"VK-RATCHET-TAG-V1" + key + event.to_bytes()[:96], digest_size=32).digest()
            if hmac.compare_digest(tag, event.ratchet_tag):
                matched.append(cpu)
        if len(matched) != 1:
            return False
        cpu = matched[0]
        states[cpu] = hashlib.blake2b(b"VK-RATCHET-STEP-V1" + states[cpu] + event.ratchet_tag, digest_size=32).digest()
    return all(hmac.compare_digest(a, b) for a, b in zip(states, expected_terminal))


def supervisor_path() -> object:
    """Locate the native confinement supervisor for this platform. Complexity: O(n + W) time and O(n + M) space; n is traversed data, W delegated work, M retained delegated state."""
    root = Path(__file__).resolve().parents[3]
    explicit = os.environ.get("VERIKERNEL_LINUX_SUPERVISOR")
    machine = "aarch64" if platform.machine() in {"aarch64", "arm64"} else "x86_64"
    candidates = [Path(explicit)] if explicit else []
    candidates += [root / "dist/native" / (machine + "-unknown-linux-" + abi) / "verikernel-linux" for abi in ["gnu", "musl"]]
    for build in [root / ".tmp" / "target", root / "target"]:
        candidates += [build / "debug" / "verikernel-linux", build / (machine + "-unknown-linux-musl") / "debug" / "verikernel-linux"]
    for path in candidates:
        if path.is_file():
            return path
    raise OSError("Linux supervisor executable is unavailable; build verikernel-core")


def consume_native_stream(stream: object) -> object:
    """Decode captured native records and retain their execution metadata. Complexity: O(n + W) time and O(n + M) space; n is traversed data, W delegated work, M retained delegated state."""
    from verikernel.m4_attest.epoch_service import EpochAttestor
    from verikernel.m4_attest.ratchet import ForwardSecureRatchet, HASH_ALGORITHM
    try:
        header = json.loads(next(iter(stream)))
    except StopIteration as exc:
        raise ValueError("native stream has no header") from exc
    if header.get("kind") != "header":
        raise ValueError("native stream has no header")
    if header.get("hash_algorithm") != HASH_ALGORITHM:
        raise ValueError("native hash profile unavailable; install the declared hash dependency")
    seed = bytes.fromhex(header["audit_seed"])
    verifier = ForwardSecureRatchet(seed)
    if not hmac.compare_digest(verifier.commitment, bytes.fromhex(header["commitment"])):
        raise ValueError("native initial commitment mismatch")
    terminal, observations = None, []
    with EpochAttestor(seed=seed) as service:
        for line in stream:
            record = json.loads(line)
            if terminal is not None:
                raise ValueError("data follows native terminal")
            if record.get("kind") == "event":
                event = KernelTelemetryEvent.from_bytes(bytes.fromhex(record["bytes"]))
                expected = event.ratchet_tag
                if event.seq_no != len(observations):
                    raise ValueError("native sequence mismatch")
                verifier.tag(event)
                if not hmac.compare_digest(expected, event.ratchet_tag):
                    raise ValueError("native producer authentication mismatch")
                service.submit(event)
                observations.append((event.syscall_nr, record["target"]))
            elif record.get("kind") == "terminal":
                terminal = record
            else:
                raise ValueError("unknown native stream record")
        if terminal is None or terminal["event_count"] != len(observations) or not hmac.compare_digest(bytes.fromhex(terminal["terminal"]), verifier.terminal):
            raise ValueError("native terminal mismatch or truncation")
    terminal.update(backend=header.get("backend", "linux-landlock-seccomp"), observations=observations)
    return terminal, service


def run_native(script: object, contract: object, mode: str="strict") -> object:
    """Launch the native workload and collect its supervisor records. Complexity: O(n + W) time and O(n + M) space; n is traversed data, W delegated work, M retained delegated state."""
    if sys.platform != "linux":
        raise OSError("native confinement requires Linux")
    if mode not in {"audit", "strict"}:
        raise ValueError("invalid native enforcement mode")
    script = Path(script).resolve(strict=True)
    policy = export_policy(contract)
    if mode == "audit":
        policy["read_write"] = ["/"]
        policy["network"] = ["*"]
    policy["read_only"].append(str(script))
    root = Path(__file__).resolve().parents[3]
    control = root / ".tmp" / ("policy-" + os.urandom(12).hex() + ".json")
    control.parent.mkdir(exist_ok=True)
    control.write_text(json.dumps(policy))
    try:
        with tempfile.TemporaryFile(dir=root / ".tmp", mode="w+", encoding="utf-8") as errors:
            with subprocess.Popen([str(supervisor_path()), "stream", str(control), sys.executable, str(script)], stdout=subprocess.PIPE, stderr=errors, text=True) as process:
                timer = threading.Timer(120, process.terminate)
                timer.daemon = True
                timer.start()
                try:
                    result, service = consume_native_stream(process.stdout)
                    if process.wait(timeout=10) != 0:
                        raise OSError("native supervisor failed")
                finally:
                    timer.cancel()
                    if process.poll() is None:
                        process.terminate()
                        try:
                            process.wait(timeout=5)
                        except subprocess.TimeoutExpired:
                            process.kill()
                            process.wait()
                errors.seek(0)
                diagnostic = errors.read()
                if diagnostic:
                    print(diagnostic, end="", file=sys.stderr)
    finally:
        control.unlink()
    events, seed, ratchet = service.events, service.audit_seed, service.ratchet
    from .diff_engine import ContractEnforcer, ghost_diff
    enforcer = ContractEnforcer(contract)
    violations = [violation for operation, target in result["observations"] if (violation := enforcer.violation(operation, target))]
    from verikernel.omnibor import file_gitoid
    manifest = {"script": str(script), "source_gitoid": file_gitoid(script), "backend": result["backend"], "contract": contract, "native_policy": policy, "mode": mode, "capabilities": {"kernel_isolation": mode == "strict", "seccomp_notification": True, "native_child_observation": True, "atomic_filesystem_policy": mode == "strict"}, "error": None if result["status"] == 0 else {"type": "NativeWorkloadFailure", "status": result["status"]}, "schedule": [], "patch": ghost_diff(violations, contract.get("contract_gitoid")), "epochs": service.epochs, "epoch_public_key": service.public_key.hex()}
    return manifest, events, seed, ratchet
