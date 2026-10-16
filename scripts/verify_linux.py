"""Verify linux."""
from __future__ import annotations
from typing import Any
import json
import os
import subprocess
import sys
import tempfile
import socket
from pathlib import Path


def verify(supervisor: Any) -> None:
    """Validate the captured evidence and return the verification result. Complexity: O(b + W) time and O(b + M) space; b is captured input/output, W external verification work, M retained measurements."""
    if sys.platform != "linux":
        raise OSError("native integration verification requires Linux")
    root = Path(__file__).resolve().parents[1]
    (root / ".tmp").mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(dir=root / ".tmp") as directory:
        folder = Path(directory)
        allowed = folder / "allowed"
        denied = folder / "denied"
        allowed.write_text("permitted\n")
        denied.write_text("private\n")
        architecture = 0xC00000B7 if os.uname().machine == "aarch64" else 0xC000003E
        numbers = [56, 221, 203, 63, 64] if architecture == 0xC00000B7 else [257, 59, 42, 0, 1]
        policy = {"architecture": architecture, "notify_syscalls": numbers, "read_only": ["/bin", "/lib", "/usr/lib", str(allowed)], "read_write": [], "network": []}
        policy_file = folder / "policy.json"
        policy_file.write_text(json.dumps(policy))
        observed = {}
        for name, path in [("allowed", allowed), ("denied", denied)]:
            completed = subprocess.run([str(supervisor), "run", str(policy_file), "/bin/busybox", "cat", str(path)], capture_output=True, text=True, check=True, timeout=30)
            receipt = json.loads(completed.stdout)
            if not receipt["events"]:
                raise AssertionError("supervisor produced no notifications")
            if (receipt["status"] == 0) != (name == "allowed"):
                raise AssertionError("Landlock enforcement result differs from policy")
            observed[name] = {"status": receipt["status"], "events": len(receipt["events"])}
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen(2)
            host, port = listener.getsockname()
            policy["read_only"].extend([str(Path(sys.executable).resolve()), sys.prefix])
            for permitted in [True, False]:
                policy["network"] = [f"{host}:{port}"] if permitted else []
                policy_file.write_text(json.dumps(policy))
                program = f"import socket; s=socket.socket(); s.settimeout(2); s.connect(({host!r},{port})); s.close()"
                completed = subprocess.run([str(supervisor), "run", str(policy_file), sys.executable, "-c", program], capture_output=True, text=True, check=True, timeout=30)
                receipt = json.loads(completed.stdout)
                if (receipt["status"] == 0) != permitted:
                    raise AssertionError("numeric endpoint policy was not enforced: " + completed.stderr)
                observed["network_allowed" if permitted else "network_denied"] = {"status": receipt["status"], "events": len(receipt["events"])}
        sys.path.insert(0, str(root / "src"))
        os.environ["VERIKERNEL_LINUX_SUPERVISOR"] = str(supervisor)
        if (root / "libverikernel_core.so").exists():
            os.environ["VERIKERNEL_NATIVE_LIBRARY"] = str(root / "libverikernel_core.so")
        from verikernel.m2_enforcer.linux_hal import run_native
        from verikernel.cli.main import pack_receipt, verify_bundle
        script = folder / "stream.py"
        script.write_text(f"import time\ntime.sleep(.2)\nwith open({str(allowed)!r}) as stream:\n    print(stream.read())\n")
        manifest, events, seed, ratchet = run_native(script, {"filesystem": [str(allowed)]})
        if manifest["error"] or not events or not manifest["epochs"]:
            raise AssertionError("native periodic execution failed")
        bundle = folder / "stream.vkr"
        pack_receipt(bundle, manifest, events, seed, ratchet)
        if not verify_bundle(bundle)["valid"]:
            raise AssertionError("native periodic receipt failed verification")
        observed["streaming_receipt"] = {"events": len(events), "epochs": len(manifest["epochs"]), "verified": True}
        print(json.dumps({"landlock_seccomp_verified": True, "uid": os.getuid(), "cases": observed}, sort_keys=True))


if __name__ == "__main__":
    verify(Path(sys.argv[1]).resolve())
