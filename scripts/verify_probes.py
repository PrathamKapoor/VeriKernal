"""Verify probes."""
from __future__ import annotations
from typing import Any
import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path

from verikernel.m2_enforcer.linux_hal import verify_kernel_stream
from verikernel.schemas import KernelTelemetryEvent


def verify(supervisor: Any, object_path: Any) -> None:
    """Validate the captured evidence and return the verification result. Complexity: O(b + W) time and O(b + M) space; b is captured input/output, W external verification work, M retained measurements."""
    root = Path(__file__).resolve().parents[1]
    directory = root / ".tmp" / ("probe-check-" + os.urandom(8).hex())
    directory.mkdir(parents=True)
    trigger, data, output = [directory / name for name in ["trigger", "data", "stream.jsonl"]]
    data.write_text("kernel boundary verification")
    code = "import os,time,sys,socket\nfrom pathlib import Path\np=Path(sys.argv[1])\nwhile not p.exists(): time.sleep(.01)\nfor i in range(20):\n with open(sys.argv[2]) as f: f.read()\n time.sleep(.01)\ns=socket.socket()\ntry: s.connect(('127.0.0.1',9))\nexcept OSError as error: print(error,file=sys.stderr)\nfinally: s.close()\nos.execv('/bin/busybox',['busybox','true'])\n"
    workload = subprocess.Popen([sys.executable, "-c", code, str(trigger), str(data)])
    monitor = subprocess.Popen([str(supervisor), "probes", str(object_path), str(workload.pid), "2000", str(output)])
    try:
        deadline = time.monotonic() + 180
        while not output.exists() or not output.stat().st_size:
            if monitor.poll() is not None:
                raise RuntimeError("probe attachment failed")
            if time.monotonic() > deadline:
                raise TimeoutError("probe attachment timed out")
            time.sleep(.05)
        trigger.touch()
        workload.wait(timeout=30)
        if monitor.wait(timeout=60) != 0:
            raise RuntimeError("probe capture failed")
        records = [json.loads(line) for line in output.read_text().splitlines()]
        header, terminal = records[0], records[-1]
        events = sorted([KernelTelemetryEvent.from_bytes(bytes.fromhex(record["bytes"])) for record in records[1:-1]], key=lambda event: event.seq_no)
        if not events or terminal["losses"] or not verify_kernel_stream(events, [bytes.fromhex(seed) for seed in header["seeds"]], [bytes.fromhex(state) for state in terminal["states"]]):
            raise ValueError("kernel stream authentication failed")
        if not {1, 2, 3, 9}.issubset({event.syscall_nr for event in events}):
            raise ValueError("an expected kernel hook produced no telemetry")
        print(json.dumps({"events": len(events), "operations": sorted({event.syscall_nr for event in events}), "losses": terminal["losses"], "ratchet_verified": True}))
    finally:
        for process in [workload, monitor]:
            if process.poll() is None:
                process.terminate()
                process.wait(timeout=10)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("supervisor", type=Path)
    parser.add_argument("object", type=Path)
    arguments = parser.parse_args()
    verify(arguments.supervisor, arguments.object)
