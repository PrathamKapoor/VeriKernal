"""Build probes."""
from __future__ import annotations
from typing import Any
import argparse
import os
import subprocess
import sys
import urllib.request
from pathlib import Path


def build(output: Any, override: bool=False) -> None:
    """Build the native artifacts required by this verification workflow. Complexity: O(b + W) time and O(b + M) space; b is captured input/output, W external verification work, M retained measurements."""
    if sys.platform != "linux":
        raise OSError("probe compilation requires Linux BTF and Clang")
    root = Path(__file__).resolve().parents[1]
    temp = root / ".tmp" / "ebpf"
    headers = temp / "bpf"
    headers.mkdir(parents=True, exist_ok=True)
    if override:
        eligible = Path("/sys/kernel/debug/fail_function/injectable")
        if not eligible.exists() or "ksys_read" not in eligible.read_text():
            raise OSError("ksys_read is not eligible for return override on this kernel")
    for name in ["bpf_helpers.h", "bpf_helper_defs.h", "bpf_core_read.h", "bpf_tracing.h"]:
        target = headers / name
        if not target.exists():
            urllib.request.urlretrieve("https://raw.githubusercontent.com/libbpf/libbpf/v1.6.2/src/" + name, target)
    with (temp / "vmlinux.h").open("wb") as stream:
        subprocess.run(["bpftool", "btf", "dump", "file", "/sys/kernel/btf/vmlinux", "format", "c"], stdout=stream, check=True)
    arch = "arm64" if os.uname().machine in {"aarch64", "arm64"} else "x86"
    flags = ["-DVK_ENABLE_OVERRIDE"] if override else []
    subprocess.run(["clang", "-target", "bpf", "-g", "-O2", "-D__TARGET_ARCH_" + arch, "-I" + str(temp), *flags, "-c", str(root / "ebpf/verikernel_probes.bpf.c"), "-o", str(output)], check=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True)
    parser.add_argument("--override-return", action="store_true")
    args = parser.parse_args()
    build(args.output, args.override_return)
