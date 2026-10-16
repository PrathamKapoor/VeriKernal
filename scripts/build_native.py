"""Build native."""
from __future__ import annotations
from typing import Any
import argparse
import os
import shutil
import subprocess
import sys
import sysconfig
from pathlib import Path


def build(target: Any=None, test: bool=True) -> None:
    """Build the native artifacts required by this verification workflow. Complexity: O(b + W) time and O(b + M) space; b is captured input/output, W external verification work, M retained measurements."""
    root = Path(__file__).resolve().parents[1]
    temporary = root / ".tmp"
    temporary.mkdir(exist_ok=True)
    environment = os.environ.copy()
    for name in ["TEMP", "TMP", "TMPDIR"]:
        environment[name] = str(temporary)
    environment.update(PYTHONDONTWRITEBYTECODE="1", CARGO_HOME=str(root / "dist/development/cargo"), CARGO_TARGET_DIR=str(root / "dist/build-target"))
    rust_host = subprocess.check_output(["rustc", "-vV"], env=environment, text=True).split("host: ")[1].splitlines()[0]
    host_linker = root / "dist/development/zig-link.cmd"
    if rust_host == "x86_64-pc-windows-gnu" and host_linker.exists():
        environment.setdefault("CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER", str(host_linker))
        environment["PATH"] = str(root / "dist/development/mingw/w64devkit/bin") + os.pathsep + environment.get("PATH", "")
    if target is None and sys.platform == "win32" and "arm64" in sysconfig.get_platform() and not rust_host.startswith("aarch64"):
        target = "aarch64-pc-windows-gnullvm"
    linker_name = "CARGO_TARGET_" + (target or rust_host).upper().replace("-", "_") + "_LINKER"
    if target == "aarch64-pc-windows-gnullvm" and linker_name not in environment:
        candidates = list((root / "dist/development/llvm").glob("*/bin/aarch64-w64-mingw32-clang.exe"))
        if candidates:
            environment[linker_name] = str(candidates[0])
    if linker_name in environment:
        environment["PATH"] = str(Path(environment[linker_name]).parent) + os.pathsep + environment.get("PATH", "")
    args = ["--target", target] if target else []
    if test:
        subprocess.run(["cargo", "test", "--workspace", *args], cwd=root, env=environment, check=True)
    subprocess.run(["cargo", "build", "--release", "--workspace", *args], cwd=root, env=environment, check=True)
    build_path = root / "dist/build-target"
    if target:
        build_path /= target
    build_path /= "release"
    host = target or rust_host
    destination = root / "dist/native" / host
    destination.mkdir(parents=True, exist_ok=True)
    filename = "verikernel_core.dll" if "windows" in host else "libverikernel_core.dylib" if "darwin" in host else "libverikernel_core.so"
    shutil.copy2(build_path / filename, destination / filename)
    checker = 'verikernel-quality.exe' if 'windows' in host else 'verikernel-quality'
    shutil.copy2(build_path/checker,destination/checker)
    native_target = 'vk-target-bin.exe' if 'windows' in host else 'vk-target-bin'
    shutil.copy2(build_path/native_target,destination/native_target)
    sandbox_target = 'verikernel-sandbox-exec.exe' if 'windows' in host else 'verikernel-sandbox-exec'
    shutil.copy2(build_path/sandbox_target,destination/sandbox_target)
    if "windows" in host and linker_name in environment:
        for name in ["libunwind.dll", "libwinpthread-1.dll"]:
            dependency = Path(environment[linker_name]).parent / name
            if dependency.exists():
                shutil.copy2(dependency, destination / name)
    if "linux" in host:
        shutil.copy2(build_path / "verikernel-linux", destination / "verikernel-linux")
    print(destination)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--target")
    parser.add_argument("--build-only", action="store_true")
    options = parser.parse_args()
    build(options.target, not options.build_only)
