"""Native."""
from __future__ import annotations
import ctypes
import os
import sys
import sysconfig
from pathlib import Path
from verikernel.schemas import KernelTelemetryEvent


def library_path() -> object:
    """Locate the compiled FIFO library for the current platform. Complexity: O(n + W) time and O(n + M) space; n is traversed data, W delegated work, M retained delegated state."""
    root = Path(__file__).resolve().parents[3]
    explicit = os.environ.get("VERIKERNEL_NATIVE_LIBRARY")
    name = "verikernel_core.dll" if sys.platform == "win32" else "libverikernel_core.dylib" if sys.platform == "darwin" else "libverikernel_core.so"
    arch = "aarch64" if "arm64" in sysconfig.get_platform() or "aarch64" in sysconfig.get_platform() else "x86_64"
    triple = arch + ("-pc-windows-gnullvm" if arch == "aarch64" and sys.platform == "win32" else "-pc-windows-gnu" if sys.platform == "win32" else "-unknown-linux-musl")
    candidates = [Path(explicit)] if explicit else []
    candidates += [root / "dist" / "native" / triple / name]
    candidates += list((root / 'dist/native').glob('*/'+name))
    candidates += [root / 'target/release' / name, root / '.tmp/target/release' / name]
    if sys.platform == "linux":
        candidates += [root / "dist/native" / (arch + "-unknown-linux-gnu") / name]
    for directory in [root / ".tmp" / "target", root / "target"]:
        candidates.extend([directory / triple / "debug" / name, directory / "debug" / name, directory / "debug" / "deps" / name])
    for path in candidates:
        if path.is_file():
            try:
                library = ctypes.CDLL(str(path))
                return library
            except OSError:
                continue
    raise OSError("native telemetry library is unavailable; build verikernel-core for this interpreter architecture")


class NativeEventQueue:
    """NativeEventQueue. Complexity: O(n + W) time and O(n + M) space; n is traversed data, W delegated work, M retained delegated state."""
    def __init__(self, capacity: int=262144) -> None:
        """Initialize the owned state and validate configuration limits. Complexity: O(n + W) time and O(n + M) space; n is traversed data, W delegated work, M retained delegated state."""
        self.library = library_path()
        self.library.vk_ring_new.argtypes = [ctypes.c_size_t]
        self.library.vk_ring_new.restype = ctypes.c_void_p
        self.library.vk_ring_push.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
        self.library.vk_ring_push.restype = ctypes.c_int
        self.library.vk_ring_pop.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
        self.library.vk_ring_pop.restype = ctypes.c_int
        self.library.vk_ring_free.argtypes = [ctypes.c_void_p]
        self.library.vk_ring_free.restype = None
        self.handle = self.library.vk_ring_new(capacity)
        if not self.handle:
            raise ValueError("invalid native ring capacity")

    def try_push(self, event: object) -> object:
        """Attempt to enqueue one telemetry event without waiting for capacity. Complexity: O(n + W) time and O(n + M) space; n is traversed data, W delegated work, M retained delegated state."""
        if not self.handle:
            raise RuntimeError("native queue is closed")
        raw = ctypes.create_string_buffer(event.to_bytes(), 128)
        result = self.library.vk_ring_push(self.handle, raw)
        if result < 0:
            raise ValueError("invalid native queue input")
        return result == 1

    def try_pop(self) -> object:
        """Attempt to dequeue one telemetry event without waiting for data. Complexity: O(n + W) time and O(n + M) space; n is traversed data, W delegated work, M retained delegated state."""
        if not self.handle:
            raise RuntimeError("native queue is closed")
        raw = ctypes.create_string_buffer(128)
        result = self.library.vk_ring_pop(self.handle, raw)
        if result < 0:
            raise ValueError("invalid native queue output")
        return KernelTelemetryEvent.from_bytes(raw.raw) if result else None

    def close(self) -> None:
        """Finish pending work and release owned resources. Complexity: O(n + W) time and O(n + M) space; n is traversed data, W delegated work, M retained delegated state."""
        if self.handle:
            self.library.vk_ring_free(self.handle)
            self.handle = None

    def __del__(self) -> None:
        """Release any native resource still owned by this instance. Complexity: O(n + W) time and O(n + M) space; n is traversed data, W delegated work, M retained delegated state."""
        if getattr(self, "handle", None):
            self.close()

    def __enter__(self) -> object:
        """Activate the scoped resource and return its handle. Complexity: O(n + W) time and O(n + M) space; n is traversed data, W delegated work, M retained delegated state."""
        return self

    def __exit__(self, typ: object, value: object, tb: object) -> bool:
        """Close the scoped resource and propagate workload errors. Complexity: O(n + W) time and O(n + M) space; n is traversed data, W delegated work, M retained delegated state."""
        self.close()
        return False
