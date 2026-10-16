"""Hal."""
from __future__ import annotations
from verikernel.type_boundaries import narrow_audit_args
import hashlib
import builtins
import io
import os
import sys
import stat as stat_module
import shlex
import socket
import threading
import time
from functools import lru_cache
from pathlib import Path
from verikernel.schemas import KernelTelemetryEvent
from .deduplicator import InodeDeduplicator
from .diff_engine import ContractEnforcer, ghost_diff
from verikernel.rust_bridge import rust_fnv1a_hash

_sessions = []
_guard = threading.local()
_installed = False
_original_open = builtins.open
_original_io_open = io.open
_original_getenv = os.getenv
_original_time = time.time
_original_monotonic = time.monotonic
_original_urandom = os.urandom
_original_recv = socket.socket.recv
_original_recv_into = socket.socket.recv_into
_original_send = socket.socket.send
_original_sendall = socket.socket.sendall

if sys.platform == "win32":
    import ctypes
    import msvcrt
    _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _final_path = _kernel32.GetFinalPathNameByHandleW
    _final_path.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p, ctypes.c_uint32, ctypes.c_uint32]
    _final_path.restype = ctypes.c_uint32


def canonical_handle(stream: object) -> object:
    """canonical handle. Complexity: O(s + c + b) boundary work and O(c + n) retained space; s is stack depth, c contract size, b I/O bytes, n retained events."""
    fd = stream.fileno()
    if sys.platform == "win32":
        buffer = ctypes.create_unicode_buffer(32768)
        size = _final_path(msvcrt.get_osfhandle(fd), buffer, len(buffer), 0)
        if not size or size >= len(buffer):
            raise OSError("cannot resolve opened file handle")
        path = buffer.value
        return "\\\\" + path[8:] if path.startswith("\\\\?\\UNC\\") else path[4:] if path.startswith("\\\\?\\") else path
    if sys.platform.startswith("linux"):
        return os.readlink(f"/proc/self/fd/{fd}")
    return os.path.realpath(os.fsdecode(stream.name))


def _current() -> object:
    """current. Complexity: O(s + c + b) boundary work and O(c + n) retained space; s is stack depth, c contract size, b I/O bytes, n retained events."""
    return _sessions[-1] if _sessions and not getattr(_guard, "busy", False) else None


def _boundary(session: object, operation: int, target: object) -> object:
    """boundary. Complexity: O(s + c + b) boundary work and O(c + n) retained space; s is stack depth, c contract size, b I/O bytes, n retained events."""
    previous = getattr(_guard, "busy", False)
    _guard.busy = True
    try:
        return session.record(operation, target)
    finally:
        _guard.busy = previous


class BoundaryFile:
    """BoundaryFile. Complexity: O(s + c + b) boundary work and O(c + n) retained space; s is stack depth, c contract size, b I/O bytes, n retained events."""
    def __init__(self, stream: object, session: object) -> None:
        """init. Complexity: O(s + c + b) boundary work and O(c + n) retained space; s is stack depth, c contract size, b I/O bytes, n retained events."""
        self._stream, self._session = stream, session

    def __getattr__(self, name: object) -> object:
        """getattr. Complexity: O(s + c + b) boundary work and O(c + n) retained space; s is stack depth, c contract size, b I/O bytes, n retained events."""
        return getattr(self._stream, name)

    def __enter__(self) -> object:
        """enter. Complexity: O(s + c + b) boundary work and O(c + n) retained space; s is stack depth, c contract size, b I/O bytes, n retained events."""
        self._stream.__enter__()
        return self

    def __exit__(self, typ: object, value: object, tb: object) -> object:
        """exit. Complexity: O(s + c + b) boundary work and O(c + n) retained space; s is stack depth, c contract size, b I/O bytes, n retained events."""
        return self._stream.__exit__(typ, value, tb)

    def __iter__(self) -> object:
        """iter. Complexity: O(s + c + b) boundary work and O(c + n) retained space; s is stack depth, c contract size, b I/O bytes, n retained events."""
        return self

    def __next__(self) -> object:
        """next. Complexity: O(s + c + b) boundary work and O(c + n) retained space; s is stack depth, c contract size, b I/O bytes, n retained events."""
        line = self.readline()
        if not line:
            raise StopIteration
        return line

    def _fault(self, operation: int) -> object:
        """fault. Complexity: O(s + c + b) boundary work and O(c + n) retained space; s is stack depth, c contract size, b I/O bytes, n retained events."""
        if self._session.owner is None or getattr(_guard, "busy", False):
            return None
        return _boundary(self._session, operation, canonical_handle(self._stream))

    def read(self, count: int=-1) -> object:
        """read. Complexity: O(s + c + b) boundary work and O(c + n) retained space; s is stack depth, c contract size, b I/O bytes, n retained events."""
        fault = self._fault(9)
        if fault and fault.code == 1:
            count = 1 if count < 0 else max(1, count//2)
        return self._stream.read(count)

    def readline(self, count: int=-1) -> object:
        """readline. Complexity: O(s + c + b) boundary work and O(c + n) retained space; s is stack depth, c contract size, b I/O bytes, n retained events."""
        fault = self._fault(9)
        if fault and fault.code == 1:
            count = 1 if count < 0 else max(1, count//2)
        return self._stream.readline(count)

    def readinto(self, buffer: object) -> object:
        """readinto. Complexity: O(s + c + b) boundary work and O(c + n) retained space; s is stack depth, c contract size, b I/O bytes, n retained events."""
        fault = self._fault(9)
        view = memoryview(buffer)
        if fault and fault.code == 1:
            view = view[:max(1, len(view)//2)]
        return self._stream.readinto(view)

    def write(self, data: object) -> object:
        """write. Complexity: O(s + c + b) boundary work and O(c + n) retained space; s is stack depth, c contract size, b I/O bytes, n retained events."""
        self._fault(10)
        return self._stream.write(data)

    def writelines(self, lines: object) -> None:
        """writelines. Complexity: O(s + c + b) boundary work and O(c + n) retained space; s is stack depth, c contract size, b I/O bytes, n retained events."""
        for line in lines:
            self.write(line)


def _open_with(original: object, *args: object, **kwargs: object) -> object:
    """open with. Complexity: O(s + c + b) boundary work and O(c + n) retained space; s is stack depth, c contract size, b I/O bytes, n retained events."""
    session = _current()
    stream = original(*args, **kwargs)
    if session and stat_module.S_ISREG(os.fstat(stream.fileno()).st_mode):
        return BoundaryFile(stream, session)
    return stream


def _open(*args: object, **kwargs: object) -> object:
    """open. Complexity: O(s + c + b) boundary work and O(c + n) retained space; s is stack depth, c contract size, b I/O bytes, n retained events."""
    return _open_with(_original_open, *args, **kwargs)


def _io_open(*args: object, **kwargs: object) -> object:
    """io open. Complexity: O(s + c + b) boundary work and O(c + n) retained space; s is stack depth, c contract size, b I/O bytes, n retained events."""
    return _open_with(_original_io_open, *args, **kwargs)


def _getenv(key: object, default: object=None) -> object:
    """getenv. Complexity: O(s + c + b) boundary work and O(c + n) retained space; s is stack depth, c contract size, b I/O bytes, n retained events."""
    session = _current()
    if session:
        _boundary(session, 5, key)
    return _original_getenv(key, default)


def _clock(original: object, target: object) -> object:
    """clock. Complexity: O(s + c + b) boundary work and O(c + n) retained space; s is stack depth, c contract size, b I/O bytes, n retained events."""
    session = _current()
    fault = _boundary(session, 6, target) if session else None
    return original() + (1.0 if fault and fault.code == 2 else 0.0)


def _wall_clock() -> object:
    """wall clock. Complexity: O(s + c + b) boundary work and O(c + n) retained space; s is stack depth, c contract size, b I/O bytes, n retained events."""
    return _clock(_original_time, "wall-clock")


def _monotonic_clock() -> object:
    """monotonic clock. Complexity: O(s + c + b) boundary work and O(c + n) retained space; s is stack depth, c contract size, b I/O bytes, n retained events."""
    return _clock(_original_monotonic, "monotonic")


def _random(count: int) -> object:
    """random. Complexity: O(s + c + b) boundary work and O(c + n) retained space; s is stack depth, c contract size, b I/O bytes, n retained events."""
    session = _current()
    if session and count:
        _boundary(session, 7, "system-random")
    return _original_urandom(count)


def _socket_target(connection: object) -> object:
    """socket target. Complexity: O(s + c + b) boundary work and O(c + n) retained space; s is stack depth, c contract size, b I/O bytes, n retained events."""
    try:
        peer = connection.getpeername()
    except OSError:
        peer = connection.getsockname()
    if isinstance(peer, tuple):
        host, port = peer[:2]
        return f"socket://[{host}]:{port}" if ":" in str(host) else f"socket://{host}:{port}"
    return "socket://" + (str(peer) or "local")


def _recv(connection: object, count: int, flags: int=0) -> object:
    """recv. Complexity: O(s + c + b) boundary work and O(c + n) retained space; s is stack depth, c contract size, b I/O bytes, n retained events."""
    session = _current()
    fault = _boundary(session, 9, _socket_target(connection)) if session and count else None
    if fault and fault.code == 1 and count > 1:
        count //= 2
    return _original_recv(connection, count, flags)


def _recv_into(connection: object, buffer: object, count: int=0, flags: int=0) -> object:
    """recv into. Complexity: O(s + c + b) boundary work and O(c + n) retained space; s is stack depth, c contract size, b I/O bytes, n retained events."""
    session = _current()
    fault = _boundary(session, 9, _socket_target(connection)) if session and len(buffer) else None
    if fault and fault.code == 1:
        count = max(1, (count or len(buffer))//2)
    return _original_recv_into(connection, buffer, count, flags)


def _send(connection: object, data: object, flags: int=0) -> object:
    """send. Complexity: O(s + c + b) boundary work and O(c + n) retained space; s is stack depth, c contract size, b I/O bytes, n retained events."""
    session = _current()
    if session and data:
        _boundary(session, 10, _socket_target(connection))
    return _original_send(connection, data, flags)


def _sendall(connection: object, data: object, flags: int=0) -> object:
    """sendall. Complexity: O(s + c + b) boundary work and O(c + n) retained space; s is stack depth, c contract size, b I/O bytes, n retained events."""
    session = _current()
    if session and data:
        _boundary(session, 10, _socket_target(connection))
    return _original_sendall(connection, data, flags)


def _dispatch(event: object, args: object) -> None:
    """dispatch. Complexity: O(s + c + b) boundary work and O(c + n) retained space; s is stack depth, c contract size, b I/O bytes, n retained events."""
    if not _sessions or getattr(_guard, "busy", False):
        return
    _guard.busy = True
    try:
        for session in tuple(_sessions):
            session._audit(event, args)
    finally:
        _guard.busy = False


@lru_cache(maxsize=4096)
def _stack_filename(filename: object) -> object:
    """stack filename. Complexity: O(s + c + b) boundary work and O(c + n) retained space; s is stack depth, c contract size, b I/O bytes, n retained events."""
    return os.path.realpath(filename)


def stack_hash(target_root: object) -> object:
    """stack hash. Complexity: O(s + c + b) boundary work and O(c + n) retained space; s is stack depth, c contract size, b I/O bytes, n retained events."""
    value = 14695981039346656037
    frame = sys._getframe(1)
    parts = []
    while frame:
        filename = _stack_filename(frame.f_code.co_filename)
        if filename.startswith(str(target_root) + os.sep) and "verikernel" + os.sep not in filename:
            parts.append(f"{os.path.relpath(filename, target_root)}:{frame.f_code.co_name}:{frame.f_lineno}".encode())
        frame = frame.f_back
    return rust_fnv1a_hash(b"\0".join(reversed(parts)))


class RuntimeInterceptorHAL:
    """RuntimeInterceptorHAL. Complexity: O(s + c + b) boundary work and O(c + n) retained space; s is stack depth, c contract size, b I/O bytes, n retained events."""
    backend = "portable-pep578"
    capabilities = {"python_audit": True, "native_child_observation": False, "kernel_isolation": False, "atomic_handle_policy": False}

    def __init__(self, contract: object=None, mode: str="audit", target_root: object=None, injector: object=None, ratchet: object=None, ringbuf: object=None, attestor: object=None) -> None:
        """init. Complexity: O(s + c + b) boundary work and O(c + n) retained space; s is stack depth, c contract size, b I/O bytes, n retained events."""
        if mode not in {"audit", "strict"}:
            raise ValueError("mode must be audit or strict")
        self.contract = contract or {}
        self.mode = mode
        self.root = Path(target_root or os.getcwd()).resolve()
        self.policy = ContractEnforcer(self.contract)
        self.injector, self.ratchet, self.ringbuf = injector, ratchet, ringbuf
        self.attestor = attestor
        self.dedup = InodeDeduplicator()
        self.events, self.violations = [], []
        self.owner = None
        self.lock = threading.RLock()

    def __enter__(self) -> object:
        """enter. Complexity: O(s + c + b) boundary work and O(c + n) retained space; s is stack depth, c contract size, b I/O bytes, n retained events."""
        global _installed
        if self.owner is not None:
            raise RuntimeError("session already active")
        if not _installed:
            sys.addaudithook(_dispatch)
            _installed = True
        self.owner = threading.get_ident()
        _sessions.append(self)
        builtins.open, io.open = _open, _io_open
        os.getenv = _getenv
        time.time, time.monotonic = _wall_clock, _monotonic_clock
        os.urandom = _random
        socket.socket.recv, socket.socket.recv_into = _recv, _recv_into
        socket.socket.send, socket.socket.sendall = _send, _sendall
        return self

    def __exit__(self, typ: object, value: object, tb: object) -> bool:
        """exit. Complexity: O(s + c + b) boundary work and O(c + n) retained space; s is stack depth, c contract size, b I/O bytes, n retained events."""
        _sessions.remove(self)
        self.owner = None
        if not _sessions:
            builtins.open, io.open = _original_open, _original_io_open
            os.getenv = _original_getenv
            time.time, time.monotonic = _original_time, _original_monotonic
            os.urandom = _original_urandom
            socket.socket.recv, socket.socket.recv_into = _original_recv, _original_recv_into
            socket.socket.send, socket.socket.sendall = _original_send, _original_sendall
        return False

    def _audit(self, event: str, args: tuple) -> None:
        """audit. Complexity: O(s + c + b) boundary work and O(c + n) retained space; s is stack depth, c contract size, b I/O bytes, n retained events."""
        args = narrow_audit_args(event, args)
        if event == "open" and not isinstance(args[0], int):
            self.record(2, os.path.realpath(os.fsdecode(args[0])))
        elif event in {"subprocess.Popen", "os.exec", "os.system"}:
            executable = args[0]
            if executable is None and event == "subprocess.Popen":
                command = args[1]
                executable = command[0] if isinstance(command, (list, tuple)) else shlex.split(command, posix=False)[0].strip('"')
            self.record(1, os.fsdecode(executable))
        elif event == "ctypes.dlopen" and args[0]:
            self.record(4, os.fsdecode(args[0]))
        elif event == "socket.connect":
            self.record(3, ":".join(map(str, args[1])) if isinstance(args[1], tuple) else str(args[1]))

    def record(self, operation: int, target: object, apply_fault: bool=True) -> object:
        """Retain an observed event for the current execution receipt. Complexity: O(s + c + b) boundary work and O(c + n) retained space; s is stack depth, c contract size, b I/O bytes, n retained events."""
        with self.lock:
            socket_operation = target.startswith("socket://")
            violation = self.policy.violation(3 if socket_operation else operation, target[9:] if socket_operation else target)
            if violation:
                self.violations.append(violation)
                if self.mode == "strict":
                    raise PermissionError(13, violation["kind"], target)
            stat = None
            if operation in {1, 2, 4, 9, 10} and not socket_operation:
                try:
                    stat = os.stat(target)
                except OSError:
                    stat = None
            stack = stack_hash(self.root)
            fault = self.injector.select(operation, stack) if self.injector and apply_fault else None
            if stat and not fault and self.dedup.seen(operation, stat.st_dev, stat.st_ino, stat.st_mtime_ns):
                return None
            event = KernelTelemetryEvent(seq_no=len(self.events), timestamp_ns=time.monotonic_ns(), pid=os.getpid(), tid=threading.get_native_id() & 0xFFFFFFFF, syscall_nr=operation, fault_injected=fault.code if fault else 0, dev_id=stat.st_dev & ((1 << 64)-1) if stat else 0, inode_nr=stat.st_ino & ((1 << 64)-1) if stat else 0, mtime_ns=stat.st_mtime_ns & ((1 << 64)-1) if stat else 0, call_stack_hash=stack, target_digest=hashlib.sha256(target.encode()).digest())
            if self.attestor:
                self.attestor.submit(event)
            elif self.ratchet:
                self.ratchet.tag(event)
            self.events.append(event)
            if self.ringbuf:
                self.ringbuf.push(event, cpu=0)
            if fault and fault.code < 0:
                raise OSError(-fault.code, fault.kind, target)
            return fault

    def read(self, stream: object, count: int=-1) -> object:
        """read. Complexity: O(s + c + b) boundary work and O(c + n) retained space; s is stack depth, c contract size, b I/O bytes, n retained events."""
        fault = self.record(9, str(stream.name))
        if fault and fault.code == 1 and count > 1:
            count = max(1, count // 2)
        return stream.read(count)

    def write(self, stream: object, data: object) -> object:
        """write. Complexity: O(s + c + b) boundary work and O(c + n) retained space; s is stack depth, c contract size, b I/O bytes, n retained events."""
        self.record(10, str(stream.name))
        return stream.write(data)

    def clock(self) -> object:
        """clock. Complexity: O(s + c + b) boundary work and O(c + n) retained space; s is stack depth, c contract size, b I/O bytes, n retained events."""
        fault = self.record(6, "monotonic")
        return _original_monotonic() + (1.0 if fault and fault.code == 2 else 0.0)

    def getenv(self, key: object, default: object=None) -> object:
        """getenv. Complexity: O(s + c + b) boundary work and O(c + n) retained space; s is stack depth, c contract size, b I/O bytes, n retained events."""
        self.record(5, key)
        return _original_getenv(key, default)

    def ghost_patch(self) -> object:
        """ghost patch. Complexity: O(s + c + b) boundary work and O(c + n) retained space; s is stack depth, c contract size, b I/O bytes, n retained events."""
        return ghost_diff(self.violations, self.contract.get("contract_gitoid"))
