"""Schemas."""
from __future__ import annotations
import struct
from dataclasses import dataclass, fields
from enum import IntEnum

EVENT_STRUCT = struct.Struct("<QQIIIIQQQQ32s32s")
assert EVENT_STRUCT.size == 128


class Operation(IntEnum):
    """Operation. Complexity: O(1) time and O(1) space for the fixed-width wire schema."""
    SYS_EXECVE = 1
    SYS_OPENAT = 2
    SYS_CONNECT = 3
    SYS_MMAP_EXEC = 4
    SYS_ENV_READ = 5
    SYS_CLOCK_GETTIME = 6
    SYS_GETRANDOM = 7
    SYS_QPU_DISPATCH = 8
    SYS_READ = 9
    SYS_WRITE = 10


@dataclass
class KernelTelemetryEvent:
    """KernelTelemetryEvent. Complexity: O(1) time and O(1) space for the fixed-width wire schema."""
    seq_no: int = 0
    timestamp_ns: int = 0
    pid: int = 0
    tid: int = 0
    syscall_nr: int = 0
    fault_injected: int = 0
    dev_id: int = 0
    inode_nr: int = 0
    mtime_ns: int = 0
    call_stack_hash: int = 0
    target_digest: bytes = bytes(32)
    ratchet_tag: bytes = bytes(32)

    def to_bytes(self) -> bytes:
        """to bytes. Complexity: O(1) time and O(1) space for the fixed-width wire schema."""
        if len(self.target_digest) != 32 or len(self.ratchet_tag) != 32:
            raise ValueError("event digests must be 32 bytes")
        values = [getattr(self, f.name) for f in fields(self)]
        if not -(1 << 31) <= self.fault_injected < (1 << 31):
            raise ValueError("fault code outside signed 32-bit range")
        values[5] &= 0xFFFFFFFF
        return EVENT_STRUCT.pack(*values)

    @classmethod
    def from_bytes(cls, data: bytes | bytearray) -> KernelTelemetryEvent:
        """from bytes. Complexity: O(1) time and O(1) space for the fixed-width wire schema."""
        if len(data) != 128:
            raise ValueError("event must contain exactly 128 bytes")
        values = list(EVENT_STRUCT.unpack(data))
        if values[5] & (1 << 31):
            values[5] -= 1 << 32
        return cls(*values)
