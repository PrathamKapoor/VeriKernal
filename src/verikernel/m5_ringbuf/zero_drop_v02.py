"""Zero drop v02."""
from __future__ import annotations
import os
from threading import Lock
from queue import SimpleQueue, Empty
from .native import NativeEventQueue
from verikernel.schemas import KernelTelemetryEvent
from verikernel.m2_enforcer.deduplicator import InodeDeduplicator


class ZeroDropRingBufferV02:
    """ZeroDropRingBufferV02. Complexity: O(n + W) time and O(n + M) space; n is traversed data, W delegated work, M retained delegated state."""
    @staticmethod
    def filter_packed(buffer: bytearray, capacity: int = 16384) -> bytearray:
        """Filter an independent packed batch in expected O(n) time, O(capacity) space."""
        from verikernel.rust_bridge import BatchEngine
        return BatchEngine().dedup(buffer,capacity)

    def __init__(self, cpus: int=4, l1_capacity: int=64, deduplicate: bool=True) -> None:
        """Initialize the owned state and validate configuration limits. Complexity: O(n + W) time and O(n + M) space; n is traversed data, W delegated work, M retained delegated state."""
        if cpus < 1 or l1_capacity < 1:
            raise ValueError("invalid transport capacity")
        self.l1 = [[] for _ in range(cpus)]
        try:
            self.shared = NativeEventQueue()
            self.lock_free_fifo = True
        except OSError:
            self.shared = SimpleQueue()
            self.lock_free_fifo = False
        self.capacity = l1_capacity
        self.locks = [Lock() for _ in range(cpus)]
        self.dedup = InodeDeduplicator() if deduplicate else None
        self.drops = self.suppressed = 0
        self.skipped = set()
        self.pending = {}
        self.next_sequence = 0

    def push(self, event: object, cpu: int=0) -> bool:
        """Admit an event to the transport and update its accounting. Complexity: O(n + W) time and O(n + M) space; n is traversed data, W delegated work, M retained delegated state."""
        if self.dedup and event.inode_nr and not event.fault_injected and self.dedup.seen(event.syscall_nr, event.dev_id, event.inode_nr, event.mtime_ns):
            self.suppressed += 1
            self.skipped.add(event.seq_no)
            return False
        with self.locks[cpu]:
            self.l1[cpu].append(KernelTelemetryEvent.from_bytes(event.to_bytes()))
            if len(self.l1[cpu]) >= self.capacity:
                self._flush(cpu)
        return True

    def _flush(self, cpu: object) -> None:
        """Move staged records into the shared transport. Complexity: O(n + W) time and O(n + M) space; n is traversed data, W delegated work, M retained delegated state."""
        staging = self.l1[cpu]
        while staging:
            event = staging[0]
            if self.lock_free_fifo:
                if not self.shared.try_push(event):
                    raise BufferError("native FIFO requires a concurrent consumer")
            else:
                self.shared.put(event)
            del staging[0]

    def drain(self) -> object:
        """Release the events currently available to the consumer. Complexity: O(n + W) time and O(n + M) space; n is traversed data, W delegated work, M retained delegated state."""
        for cpu in range(len(self.l1)):
            with self.locks[cpu]:
                self._flush(cpu)
        result = []
        while True:
            if self.lock_free_fifo:
                event = self.shared.try_pop()
                if event is None:
                    break
            else:
                try:
                    event = self.shared.get_nowait()
                except Empty:
                    break
            result.append(event)
        for event in result:
            if event.seq_no < self.next_sequence or event.seq_no in self.pending:
                raise ValueError("duplicate sequence number")
            self.pending[event.seq_no] = event
        ordered = []
        while self.next_sequence in self.pending or self.next_sequence in self.skipped:
            if self.next_sequence in self.skipped:
                self.skipped.remove(self.next_sequence)
            else:
                ordered.append(self.pending.pop(self.next_sequence))
            self.next_sequence += 1
        return ordered

    @staticmethod
    def canonical_allowed(path: object, root: object) -> object:
        """Check containment after resolving a target path. Complexity: O(n + W) time and O(n + M) space; n is traversed data, W delegated work, M retained delegated state."""
        try:
            return os.path.commonpath([os.path.realpath(path), os.path.realpath(root)]) == os.path.realpath(root)
        except ValueError:
            return False
