"""Deduplicator."""
from __future__ import annotations
from collections import OrderedDict
from threading import Lock


class InodeDeduplicator:
    """InodeDeduplicator. Complexity: O(n + W) time and O(n + M) space; n is traversed data, W delegated work, M retained delegated state."""
    def __init__(self, capacity: int=16384) -> None:
        """Initialize the owned state and validate configuration limits. Complexity: O(n + W) time and O(n + M) space; n is traversed data, W delegated work, M retained delegated state."""
        if capacity < 1:
            raise ValueError("capacity must be positive")
        self.capacity = capacity
        self.entries = OrderedDict()
        self.lock = Lock()
        self.hits = 0
        self.misses = 0

    def seen(self, syscall_nr: int, dev_id: object, inode_nr: object, mtime_ns: object) -> bool:
        """Refresh an inode key and report whether it was already cached. Complexity: O(n + W) time and O(n + M) space; n is traversed data, W delegated work, M retained delegated state."""
        key = (syscall_nr, dev_id, inode_nr, mtime_ns)
        with self.lock:
            if key in self.entries:
                self.entries.move_to_end(key)
                self.hits += 1
                return True
            self.misses += 1
            self.entries[key] = None
            if len(self.entries) > self.capacity:
                self.entries.popitem(last=False)
            return False
