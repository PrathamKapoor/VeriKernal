"""Baseline v01."""
from __future__ import annotations
from collections import deque
from threading import Lock


class FlawedBaselineRingBufferV01:
    """FlawedBaselineRingBufferV01. Complexity: O(n + W) time and O(n + M) space; n is traversed data, W delegated work, M retained delegated state."""
    def __init__(self, cpus: int=4, capacity: int=64, signer: object=None) -> None:
        """Initialize the owned state and validate configuration limits. Complexity: O(n + W) time and O(n + M) space; n is traversed data, W delegated work, M retained delegated state."""
        if cpus < 1 or capacity < 1:
            raise ValueError("invalid transport capacity")
        self.buffers = [deque() for _ in range(cpus)]
        self.capacity = capacity
        self.drops = 0
        self.lock = Lock()
        self.signer = signer

    def push(self, event: object, cpu: int=0) -> bool:
        """Admit an event to the transport and update its accounting. Complexity: O(n + W) time and O(n + M) space; n is traversed data, W delegated work, M retained delegated state."""
        with self.lock:
            queue = self.buffers[cpu]
            if len(queue) == self.capacity:
                self.drops += 1
                return False
            queue.append(event)
            return True

    def drain(self) -> object:
        """Release the events currently available to the consumer. Complexity: O(n + W) time and O(n + M) space; n is traversed data, W delegated work, M retained delegated state."""
        out = []
        with self.lock:
            for queue in self.buffers:
                out.extend(queue)
                queue.clear()
        if self.signer:
            for start in range(0, len(out), 128):
                self.signer.sign(b"".join(e.to_bytes() for e in out[start:start+128]))
        return out

    @staticmethod
    def naive_allowed(path: object, root: object) -> object:
        """Apply the intentionally incomplete string-prefix baseline policy. Complexity: O(n + W) time and O(n + M) space; n is traversed data, W delegated work, M retained delegated state."""
        return str(path).startswith(str(root))
