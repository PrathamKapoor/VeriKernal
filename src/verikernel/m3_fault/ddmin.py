"""Ddmin."""
from __future__ import annotations
class DeltaDebuggingShrinker:
    """DeltaDebuggingShrinker. Complexity: O(n^2 * W) worst-case oracle work and O(n^2) memoization space; W is one oracle evaluation."""
    def __init__(self, fails: object) -> None:
        """init. Complexity: O(n^2 * W) worst-case oracle work and O(n^2) memoization space; W is one oracle evaluation."""
        self.fails = fails
        self.memo = {}
        self.evaluations = 0

    def _test(self, items: object) -> object:
        """test. Complexity: O(n^2 * W) worst-case oracle work and O(n^2) memoization space; W is one oracle evaluation."""
        key = tuple(items)
        if key not in self.memo:
            self.memo[key] = bool(self.fails(list(key)))
            self.evaluations += 1
        return self.memo[key]

    def shrink(self, candidates: object) -> object:
        """shrink. Complexity: O(n^2 * W) worst-case oracle work and O(n^2) memoization space; W is one oracle evaluation."""
        current = sorted(set(candidates))
        if not self._test(current):
            raise ValueError("initial schedule does not reproduce failure")
        if self._test([]):
            return []
        partitions = 2
        while len(current) >= 2:
            size = (len(current) + partitions - 1) // partitions
            chunks = [current[i:i + size] for i in range(0, len(current), size)]
            reduced = False
            for chunk in chunks:
                if self._test(chunk):
                    current = chunk
                    partitions = 2
                    reduced = True
                    break
            if not reduced:
                for chunk in chunks:
                    removed = set(chunk)
                    complement = [x for x in current if x not in removed]
                    if self._test(complement):
                        current = complement
                        partitions = max(2, partitions - 1)
                        reduced = True
                        break
            if not reduced:
                if partitions >= len(current):
                    break
                partitions = min(len(current), partitions * 2)
        return current
