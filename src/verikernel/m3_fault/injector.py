"""Injector."""
from __future__ import annotations
from dataclasses import dataclass, asdict

MASK = (1 << 64) - 1


def splitmix64(value: object) -> object:
    """splitmix64. Complexity: O(1) time and O(1) space for bounded machine-word inputs."""
    from verikernel.rust_bridge import rust_splitmix64
    return rust_splitmix64(value)


@dataclass(frozen=True)
class Fault:
    """Fault. Complexity: O(n + W) time and O(n + M) space; n is traversed data, W delegated work, M retained delegated state."""
    site_id: int
    syscall_nr: int
    stack_hash: int
    ordinal: int
    code: int
    kind: str


class SyscallFaultInjector:
    """SyscallFaultInjector. Complexity: O(n + W) time and O(n + M) space; n is traversed data, W delegated work, M retained delegated state."""
    def __init__(self, seed: int=0, p_fault: float=0.05, schedule: object=None, active_sites: object=None, syscall_types: object=None) -> None:
        """Initialize the owned state and validate configuration limits. Complexity: O(n + W) time and O(n + M) space; n is traversed data, W delegated work, M retained delegated state."""
        if not 0 <= p_fault <= 1:
            raise ValueError("fault probability must lie in [0,1]")
        self.seed, self.probability = seed & MASK, int(p_fault * 1_000_000)
        self.types = set(syscall_types or {1, 2, 3, 4, 6, 9, 10})
        self.replay = schedule is not None
        self.schedule = list(schedule or [])
        self.by_site = {item["site_id"]: item for item in self.schedule}
        self.active = set(active_sites) if active_sites is not None else set(self.by_site)
        self.ordinals, self.site_counter = {}, 0

    def select(self, operation: int, stack: object) -> object:
        """Select a scheduled or seeded fault for the current syscall site. Complexity: O(n + W) time and O(n + M) space; n is traversed data, W delegated work, M retained delegated state."""
        if operation not in self.types:
            return None
        key = (operation, stack)
        ordinal = self.ordinals.get(key, 0)
        self.ordinals[key] = ordinal + 1
        site = self.site_counter
        self.site_counter += 1
        if self.replay:
            item = self.by_site.get(site)
            if item and (item["syscall_nr"], item["stack_hash"], item["ordinal"]) != (operation, stack, ordinal):
                raise ValueError(f"replay divergence at site {site}")
            return Fault(**item) if item and site in self.active else None
        random = splitmix64(self.seed ^ splitmix64(stack) ^ splitmix64(operation) ^ splitmix64(ordinal))
        if random % 1_000_000 >= self.probability:
            return None
        kinds = [(-11, "EAGAIN"), (-110, "ETIMEDOUT"), (-28, "ENOSPC"), (-5, "EIO")]
        if operation == 9:
            kinds.append((1, "SHORT_READ"))
        if operation == 6:
            kinds = [(2, "CLOCK_SKEW")]
        code, kind = kinds[splitmix64(random) % len(kinds)]
        fault = Fault(site, operation, stack, ordinal, code, kind)
        self.schedule.append(asdict(fault))
        return fault
