"""Diff engine."""
from __future__ import annotations
import os
from collections.abc import Sequence
from verikernel.type_boundaries import ContractDict, ContractPatchDict, GhostDiffItemDict, validate_contract_dict

CATEGORIES = {1: ("GHOST_SUBPROCESS", "subprocesses"), 2: ("GHOST_FILESYSTEM", "filesystem"), 3: ("GHOST_NETWORK", "network"), 4: ("GHOST_SHARED_LIB", "shared_libraries"), 5: ("GHOST_ENVIRONMENT", "environment"), 9: ("GHOST_FILESYSTEM", "filesystem"), 10: ("GHOST_FILESYSTEM", "filesystem")}


class ContractEnforcer:
    """ContractEnforcer. Complexity: O(n + W) time and O(n + M) space; n is traversed data, W delegated work, M retained delegated state."""
    def __init__(self, contract: ContractDict) -> None:
        """Initialize the owned state and validate configuration limits. Complexity: O(n + W) time and O(n + M) space; n is traversed data, W delegated work, M retained delegated state."""
        self.contract = validate_contract_dict(contract)

    def violation(self, operation: int, target: str) -> GhostDiffItemDict | None:
        """Return the contract violation associated with an observed operation. Complexity: O(n + W) time and O(n + M) space; n is traversed data, W delegated work, M retained delegated state."""
        if operation not in CATEGORIES:
            return None
        kind, field = CATEGORIES[operation]
        values = self.contract.get(field, [])
        if field == "filesystem":
            target = os.path.realpath(target)
            allowed = {os.path.normcase(os.path.realpath(p)) for p in values}
        elif field in {"subprocesses", "shared_libraries"}:
            allowed = {os.path.normcase(p) for p in values}
            target = os.path.normcase(target)
        else:
            allowed = set(values)
        comparison = os.path.normcase(target) if field == "filesystem" else target
        return None if comparison in allowed else {"kind": kind, "field": field, "target": target}


def ghost_diff(violations: Sequence[GhostDiffItemDict], contract_gitoid: str | None=None) -> ContractPatchDict:
    """Compare observed targets with the declared dependency contract. Complexity: O(n + W) time and O(n + M) space; n is traversed data, W delegated work, M retained delegated state."""
    additions = {}
    for violation in violations:
        additions.setdefault(violation["field"], set()).add(violation["target"])
    return {"schema": "verikernel-contract-patch-v1", "base_contract_gitoid": contract_gitoid, "add": {k: sorted(v) for k, v in sorted(additions.items())}}
