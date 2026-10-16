"""Omnibor."""
from __future__ import annotations
import hashlib
import re
from pathlib import Path


def gitoid_sha256(data: bytes) -> str:
    """Hash bytes with the canonical Git blob header. Complexity: O(n + W) time and O(n + M) space; n is traversed data, W delegated work, M retained delegated state."""
    return "gitoid:blob:sha256:" + hashlib.sha256(f"blob {len(data)}\0".encode() + data).hexdigest()


def file_gitoid(path: object) -> object:
    """Read an artifact and compute its Git blob identity. Complexity: O(n + W) time and O(n + M) space; n is traversed data, W delegated work, M retained delegated state."""
    return gitoid_sha256(Path(path).read_bytes())


def input_manifest(gitoids: object) -> object:
    """Build a sorted OmniBOR input manifest and its identity. Complexity: O(n + W) time and O(n + M) space; n is traversed data, W delegated work, M retained delegated state."""
    ordered = sorted(set(gitoids))
    if any(not re.fullmatch(r"gitoid:blob:sha256:[0-9a-f]{64}", g) for g in ordered):
        raise ValueError("invalid input GitOID")
    body = ("gitoid:blob:sha256\n" + "".join("blob " + g.rsplit(":", 1)[1] + "\n" for g in ordered)).encode()
    return body, gitoid_sha256(body)
