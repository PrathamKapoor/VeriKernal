"""Ratchet."""
from __future__ import annotations
import hashlib
import hmac
import secrets

try:
    from blake3 import blake3
except ImportError:
    blake3 = None

HASH_ALGORITHM = "blake3" if blake3 else "blake2b-256"


def digest(data: object) -> bytes:
    """digest. Complexity: O(n) time and O(1) mutable key space; n is the number of events processed."""
    return blake3(data).digest() if blake3 else hashlib.blake2b(data, digest_size=32).digest()


class ForwardSecureRatchet:
    """ForwardSecureRatchet. Complexity: O(n) time and O(1) mutable key space; n is the number of events processed."""
    def __init__(self, seed: object=None) -> None:
        """init. Complexity: O(n) time and O(1) mutable key space; n is the number of events processed."""
        seed = secrets.token_bytes(32) if seed is None else seed
        if len(seed) != 32:
            raise ValueError("ratchet seed must contain 32 bytes")
        self.state = bytearray(seed)
        self.commitment = digest(b"VK-RATCHET-COMMIT-V1" + seed)
        self.count = 0

    @property
    def terminal(self) -> object:
        """terminal. Complexity: O(n) time and O(1) mutable key space; n is the number of events processed."""
        return bytes(self.state)

    def tag(self, event: object) -> object:
        """tag. Complexity: O(n) time and O(1) mutable key space; n is the number of events processed."""
        tag = digest(b"VK-RATCHET-TAG-V1" + bytes(self.state) + event.to_bytes()[:96])
        next_state = digest(b"VK-RATCHET-STEP-V1" + bytes(self.state) + tag)
        for b in range(32):
            self.state[b] = 0
        self.state = bytearray(next_state)
        self.count += 1
        event.ratchet_tag = tag
        return tag


def ratchet_error(events: object, k0: object, expected_c0: object, expected_kn: object) -> object:
    """ratchet error. Complexity: O(n) time and O(1) mutable key space; n is the number of events processed."""
    ratchet = ForwardSecureRatchet(k0)
    commitment_ok = hmac.compare_digest(ratchet.commitment, expected_c0)
    first_error = None
    for i, event in enumerate(events):
        saved = event.ratchet_tag
        tag = digest(b"VK-RATCHET-TAG-V1" + bytes(ratchet.state) + event.to_bytes()[:96])
        tag_ok = hmac.compare_digest(tag,saved)
        if first_error is None and event.seq_no != i:
            first_error = {"index": i, "seq_no": event.seq_no, "reason": "sequence gap or reordering"}
        if first_error is None and not tag_ok:
            first_error = {"index": i, "seq_no": event.seq_no, "reason": "authentication mismatch"}
        next_key = digest(b'VK-RATCHET-STEP-V1'+bytes(ratchet.state)+tag)
        ratchet.state[:] = bytes(32)
        ratchet.state[:] = next_key
    terminal_ok = hmac.compare_digest(ratchet.terminal,expected_kn)
    if not commitment_ok:
        return {"index": None, "seq_no": None, "reason": "initial commitment mismatch"}
    if first_error is not None:
        return first_error
    if not terminal_ok:
        return {"index": len(events), "seq_no": len(events), "reason": "terminal state mismatch or tail truncation"}
    return None


def verify_ratchet_chain(events: object, k0: object, expected_c0: object, expected_kn: object) -> bool:
    """verify ratchet chain. Complexity: O(n) time and O(1) mutable key space; n is the number of events processed."""
    return ratchet_error(events, k0, expected_c0, expected_kn) is None


def seal_packed_sha256(buffer: bytearray, seed: bytes) -> tuple[bytes,bytes]:
    """Seal the explicit SHA-256 batch profile in O(n) time and O(1) native workspace."""
    from verikernel.rust_bridge import BatchEngine
    return BatchEngine().seal(buffer,seed)
