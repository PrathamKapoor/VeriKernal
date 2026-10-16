"""Epoch service."""
from __future__ import annotations
import hashlib
import hmac
import secrets
import threading
import time
from queue import SimpleQueue
from verikernel.m5_ringbuf.native import NativeEventQueue
from verikernel.schemas import KernelTelemetryEvent
from verikernel.m1_contract.compiler import canonical_json
from .ratchet import ForwardSecureRatchet, HASH_ALGORITHM, verify_ratchet_chain
from .merkle_tiles import mth, prove_consistency, verify_consistency
from .pqc_signer import MLDSA65Signer
from .dsse_envelope import seal, verify, statement_payload

_monotonic = time.monotonic


class EpochAttestor:
    """EpochAttestor. Complexity: O(n + W) time and O(n + M) space; n is traversed data, W delegated work, M retained delegated state."""
    def __init__(self, seed: object=None, max_events: int=65536, interval: float=.1, signer: object=None) -> None:
        """Initialize the owned state and validate configuration limits. Complexity: O(n + W) time and O(n + M) space; n is traversed data, W delegated work, M retained delegated state."""
        if max_events < 1 or interval <= 0:
            raise ValueError("invalid epoch thresholds")
        self.audit_seed = secrets.token_bytes(32) if seed is None else bytes(seed)
        self.ratchet = ForwardSecureRatchet(self.audit_seed)
        self.signer = signer or MLDSA65Signer()
        self.public_key = self.signer.public_key
        self.max_events, self.interval = max_events, interval
        self.condition = threading.Condition()
        try:
            self.pending = NativeEventQueue(capacity=max(64, max_events*4))
            self.transport_backend = "rust-lock-free-fifo"
        except OSError:
            self.pending = SimpleQueue()
            self.transport_backend = "portable-simple-queue"
        self._pending_count = 0
        self._producer_lock = threading.Lock()
        self.events, self.epochs = [], []
        self._submitted = 0
        self._closed = False
        self._error = None
        self._thread = threading.Thread(target=self._consume, name="verikernel-epochs", daemon=False)
        self._thread.start()

    def __enter__(self) -> object:
        """Activate the scoped resource and return its handle. Complexity: O(n + W) time and O(n + M) space; n is traversed data, W delegated work, M retained delegated state."""
        return self

    def __exit__(self, typ: object, value: object, tb: object) -> bool:
        """Close the scoped resource and propagate workload errors. Complexity: O(n + W) time and O(n + M) space; n is traversed data, W delegated work, M retained delegated state."""
        self.close()
        return False

    def _check(self) -> None:
        """Propagate a background signing failure to the caller. Complexity: O(n + W) time and O(n + M) space; n is traversed data, W delegated work, M retained delegated state."""
        if self._error is not None:
            raise RuntimeError("epoch consumer failed") from self._error

    def submit(self, event: object) -> None:
        """Admit an event to the ordered asynchronous signing stream. Complexity: O(n + W) time and O(n + M) space; n is traversed data, W delegated work, M retained delegated state."""
        with self._producer_lock:
            with self.condition:
                self._check()
                if self._closed:
                    raise RuntimeError("epoch service is closed")
                if event.seq_no != self._submitted:
                    raise ValueError("event sequence is not contiguous")
                self.ratchet.tag(event)
                if self.transport_backend == "rust-lock-free-fifo":
                    while not self.pending.try_push(event):
                        self.condition.wait(.1)
                        self._check()
                        if self._closed:
                            raise RuntimeError("epoch service closed during backpressure")
                else:
                    self.pending.put(event.to_bytes())
                self._pending_count += 1
                self._submitted += 1
                self.condition.notify_all()

    def _seal(self, terminal: object) -> None:
        """Seal the pending epoch and advance its checkpoint chain. Complexity: O(n + W) time and O(n + M) space; n is traversed data, W delegated work, M retained delegated state."""
        count = len(self.events)
        previous_count = self.epochs[-1]["statement"]["predicate"]["event_count"] if self.epochs else 0
        if self.epochs and count == previous_count:
            return
        leaves = [e.to_bytes() for e in self.events]
        previous_envelope = self.epochs[-1]["envelope"] if self.epochs else None
        predicate = {"epoch_index": len(self.epochs), "event_count": count, "previous_count": previous_count, "hash_algorithm": HASH_ALGORITHM, "merkle_root": mth(leaves).hex(), "ratchet_commitment": self.ratchet.commitment.hex(), "ratchet_terminal": terminal.hex(), "previous_envelope_sha256": hashlib.sha256(canonical_json(previous_envelope)).hexdigest() if previous_envelope else None, "consistency_proof": [p.hex() for p in prove_consistency(previous_count, leaves)]}
        statement = {"_type": "https://in-toto.io/Statement/v1", "subject": [{"name": "event-stream", "digest": {"sha256": hashlib.sha256(b"".join(leaves)).hexdigest()}}], "predicateType": "https://verikernel.dev/epoch/v1", "predicate": predicate}
        envelope = seal(statement, self.signer)
        with self.condition:
            self.epochs.append({"statement": statement, "envelope": envelope})
            self.condition.notify_all()

    def _consume(self) -> None:
        """Drain queued events and seal epochs at the configured boundaries. Complexity: O(n + W) time and O(n + M) space; n is traversed data, W delegated work, M retained delegated state."""
        terminal = self.audit_seed
        verifier = ForwardSecureRatchet(self.audit_seed)
        deadline = _monotonic() + self.interval
        last_sealed = 0
        try:
            while True:
                with self.condition:
                    while not self._pending_count and not self._closed and _monotonic() < deadline:
                        self.condition.wait(deadline - _monotonic())
                    if self._pending_count:
                        item = self.pending.try_pop() if self.transport_backend == "rust-lock-free-fifo" else KernelTelemetryEvent.from_bytes(self.pending.get_nowait())
                        self._pending_count -= 1
                        self.condition.notify_all()
                    else:
                        item = None
                    finished = self._closed and not self._pending_count and item is None
                if item is not None:
                    expected = item.ratchet_tag
                    if item.seq_no != len(self.events):
                        raise ValueError("FIFO sequence divergence")
                    verifier.tag(item)
                    if not hmac.compare_digest(expected, item.ratchet_tag):
                        raise ValueError("producer authentication mismatch")
                    terminal = verifier.terminal
                    self.events.append(item)
                due = len(self.events) - last_sealed >= self.max_events
                expired = _monotonic() >= deadline
                if due or (expired and len(self.events) > last_sealed) or finished:
                    self._seal(terminal)
                    last_sealed = len(self.events)
                    deadline = _monotonic() + self.interval
                elif expired:
                    deadline = _monotonic() + self.interval
                if finished:
                    return
        except BaseException as exc:
            with self.condition:
                self._error = exc
                self.condition.notify_all()

    def wait_for_epochs(self, count: int, timeout: int=10) -> bool:
        """Wait for signed epochs or a background failure within the deadline. Complexity: O(n + W) time and O(n + M) space; n is traversed data, W delegated work, M retained delegated state."""
        deadline = _monotonic() + timeout
        with self.condition:
            while len(self.epochs) < count:
                self._check()
                remaining = deadline - _monotonic()
                if remaining <= 0:
                    return False
                self.condition.wait(remaining)
            return True

    def close(self) -> None:
        """Finish pending work and release owned resources. Complexity: O(n + W) time and O(n + M) space; n is traversed data, W delegated work, M retained delegated state."""
        with self.condition:
            self._closed = True
            self.condition.notify_all()
        self._thread.join()
        self._check()
        if self.transport_backend == "rust-lock-free-fifo":
            self.pending.close()

    def verify_epochs(self) -> bool:
        """Verify every epoch and its link to the cumulative stream. Complexity: O(n + W) time and O(n + M) space; n is traversed data, W delegated work, M retained delegated state."""
        previous_count, previous_root, previous_envelope = 0, mth([]), None
        try:
            for index, epoch in enumerate(self.epochs):
                statement, envelope = epoch["statement"], epoch["envelope"]
                if not verify(envelope, self.public_key) or statement_payload(envelope) != statement:
                    return False
                predicate = statement["predicate"]
                count = predicate["event_count"]
                if predicate["epoch_index"] != index or predicate["previous_count"] != previous_count or count < previous_count or count > len(self.events):
                    return False
                records = self.events[:count]
                root = mth([e.to_bytes() for e in records])
                if predicate["merkle_root"] != root.hex():
                    return False
                expected_previous = hashlib.sha256(canonical_json(previous_envelope)).hexdigest() if previous_envelope else None
                if predicate["previous_envelope_sha256"] != expected_previous:
                    return False
                if not verify_consistency(previous_count, count, previous_root, root, [bytes.fromhex(p) for p in predicate["consistency_proof"]]):
                    return False
                if not verify_ratchet_chain(records, self.audit_seed, bytes.fromhex(predicate["ratchet_commitment"]), bytes.fromhex(predicate["ratchet_terminal"])):
                    return False
                previous_count, previous_root, previous_envelope = count, root, envelope
            return bool(self.epochs) and previous_count == len(self.events) == self._submitted
        except (KeyError, ValueError, TypeError):
            return False
