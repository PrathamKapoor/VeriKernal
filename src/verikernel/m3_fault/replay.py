"""Replay."""
from __future__ import annotations
import hashlib
import json
import struct
import os
import tempfile
from pathlib import Path
from verikernel.schemas import KernelTelemetryEvent

HEADER = struct.Struct("<8sQQ32s")
MAGIC = b"VKR\x00\x02\x00\x00\x00"
MAX_METADATA = 16 * 1024 * 1024


def write_container(path: object, metadata: object, events: object, exclusive: bool=False) -> None:
    """Write framed replay sections with their integrity metadata. Complexity: O(n + W) time and O(n + M) space; n is traversed data, W delegated work, M retained delegated state."""
    meta = json.dumps(metadata, sort_keys=True, separators=(",", ":")).encode()
    payload = b"".join(e.to_bytes() for e in events)
    if len(meta) > MAX_METADATA:
        raise ValueError("bundle metadata too large")
    data = HEADER.pack(MAGIC, len(meta), len(payload) // 128, hashlib.sha256(meta + payload).digest()) + meta + payload
    if exclusive:
        with tempfile.NamedTemporaryFile(dir=Path(path).parent,delete=False) as stream:
            temporary = Path(stream.name)
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        try:
            os.link(temporary,path)
        finally:
            temporary.unlink()
    else:
        Path(path).write_bytes(data)


def read_container(path: object) -> object:
    """Validate replay framing and decode the stored sections. Complexity: O(n + W) time and O(n + M) space; n is traversed data, W delegated work, M retained delegated state."""
    data = Path(path).read_bytes()
    if len(data) < HEADER.size:
        raise ValueError("truncated bundle header")
    magic, size, count, digest = HEADER.unpack_from(data)
    if magic != MAGIC or size > MAX_METADATA or HEADER.size + size + count * 128 != len(data):
        raise ValueError("invalid bundle framing")
    body = data[HEADER.size:]
    if hashlib.sha256(body).digest() != digest:
        raise ValueError("bundle checksum mismatch")
    metadata = json.loads(body[:size])
    if not isinstance(metadata, dict):
        raise ValueError("bundle metadata must be an object")
    payload = body[size:]
    return metadata, [KernelTelemetryEvent.from_bytes(payload[i:i+128]) for i in range(0, len(payload), 128)]
