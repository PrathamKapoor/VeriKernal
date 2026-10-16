"""Merkle tiles."""
from __future__ import annotations
import hmac
import hashlib
import struct
import os
import tempfile
from pathlib import Path
from .ratchet import digest

TILE_HEADER = struct.Struct("<8sQII32s")
TILE_MAGIC = b"VKTILE02"


def mth_packed_sha256(buffer: bytearray) -> bytes:
    """Compute the explicit SHA-256 batch root in O(n) time, O(log n) native space."""
    from verikernel.rust_bridge import BatchEngine
    return BatchEngine().root(buffer)


def leaf_hash(data: object, hash_fn: object=digest) -> bytes:
    """leaf hash. Complexity: O(n log n) time and O(n) space as an upper bound for list-based tree operations; n is the leaf count."""
    return hash_fn(b"\x00" + data)


def node_hash(left: object, right: object, hash_fn: object=digest) -> bytes:
    """node hash. Complexity: O(n log n) time and O(n) space as an upper bound for list-based tree operations; n is the leaf count."""
    return hash_fn(b"\x01" + left + right)


def largest_power_of_two_less_than(n: int) -> int:
    """largest power of two less than. Complexity: O(n log n) time and O(n) space as an upper bound for list-based tree operations; n is the leaf count."""
    if n <= 1:
        raise ValueError("split requires more than one leaf")
    k = 1
    while (k << 1) < n:
        k <<= 1
    return k


def mth(leaves: object, hash_fn: object=digest) -> bytes:
    """mth. Complexity: O(n log n) time and O(n) space as an upper bound for list-based tree operations; n is the leaf count."""
    if not leaves:
        return hash_fn(b"")
    if len(leaves) == 1:
        return leaf_hash(leaves[0],hash_fn)
    k = largest_power_of_two_less_than(len(leaves))
    return node_hash(mth(leaves[:k],hash_fn), mth(leaves[k:],hash_fn),hash_fn)


def prove_inclusion(m: int, leaves: object, hash_fn: object=digest) -> object:
    """prove inclusion. Complexity: O(n log n) time and O(n) space as an upper bound for list-based tree operations; n is the leaf count."""
    if not 0 <= m < len(leaves):
        raise ValueError("leaf index outside tree")
    if len(leaves) == 1:
        return []
    k = largest_power_of_two_less_than(len(leaves))
    return prove_inclusion(m, leaves[:k],hash_fn) + [mth(leaves[k:],hash_fn)] if m < k else prove_inclusion(m-k, leaves[k:],hash_fn) + [mth(leaves[:k],hash_fn)]


def verify_inclusion(leaf_bytes: object, m: int, n: int, proof: object, expected_root: object, hash_fn: object=digest) -> bool:
    """verify inclusion. Complexity: O(n log n) time and O(n) space as an upper bound for list-based tree operations; n is the leaf count."""
    if not 0 <= m < n or any(len(p) != 32 for p in proof):
        return False

    def walk(index: int, count: int, path: object) -> object:
        """Traverse the current subtree and accumulate its result. Complexity: O(n log n) time and O(n) space as an upper bound for list-based tree operations; n is the leaf count."""
        if count == 1:
            if path:
                raise ValueError("excess proof nodes")
            return leaf_hash(leaf_bytes,hash_fn)
        if not path:
            raise ValueError("missing proof node")
        k = largest_power_of_two_less_than(count)
        if index < k:
            return node_hash(walk(index, k, path[:-1]), path[-1],hash_fn)
        return node_hash(path[-1], walk(index-k, count-k, path[:-1]),hash_fn)

    try:
        return hmac.compare_digest(walk(m, n, proof), expected_root)
    except (ValueError, TypeError):
        return False


def prove_consistency(first: int, leaves: object, hash_fn: object=digest) -> object:
    """prove consistency. Complexity: O(n log n) time and O(n) space as an upper bound for list-based tree operations; n is the leaf count."""
    if not 0 <= first <= len(leaves):
        raise ValueError("prefix size outside tree")
    if first == 0:
        return []

    def subproof(m: int, data: object, complete: object) -> object:
        """subproof. Complexity: O(n log n) time and O(n) space as an upper bound for list-based tree operations; n is the leaf count."""
        if m == len(data):
            return [] if complete else [mth(data,hash_fn)]
        k = largest_power_of_two_less_than(len(data))
        if m <= k:
            return subproof(m, data[:k], complete) + [mth(data[k:],hash_fn)]
        return subproof(m-k, data[k:], False) + [mth(data[:k],hash_fn)]

    return subproof(first, leaves, True)


def verify_consistency(first: int, second: int, first_root: object, second_root: object, proof: object, hash_fn: object=digest) -> bool:
    """verify consistency. Complexity: O(n log n) time and O(n) space as an upper bound for list-based tree operations; n is the leaf count."""
    if not 0 <= first <= second or any(len(p) != 32 for p in proof):
        return False
    if first == 0:
        return not proof and hmac.compare_digest(first_root, hash_fn(b""))
    if first == second:
        return not proof and hmac.compare_digest(first_root, second_root)
    fn, sn = first-1, second-1
    while fn & 1:
        fn >>= 1
        sn >>= 1
    if fn == 0:
        fr = sr = first_root
        start = 0
    else:
        if not proof:
            return False
        fr = sr = proof[0]
        start = 1
    for item in proof[start:]:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            fr, sr = node_hash(item, fr,hash_fn), node_hash(item, sr,hash_fn)
            while fn and not fn & 1:
                fn >>= 1
                sn >>= 1
        else:
            sr = node_hash(sr, item,hash_fn)
        fn >>= 1
        sn >>= 1
    first_ok = hmac.compare_digest(fr,first_root)
    second_ok = hmac.compare_digest(sr,second_root)
    return bool((sn==0) & first_ok & second_ok)


def write_tiles(leaves: object, directory: object, hash_fn: object=digest) -> object:
    """write tiles. Complexity: O(n log n) time and O(n) space as an upper bound for list-based tree operations; n is the leaf count."""
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    paths = []
    for start in range(0, len(leaves), 256):
        hashes = b"".join(leaf_hash(d,hash_fn) for d in leaves[start:start+256])
        body = TILE_HEADER.pack(b"VKSH2563" if hash_fn is sha256_digest else TILE_MAGIC, start, len(hashes)//32, 0, hash_fn(hashes)) + hashes
        path = directory / (hash_fn(body).hex() + ".tile")
        publish_immutable(path, body)
        paths.append(path)
    write_tessera_tiles(leaves, directory,hash_fn)
    return paths


def publish_immutable(path: object, data: object) -> None:
    """publish immutable. Complexity: O(n log n) time and O(n) space as an upper bound for list-based tree operations; n is the leaf count."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(dir=path.parent, prefix=".vk-", delete=False) as stream:
        temporary = Path(stream.name)
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    try:
        try:
            os.link(temporary, path)
        except FileExistsError:
            if not hmac.compare_digest(path.read_bytes(), data):
                raise ValueError("immutable tile publication conflicts with existing content")
    finally:
        temporary.unlink()


def tessera_tile_path(level: int, index: int, width: int=256) -> object:
    """tessera tile path. Complexity: O(n log n) time and O(n) space as an upper bound for list-based tree operations; n is the leaf count."""
    if level < 0 or index < 0 or not 1 <= width <= 256:
        raise ValueError("invalid tile coordinates")
    digits = str(index)
    digits = digits.zfill((len(digits)+2)//3*3)
    groups = [digits[i:i+3] for i in range(0, len(digits), 3)]
    encoded = "/".join(["x"+group for group in groups[:-1]] + [groups[-1]])
    suffix = "" if width == 256 else f".p/{width}"
    return f"tile/{level}/{encoded}{suffix}"


def write_tessera_tiles(leaves: object, directory: object,hash_fn: object=digest) -> object:
    """write tessera tiles. Complexity: O(n log n) time and O(n) space as an upper bound for list-based tree operations; n is the leaf count."""
    hashes = [leaf_hash(leaf,hash_fn) for leaf in leaves]
    level = 0
    paths = []
    while hashes:
        for start in range(0, len(hashes), 256):
            tile = hashes[start:start+256]
            path = Path(directory) / tessera_tile_path(level, start//256, len(tile))
            publish_immutable(path, b"".join(tile))
            paths.append(path)
        parents = []
        for start in range(0, len(hashes)-255, 256):
            nodes = hashes[start:start+256]
            while len(nodes) > 1:
                nodes = [node_hash(nodes[i], nodes[i+1],hash_fn) for i in range(0, len(nodes), 2)]
            parents.append(nodes[0])
        hashes = parents
        level += 1
    return paths


def read_tile(path: object) -> object:
    """read tile. Complexity: O(n log n) time and O(n) space as an upper bound for list-based tree operations; n is the leaf count."""
    data = Path(path).read_bytes()
    if len(data) < TILE_HEADER.size:
        raise ValueError("truncated tile")
    magic, start, count, level, expected = TILE_HEADER.unpack_from(data)
    body = data[TILE_HEADER.size:]
    hash_fn = sha256_digest if magic == b"VKSH2563" else digest
    if magic not in {TILE_MAGIC,b"VKSH2563"} or level != 0 or not 1 <= count <= 256 or len(body) != count*32 or not hmac.compare_digest(hash_fn(body), expected):
        raise ValueError("invalid tile")
    return {"start": start, "level": level, "hashes": [body[i:i+32] for i in range(0, len(body), 32)]}


def sha256_digest(data: bytes) -> bytes:
    """Explicit SHA-256 profile; O(n) time and O(1) workspace."""
    return hashlib.sha256(data).digest()
