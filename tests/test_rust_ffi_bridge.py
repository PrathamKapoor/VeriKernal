import random
import pytest


def test_native_algorithms_match_reference_and_abi():
    from verikernel import rust_bridge as bridge
    assert bridge.is_native_rust_loaded()
    assert bridge.abi_version() == 200 and bridge.event_size() == 128
    rng = random.Random(117)
    for index in range(1000):
        value = rng.getrandbits(64)
        data = rng.randbytes(index % 257)
        assert bridge.rust_splitmix64(value) == bridge.python_splitmix64(value)
        assert bridge.rust_fnv1a_hash(data) == bridge.python_fnv1a_hash(data)
        assert bridge.rust_compute_site_key(value, index, index*9, 4) == bridge.python_compute_site_key(value, index, index*9, 4)
    assert bridge.rust_fnv1a_hash(b'hello') == 0xa430d84680aabd0b


def test_bridge_fallback_and_batched_crypto():
    from verikernel.rust_bridge import RustBridge
    from verikernel.m4_attest.merkle_tiles import mth
    native = RustBridge()
    portable = RustBridge(native=False)
    assert portable.splitmix64(0) == 0xe220a8397b1dcdaf
    leaves = [bytes([i])*256 for i in range(17)]
    assert native.merkle_root_256(leaves) == portable.merkle_root_256(leaves) == mth(leaves)
    assert native.ratchet_step(bytes(32), bytes([3])*32) == portable.ratchet_step(bytes(32), bytes([3])*32)
    with pytest.raises(ValueError):
        native.merkle_root_256([b'short'])
