import copy
import pytest


def test_ratchet_erasure_mutation_and_tail_truncation():
    from verikernel.m4_attest.ratchet import ForwardSecureRatchet, verify_ratchet_chain
    from verikernel.schemas import KernelTelemetryEvent
    seed = bytes(range(32))
    ratchet = ForwardSecureRatchet(seed)
    old = ratchet.state
    events = [KernelTelemetryEvent(seq_no=i) for i in range(4)]
    for event in events:
        ratchet.tag(event)
    assert old == bytearray(32)
    assert verify_ratchet_chain(events, seed, ratchet.commitment, ratchet.terminal)
    assert not verify_ratchet_chain(events[:-1], seed, ratchet.commitment, ratchet.terminal)
    changed = copy.deepcopy(events)
    changed[2].pid = 7
    assert not verify_ratchet_chain(changed, seed, ratchet.commitment, ratchet.terminal)


def test_rfc9162_inclusion_and_consistency_all_prefixes():
    from verikernel.m4_attest.merkle_tiles import mth, prove_inclusion, verify_inclusion, prove_consistency, verify_consistency
    for n in range(1, 33):
        leaves = [str(i).encode() for i in range(n)]
        for index in range(n):
            proof = prove_inclusion(index, leaves)
            assert verify_inclusion(leaves[index], index, n, proof, mth(leaves))
            assert not verify_inclusion(b"altered", index, n, proof, mth(leaves))
            assert not verify_inclusion(leaves[index], index, n, proof + [bytes(32)], mth(leaves))
        for first in range(n + 1):
            proof = prove_consistency(first, leaves)
            assert verify_consistency(first, n, mth(leaves[:first]), mth(leaves), proof)
            if first:
                assert not verify_consistency(first, n, bytes(32), mth(leaves), proof)


def test_static_tile_roundtrip_and_digest_rejection(tmp_path):
    from verikernel.m4_attest.merkle_tiles import write_tiles, read_tile
    paths = write_tiles([b"x"] * 257, tmp_path)
    assert len(paths) == 2
    assert len(read_tile(paths[0])["hashes"]) == 256
    path = paths[0]
    data = bytearray(path.read_bytes())
    data[-1] ^= 1
    path.write_bytes(data)
    with pytest.raises(ValueError):
        read_tile(path)


def test_mldsa_standard_sizes_determinism_and_tamper():
    from verikernel.m4_attest.pqc_signer import MLDSA65Signer
    signer = MLDSA65Signer(seed=bytes(32))
    assert len(signer.public_key) == 1952 and len(signer.secret_key) == 4032
    sig = signer.sign(b"receipt")
    assert len(sig) == 3309 and sig == signer.sign(b"receipt")
    assert signer.verify(signer.public_key, b"receipt", sig)
    assert not signer.verify(signer.public_key, b"receipu", sig)
    altered = bytearray(sig)
    altered[100] ^= 1
    assert not signer.verify(signer.public_key, b"receipt", bytes(altered))
    altered_pk = bytearray(signer.public_key)
    altered_pk[100] ^= 1
    assert not signer.verify(bytes(altered_pk), b"receipt", sig)


def test_dsse_pae_and_payload_type_binding():
    from verikernel.m4_attest.dsse_envelope import pae, seal, verify
    from verikernel.m4_attest.pqc_signer import MLDSA65Signer
    assert pae("x", b"abc") == b"DSSEv1 1 x 3 abc"
    signer = MLDSA65Signer(seed=bytes(32))
    envelope = seal({"_type": "https://in-toto.io/Statement/v1", "test": 7}, signer)
    assert verify(envelope, signer.public_key)
    envelope["payloadType"] = "other"
    assert not verify(envelope, signer.public_key)


def test_native_or_portable_nondeterministic_signature_verifies():
    from verikernel.m4_attest.pqc_signer import MLDSA65Signer
    signer = MLDSA65Signer(seed=bytes(32))
    sig = signer.sign(b"native", deterministic=False)
    assert signer.verify(signer.public_key, b"native", sig)
    assert not signer.verify(signer.public_key, b"tampered", sig)


def test_epoch_service_seals_count_and_idle_deadline():
    import time
    from verikernel.m4_attest.epoch_service import EpochAttestor
    from verikernel.schemas import KernelTelemetryEvent
    from verikernel.m4_attest.dsse_envelope import verify
    with EpochAttestor(seed=bytes(32), max_events=2, interval=.02) as service:
        service.submit(KernelTelemetryEvent(seq_no=0))
        service.submit(KernelTelemetryEvent(seq_no=1))
        assert service.wait_for_epochs(1, timeout=10)
        service.submit(KernelTelemetryEvent(seq_no=2))
        assert service.wait_for_epochs(2, timeout=10)
    assert [e["statement"]["predicate"]["event_count"] for e in service.epochs] == [2, 3]
    assert all(verify(e["envelope"], service.public_key) for e in service.epochs)
    assert service.verify_epochs()


def test_epoch_service_rejects_reordered_and_mutated_records():
    from verikernel.m4_attest.epoch_service import EpochAttestor
    from verikernel.schemas import KernelTelemetryEvent
    with EpochAttestor(seed=bytes(32), max_events=100, interval=10) as service:
        event = KernelTelemetryEvent(seq_no=0)
        service.submit(event)
        event.pid = 999
        with pytest.raises(ValueError):
            service.submit(KernelTelemetryEvent(seq_no=0))
    assert service.verify_epochs()
    assert service.events[0].pid == 0
    service.epochs[-1]["statement"]["predicate"]["event_count"] = 0
    assert not service.verify_epochs()


def test_rust_mldsa_matches_independent_reference():
    from verikernel.m4_attest.native_signer import RustMLDSA65
    from dilithium_py.ml_dsa import ML_DSA_65
    signer = RustMLDSA65(bytes(32))
    public, secret = ML_DSA_65.key_derive(bytes(32))
    assert signer.public_key == public and signer.secret_key == secret
    signature = signer.sign(b"independent-check")
    assert ML_DSA_65.verify(public, b"independent-check", signature)
    assert signer.verify(public, b"independent-check", signature)
    assert not signer.verify(public, b"modified", signature)


def test_tlog_tile_layout_is_headerless_and_immutable(tmp_path):
    from verikernel.m4_attest.merkle_tiles import write_tessera_tiles, tessera_tile_path, mth
    assert tessera_tile_path(0, 1234067, 8) == "tile/0/x001/x234/067.p/8"
    leaves = [str(i).encode() for i in range(257)]
    write_tessera_tiles(leaves, tmp_path)
    assert (tmp_path / "tile/0/000").stat().st_size == 8192
    assert (tmp_path / "tile/0/001.p/1").stat().st_size == 32
    assert (tmp_path / "tile/1/000.p/1").read_bytes() == mth(leaves[:256])
    with pytest.raises(ValueError):
        write_tessera_tiles([b"changed"] + leaves[1:], tmp_path)


def test_bundle_verifier_checks_signed_intermediate_ratchet(tmp_path):
    from verikernel.cli.main import pack_receipt, verify_bundle
    from verikernel.m4_attest.epoch_service import EpochAttestor
    from verikernel.m4_attest.dsse_envelope import seal
    from verikernel.schemas import KernelTelemetryEvent
    with EpochAttestor(seed=bytes(32)) as service:
        service.submit(KernelTelemetryEvent(seq_no=0))
    epoch = service.epochs[0]
    epoch["statement"]["predicate"]["ratchet_terminal"] = bytes(32).hex()
    epoch["envelope"] = seal(epoch["statement"], service.signer)
    path = tmp_path / "incorrect-epoch.vkr"
    pack_receipt(path, {"epochs": service.epochs, "epoch_public_key": service.public_key.hex()}, service.events, service.audit_seed, service.ratchet)
    with pytest.raises(ValueError, match="periodic ratchet"):
        verify_bundle(path)


def test_receipt_collision_preserves_existing_signed_evidence(tmp_path):
    from verikernel.cli.main import pack_receipt,verify_bundle
    from verikernel.m4_attest.ratchet import ForwardSecureRatchet
    from verikernel.schemas import KernelTelemetryEvent
    path = tmp_path/'unique.vkr'
    seed = bytes(32)
    ratchet = ForwardSecureRatchet(seed)
    event = KernelTelemetryEvent()
    ratchet.tag(event)
    pack_receipt(path,{},[event],seed,ratchet)
    original = path.read_bytes()
    with pytest.raises(FileExistsError):
        pack_receipt(path,{'other':True},[event],seed,ratchet)
    assert path.read_bytes() == original and verify_bundle(path)['valid']
