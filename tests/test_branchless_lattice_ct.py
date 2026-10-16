import ctypes
import random
import pytest

Q = 8380417
R = 2**32 % Q


def test_modular_primitives_and_all_norm_positions():
    from verikernel.rust_bridge import LatticeEngine
    engine = LatticeEngine()
    rng = random.Random(31)
    for _ in range(1000):
        value = rng.randrange(-(Q << 30), Q << 30)
        assert engine.montgomery(value) % Q == value * pow(2**32, -1, Q) % Q
        coefficient = rng.randrange(-Q, Q)
        assert engine.caddq(coefficient) == (coefficient+Q if coefficient < 0 else coefficient)
    for index in range(256):
        coefficients = [0]*256
        for value in [99, -99, 100, -100, Q//2, -(Q//2)]:
            coefficients[index] = value
            assert engine.check_norm(coefficients, 100) == (abs(value) >= 100)
    assert engine.check_norm([0]*256, 0)


def test_ntt_matches_independent_reference_and_montgomery_inverse():
    from verikernel.rust_bridge import LatticeEngine
    from dilithium_py.ml_dsa import ML_DSA_65
    engine = LatticeEngine()
    rng = random.Random(32)
    for _ in range(20):
        coefficients = [rng.randrange(Q) for _ in range(256)]
        transformed = engine.ntt(coefficients)
        assert [value % Q for value in transformed] == ML_DSA_65.R(coefficients).to_ntt().coeffs
        # The FIPS reference inverse includes the Montgomery factor R.
        assert [value % Q for value in engine.inverse(transformed)] == [value*R % Q for value in coefficients]
    with pytest.raises(ValueError):
        engine.ntt([0]*255)


def test_native_ring_provider_matches_standard_signature():
    from verikernel.m4_attest.pqc_signer import MLDSA65Signer
    from dilithium_py.ml_dsa import ML_DSA_65
    seed, message = bytes([31])*32, b'native-ring-signature'
    signer = MLDSA65Signer(seed, arithmetic_backend='native-ring')
    pk, sk = ML_DSA_65.key_derive(seed)
    assert signer.public_key == pk and signer.secret_key == sk
    signature = signer.sign(message)
    assert signature == ML_DSA_65.sign(sk, message, deterministic=True)
    assert MLDSA65Signer.verify(pk, message, signature)
    assert signer.arithmetic_counts['ntt'] > 0
    assert signer.arithmetic_counts['norm'] > 0


def test_all_six_machine_code_symbols_and_secret_branch_rejection():
    from scripts.verify_constant_time_asm import verify_crypto_symbols, audit_control_flow
    report = verify_crypto_symbols()
    assert report['verified'] and len(report['symbols']) == 6
    assert all(row['secret_dependent_branches'] == [] for row in report['symbols'].values())
    with pytest.raises(ValueError):
        audit_control_flow([('1000','00000000','ldrb','w8, [x0]'), ('1004','00000000','cmp','w8, #0'), ('1008','00000000','b.ne','0x1000')], 'aarch64')
