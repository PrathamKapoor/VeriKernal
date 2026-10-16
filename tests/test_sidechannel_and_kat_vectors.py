import math


def test_fixed_vectors_against_reference_and_native():
    from verikernel.m4_attest.kat_vectors import verify_known_answers
    result=verify_known_answers()
    assert result['verified']==5 and result['independent_signature_reference']


def test_welch_harness_reports_samples_and_actual_findings():
    from verikernel.m4_attest.sidechannel_audit import run_welch_t_test_audit,welch_statistic
    assert welch_statistic([1,2,3],[1,2,3])==0
    result=run_welch_t_test_audit(2000)
    assert result['samples_per_class']==2000
    assert result['randomized_interleaving']
    assert all(math.isfinite(row['t_statistic']) for row in result['paths'].values())
    assert all(row['all_rejected'] for row in result['paths'].values())
    assert result['all_below_threshold'],result
    assert result['constant_time_certification'] is False


def test_noncanonical_hint_is_rejected_after_normalized_backend_work(monkeypatch):
    from verikernel.m4_attest.pqc_signer import MLDSA65Signer
    import verikernel.m4_attest.native_signer as provider
    signer=MLDSA65Signer(seed=bytes([153])*32)
    message=b'VeriKernel timing evidence'
    signature=bytearray(signer.sign(message)); signature[-1]^=1
    observed=[]
    def capture(public,message,work):
        observed.append(work)
        return True
    monkeypatch.setattr(provider,'verify_signature',capture)
    assert MLDSA65Signer.verify(signer.public_key,message,bytes(signature)) is False
    assert observed and observed[0]!=bytes(signature)
