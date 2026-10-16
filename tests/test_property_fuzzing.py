def test_five_invariants_across_500_seeds_and_130_tree_sizes():
    from verikernel.formal_invariants import FormalInvariantVerifier
    result = FormalInvariantVerifier().run(seed=20261015,trials=500)
    assert result['seeds'] == 500
    assert result['wire_trials'] == 500
    assert result['tree_sizes'] == 130
    assert result['consistency_checks'] == 8515
    assert result['tamper_attacks'] == result['tamper_detections'] == 400
    assert result['minimality_trials'] == 100
    assert result['unitary_trials'] == 50
    assert result['minimum_unitary_fidelity'] >= 1-1e-12


def test_ratchet_reports_stream_index_instead_of_trusting_mutated_sequence():
    from verikernel.m4_attest.ratchet import ForwardSecureRatchet,ratchet_error
    from verikernel.schemas import KernelTelemetryEvent
    ratchet = ForwardSecureRatchet(bytes(32))
    events = [KernelTelemetryEvent(seq_no=i) for i in range(4)]
    for event in events:
        ratchet.tag(event)
    events[2].seq_no = 1<<60
    error = ratchet_error(events,bytes(32),ratchet.commitment,ratchet.terminal)
    assert error['index'] == 2
    assert error['seq_no'] == 1<<60
