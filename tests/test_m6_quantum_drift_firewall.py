import pytest


def test_circuit_equivalence_global_phase_and_gate_rejection():
    from verikernel.m6_quantum.circuit_contract import CircuitContract
    a = CircuitContract(1, [("H", 0), ("H", 0)])
    assert a.equivalent(CircuitContract(1, []))
    assert not a.equivalent(CircuitContract(1, [("X", 0)]))
    with pytest.raises(ValueError):
        CircuitContract(1, [("UNKNOWN", 0)])


def test_firewall_all_four_actions_and_uncertainty():
    from verikernel.m6_quantum.drift_firewall import audit_uncertainty
    assert audit_uncertainty([.5, .5], 10000, [.5, .5], [.5, .5])["verdict"] == "PREDICT_CERTIFIED"
    assert audit_uncertainty([.01, .99], 10000, [.5, .5], [.5, .5])["verdict"] == "ABSTAIN_OOD_IGNORANCE"
    assert audit_uncertainty([.5, .5], 10000, [.5, .5], [.99, .01])["verdict"] == "ABSTAIN_HARDWARE_DRIFT"
    assert audit_uncertainty([.5, .5], 10, [.5, .5], [.5, .5])["verdict"] == "ADD_SHOTS"
    with pytest.raises(ValueError):
        audit_uncertainty([.5], 0, [.5, .5], [.5, .5])


def test_observable_equivalence_checks_offdiagonal_coherence():
    from verikernel.m6_quantum.circuit_contract import CircuitContract
    a = CircuitContract(1, [("H", 0)])
    b = CircuitContract(1, [("H", 0), ("Y", 0)])
    assert not a.equivalent(b, observable=[1, -1])
