import math
import numpy as np
import pytest


def test_qasm_bell_roundtrip_parameters_and_measurement_boundary():
    from verikernel.m6_quantum.qasm_parser import parse_qasm
    circuit = parse_qasm('OPENQASM 3.0; include "stdgates.inc"; qubit[2] q; bit[2] c; h q[0]; cx q[0],q[1]; c = measure q;')
    assert np.allclose(circuit.to_unitary()[:,0], [1/math.sqrt(2),0,0,1/math.sqrt(2)])
    assert np.allclose(parse_qasm(circuit.to_qasm3()).to_unitary(),circuit.to_unitary())
    assert circuit.measurements == ((0,0),(1,1))
    other = parse_qasm('OPENQASM 2.0; qreg a[2]; creg b[2]; ry(pi/3) a[0]; cz a[0],a[1]; swap a[0],a[1]; measure a -> b;')
    assert np.allclose(other.to_unitary().conj().T @ other.to_unitary(),np.eye(4))
    assert other.edges == ((0,1),(1,2))
    for text in ['OPENQASM 3.0; qubit[1] q; rx(__import__("os")) q[0];', 'OPENQASM 3.0; qubit[1] q; x q[1];', 'OPENQASM 3.0; qubit[1] q; bit c; c=measure q[0]; h q[0];']:
        with pytest.raises(ValueError):
            parse_qasm(text)


def test_ibm_snapshot_unit_conversion_and_survival_formula():
    from verikernel.m6_quantum.qasm_parser import parse_qasm
    from verikernel.m6_quantum.calibration_topology import HardwareCalibrationSnapshot
    data = {'backend_name':'imported-fixture','qubits':[[{'name':'T1','value':100,'unit':'us'},{'name':'T2','value':.0001,'unit':'s'},{'name':'readout_error','value':.01,'unit':''}] for i in range(2)], 'gates':[{'gate':'x','qubits':[i],'parameters':[{'name':'gate_error','value':.001},{'name':'gate_length','value':50,'unit':'ns'}]} for i in range(2)] + [{'gate':'cx','qubits':[0,1],'parameters':[{'name':'gate_error','value':.02},{'name':'gate_length','value':300,'unit':'ns'}]}]}
    snapshot = HardwareCalibrationSnapshot.from_ibm_json(data)
    circuit = parse_qasm('OPENQASM 3.0; qubit[2] q; x q[0]; cx q[0],q[1];')
    expected = .999*.98*.99**2*math.exp(-.35/100*4)
    assert snapshot.expected_fidelity(circuit,[0,1]) == pytest.approx(expected)
    assert snapshot.qubits[0].t2_us == pytest.approx(100)
    assert snapshot.expected_fidelity(circuit,[1,0]) == 0


def test_reroute_avoids_drift_and_checks_physical_basis_permutation(tmp_path):
    from verikernel.m6_quantum.qasm_parser import parse_qasm, unitary_fidelity
    from verikernel.m6_quantum.calibration_topology import HardwareCalibrationSnapshot
    from verikernel.m6_quantum.subgraph_rerouter import reroute_subgraph
    from verikernel.cli.main import verify_bundle
    circuit = parse_qasm('OPENQASM 3.0; qubit[3] q; ry(.7) q[0]; cx q[0],q[1]; cx q[1],q[2]; rz(.2) q[2];')
    baseline = HardwareCalibrationSnapshot.synthetic(12)
    drifted = baseline.with_drift(2,15)
    receipt = reroute_subgraph(circuit,[0,1,2],drifted,baseline=baseline)
    assert 2 not in receipt.layout
    assert receipt.recovered_fidelity > receipt.drifted_fidelity
    assert receipt.unitary_fidelity >= 1-1e-12
    bound = circuit.remap([9,8,7])
    assert unitary_fidelity(circuit,bound) >= 1-1e-12
    changed = parse_qasm('OPENQASM 3.0; qubit[3] q; x q[0];')
    assert unitary_fidelity(circuit,changed) < .99
    bundle = tmp_path/'rerouted.vkr'
    receipt.seal(bundle)
    assert verify_bundle(bundle)['valid']
