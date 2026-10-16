"""Case3 quantum drift reroute."""
from __future__ import annotations
from typing import Any
import argparse
import json
import secrets
from dataclasses import asdict
from pathlib import Path
from verikernel.m6_quantum.qasm_parser import parse_qasm
from verikernel.m6_quantum.calibration_topology import HardwareCalibrationSnapshot
from verikernel.m6_quantum.subgraph_rerouter import reroute_subgraph
from verikernel.m6_quantum.drift_firewall import audit_uncertainty

SOURCE = 'OPENQASM 3.0; include "stdgates.inc"; qubit[3] q; bit[3] c; ry(pi/3) q[0]; rx(.4) q[1]; cx q[0],q[1]; cx q[1],q[2]; rz(.2) q[2]; c=measure q;'


def run(output_dir: Any) -> Any:
    """Run the quantum drift reroute workflow and collect its results. Complexity: O(n + W) time and O(n + M) space; n is traversed data, W delegated work, M retained delegated state."""
    directory = Path(output_dir)
    directory.mkdir(parents=True,exist_ok=True)
    circuit = parse_qasm(SOURCE)
    baseline = HardwareCalibrationSnapshot.synthetic(12)
    drifted = baseline.with_drift(2,15)
    firewall = audit_uncertainty([.49,.51],4096,baseline.probe_distribution(2),drifted.probe_distribution(2))
    receipt = reroute_subgraph(circuit,[0,1,2],drifted,baseline,firewall['verdict'])
    bundle = directory/('rerouted-'+secrets.token_hex(8)+'.vkr')
    receipt.seal(bundle)
    result = {'case':'quantum-drift-reroute','evidence':baseline.provenance,'q2_t2_before_us':baseline.qubits[2].t2_us,'q2_t2_after_us':drifted.qubits[2].t2_us,'firewall':firewall,'reroute':asdict(receipt),'couplers':[[a,b] for a,b in drifted.couplers if a<b],'qubits':list(drifted.qubits),'bundle':str(bundle)}
    result['calibration'] = {str(q):asdict(value) for q,value in drifted.qubits.items()}
    (directory/'circuit.qasm').write_text(circuit.to_qasm3(),encoding='utf-8')
    (directory/'result.json').write_text(json.dumps(result,indent=2),encoding='utf-8')
    return result


if __name__=='__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--output-dir',default='dist/case3')
    print(json.dumps(run(parser.parse_args().output_dir),indent=2))
