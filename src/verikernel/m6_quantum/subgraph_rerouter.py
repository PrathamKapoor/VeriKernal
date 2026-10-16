"""Subgraph rerouter."""
from __future__ import annotations
import hashlib
import secrets
from dataclasses import dataclass,asdict
from verikernel.m1_contract.compiler import canonical_json
from verikernel.omnibor import gitoid_sha256
from .qasm_parser import unitary_fidelity


def enumerate_layouts(circuit: object,snapshot: object) -> object:
    """enumerate layouts. Complexity: O(g * 4^q + P) time and O(4^q + P) space as an upper bound; g counts gates and P is enumerated layout work."""
    interactions = [gate for gate in circuit.gates if len(gate.qubits)==2]
    degrees = {q:sum(q in gate.qubits for gate in interactions) for q in circuit.labels}
    order = sorted(circuit.labels,key=lambda q:(-degrees[q],q))
    healthy = sorted(q for q,value in snapshot.qubits.items() if value.t2_us>=20 and value.oneq_error<.02 and value.readout_error<.15)
    mapping = {}
    def search(index: int) -> object:
        """search. Complexity: O(g * 4^q + P) time and O(4^q + P) space as an upper bound; g counts gates and P is enumerated layout work."""
        if index==len(order):
            chosen = set(mapping.values())
            visited, pending = set(),[min(chosen)]
            while pending:
                q = pending.pop()
                if q in visited:
                    continue
                visited.add(q)
                pending.extend(b for a,b in snapshot.couplers if a==q and b in chosen and b not in visited)
                pending.extend(a for a,b in snapshot.couplers if b==q and a in chosen and a not in visited)
            if visited==chosen:
                yield tuple(mapping[q] for q in circuit.labels)
            return
        logical = order[index]
        for physical in healthy:
            if physical in mapping.values():
                continue
            mapping[logical] = physical
            valid = True
            for gate in interactions:
                a,b = gate.qubits
                if a in mapping and b in mapping:
                    edge = (mapping[a],mapping[b])
                    calibrated = snapshot.couplers.get(edge)
                    if calibrated is None and gate.name in {'cz','swap'}:
                        calibrated = snapshot.couplers.get(edge[::-1])
                    if calibrated is None or calibrated.error>=.05:
                        valid = False
                        break
            if valid:
                yield from search(index+1)
            del mapping[logical]
    yield from search(0)


@dataclass(frozen=True)
class SubgraphRerouteReceipt:
    """SubgraphRerouteReceipt. Complexity: O(g * 4^q + P) time and O(4^q + P) space as an upper bound; g counts gates and P is enumerated layout work."""
    original_layout: tuple
    layout: tuple
    pre_drift_fidelity: float
    drifted_fidelity: float
    recovered_fidelity: float
    unitary_fidelity: float
    candidates: int
    circuit_gitoid: str
    calibration_gitoid: str
    provenance: str
    verdict: str

    def seal(self,path: object) -> object:
        """Sign a canonical statement and return its DSSE envelope. Complexity: O(g * 4^q + P) time and O(4^q + P) space as an upper bound; g counts gates and P is enumerated layout work."""
        from verikernel.cli.main import pack_receipt
        from verikernel.schemas import KernelTelemetryEvent
        from verikernel.m4_attest.ratchet import ForwardSecureRatchet
        receipt = asdict(self)
        seed = secrets.token_bytes(32)
        ratchet = ForwardSecureRatchet(seed)
        event = KernelTelemetryEvent(syscall_nr=8,target_digest=hashlib.sha256(canonical_json(receipt)).digest())
        ratchet.tag(event)
        return pack_receipt(path,{'receipt':receipt},[event],seed,ratchet)


def reroute_subgraph(circuit: object,initial_layout: object,calibration: object,baseline: object=None,verdict: str='ABSTAIN_HARDWARE_DRIFT') -> object:
    """reroute subgraph. Complexity: O(g * 4^q + P) time and O(4^q + P) space as an upper bound; g counts gates and P is enumerated layout work."""
    if verdict!='ABSTAIN_HARDWARE_DRIFT':
        raise ValueError('rerouting requires a hardware drift verdict')
    best,score,count = None,-1.0,0
    for layout in enumerate_layouts(circuit,calibration):
        count += 1
        fidelity = calibration.expected_fidelity(circuit,layout)
        if fidelity>score:
            best,score = layout,fidelity
    if best is None:
        raise ValueError('no healthy connected embedding exists')
    equivalence = unitary_fidelity(circuit,circuit.remap(best))
    if equivalence<1-1e-9:
        raise ValueError('logical unitary changed during remapping')
    return SubgraphRerouteReceipt(tuple(initial_layout),best,(baseline or calibration).expected_fidelity(circuit,initial_layout),calibration.expected_fidelity(circuit,initial_layout),score,equivalence,count,gitoid_sha256(circuit.to_qasm3().encode()),calibration.identity,calibration.provenance,verdict)
