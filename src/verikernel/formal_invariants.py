"""Formal invariants."""
from __future__ import annotations
import json
import random
import time
from pathlib import Path
from verikernel.schemas import KernelTelemetryEvent
from verikernel.m4_attest.ratchet import ForwardSecureRatchet,ratchet_error
from verikernel.m4_attest.merkle_tiles import mth,prove_inclusion,verify_inclusion,prove_consistency,verify_consistency
from verikernel.m3_fault.ddmin import DeltaDebuggingShrinker
from verikernel.m6_quantum.qasm_parser import parse_qasm,unitary_fidelity
from verikernel.m6_quantum.calibration_topology import HardwareCalibrationSnapshot
from verikernel.m6_quantum.subgraph_rerouter import enumerate_layouts


def flip(data: object,rng: object) -> object:
    """Flip one selected payload bit without changing the other bytes. Complexity: O(n + W) time and O(n + M) space; n is traversed data, W delegated work, M retained delegated state."""
    data = bytearray(data)
    bit = rng.randrange(len(data)*8)
    data[bit//8] ^= 1<<(bit%8)
    return bytes(data)


class FormalInvariantVerifier:
    """FormalInvariantVerifier. Complexity: O(n + W) time and O(n + M) space; n is traversed data, W delegated work, M retained delegated state."""
    def wire(self,rng: object) -> None:
        """Exercise event serialization against randomized field values. Complexity: O(n + W) time and O(n + M) space; n is traversed data, W delegated work, M retained delegated state."""
        event = KernelTelemetryEvent(seq_no=rng.getrandbits(64),timestamp_ns=rng.getrandbits(64),pid=rng.getrandbits(32),tid=rng.getrandbits(32),syscall_nr=rng.getrandbits(32),fault_injected=rng.randrange(-(1<<31),1<<31),dev_id=rng.getrandbits(64),inode_nr=rng.getrandbits(64),mtime_ns=rng.getrandbits(64),call_stack_hash=rng.getrandbits(64),target_digest=rng.randbytes(32),ratchet_tag=rng.randbytes(32))
        encoded = event.to_bytes()
        if len(encoded)!=128 or KernelTelemetryEvent.from_bytes(encoded)!=event:
            raise AssertionError('I1 wire bijection failed')

    def merkle(self,rng: object,maximum: int=130) -> object:
        """Check inclusion, mutation rejection and append-only prefix proofs. Complexity: O(n + W) time and O(n + M) space; n is traversed data, W delegated work, M retained delegated state."""
        leaves = [rng.randbytes(rng.randrange(1,65)) for index in range(maximum)]
        roots = [mth(leaves[:n]) for n in range(maximum+1)]
        count = 0
        for n in range(1,maximum+1):
            index = rng.randrange(n)
            proof = prove_inclusion(index,leaves[:n])
            if not verify_inclusion(leaves[index],index,n,proof,roots[n]):
                raise AssertionError('I2 valid inclusion rejected')
            if verify_inclusion(flip(leaves[index],rng),index,n,proof,roots[n]):
                raise AssertionError('I2 altered leaf accepted')
            if proof:
                altered = list(proof)
                node = rng.randrange(len(proof))
                altered[node] = flip(altered[node],rng)
                if verify_inclusion(leaves[index],index,n,altered,roots[n]):
                    raise AssertionError('I2 altered proof accepted')
            for first in range(1,n+1):
                consistency = prove_consistency(first,leaves[:n])
                if not verify_consistency(first,n,roots[first],roots[n],consistency):
                    raise AssertionError('I2 prefix consistency rejected')
                if consistency:
                    corrupted = list(consistency)
                    at = rng.randrange(len(corrupted))
                    corrupted[at] = flip(corrupted[at],rng)
                    if verify_consistency(first,n,roots[first],roots[n],corrupted):
                        raise AssertionError('I2 altered consistency accepted')
                count += 1
        return count

    def ratchet(self,rng: object) -> object:
        """Check tag rejection for altered, reordered and truncated streams. Complexity: O(n + W) time and O(n + M) space; n is traversed data, W delegated work, M retained delegated state."""
        seed = rng.randbytes(32)
        ratchet = ForwardSecureRatchet(seed)
        events = [KernelTelemetryEvent(seq_no=i,target_digest=rng.randbytes(32)) for i in range(rng.randrange(5,51))]
        for event in events:
            ratchet.tag(event)
        if ratchet_error(events,seed,ratchet.commitment,ratchet.terminal):
            raise AssertionError('I3 intact chain rejected')
        at = rng.randrange(len(events)-1)
        changed = [KernelTelemetryEvent.from_bytes(e.to_bytes()) for e in events]
        changed[at] = KernelTelemetryEvent.from_bytes(flip(changed[at].to_bytes(),rng))
        swapped = list(events)
        swapped[at],swapped[at+1] = swapped[at+1],swapped[at]
        truncated = rng.randrange(1,len(events))
        attacks = [(changed,at),(swapped,at),(events[:at]+events[at+1:],at),(events[:truncated],truncated)]
        for attacked,index in attacks:
            error = ratchet_error(attacked,seed,ratchet.commitment,ratchet.terminal)
            if not error or error['index']!=index:
                raise AssertionError('I3 attack escaped or first corruption was misidentified')
        return len(attacks)

    def minimality(self,rng: object) -> object:
        """Check that removing any surviving fault clears the failure. Complexity: O(n + W) time and O(n + M) space; n is traversed data, W delegated work, M retained delegated state."""
        target = set(rng.sample(range(24),rng.randrange(1,4)))
        oracle = lambda chosen: target.issubset(chosen)
        shrinker = DeltaDebuggingShrinker(oracle)
        minimal = shrinker.shrink(range(24))
        if not oracle(minimal) or any(oracle(set(minimal)-{item}) for item in minimal):
            raise AssertionError('I4 minimum is not 1-minimal')
        if set(minimal)!=target:
            raise AssertionError('I4 monotone target was not isolated')
        return shrinker.evaluations

    def unitary(self,rng: object) -> object:
        """Check trace fidelity after relabeling circuit qubits. Complexity: O(n + W) time and O(n + M) space; n is traversed data, W delegated work, M retained delegated state."""
        count = rng.choice([2,3,4])
        gates = [f'ry({rng.uniform(-3,3)!r}) q[{q}]; rz({rng.uniform(-3,3)!r}) q[{q}];' for q in range(count)]
        gates += [f'cx q[{q}],q[{q+1}];' for q in range(count-1)]
        circuit = parse_qasm(f'OPENQASM 3.0; qubit[{count}] q; '+''.join(gates))
        snapshot = HardwareCalibrationSnapshot.synthetic(12)
        layouts = list(enumerate_layouts(circuit,snapshot))
        if not layouts:
            raise AssertionError('I5 fixture has no valid topology embedding')
        bound = circuit.remap(rng.choice(layouts))
        fidelity = unitary_fidelity(circuit,bound)
        if fidelity<1-1e-12:
            raise AssertionError('I5 physical basis permutation changed the unitary')
        return fidelity

    def run(self,seed: int=20261015,trials: int=500,output: object=None) -> object:
        """Run the formal invariants workflow and collect its results. Complexity: O(n + W) time and O(n + M) space; n is traversed data, W delegated work, M retained delegated state."""
        if trials<500:
            raise ValueError('the invariant campaign requires at least 500 seeds')
        start = time.perf_counter()
        attacks,evaluations,minimum = 0,0,1.0
        for trial in range(trials):
            rng = random.Random(seed+trial)
            self.wire(rng)
            if trial<100:
                attacks += self.ratchet(rng)
                evaluations += self.minimality(rng)
            if trial<50:
                minimum = min(minimum,self.unitary(rng))
        consistency = self.merkle(random.Random(seed))
        result = {'seed':seed,'seeds':trials,'wire_trials':trials,'tree_sizes':130,'consistency_checks':consistency,'tamper_attacks':attacks,'tamper_detections':attacks,'tamper_detection_percent':100*attacks/attacks,'minimality_trials':100,'oracle_evaluations':evaluations,'unitary_trials':50,'minimum_unitary_fidelity':minimum,'seconds':time.perf_counter()-start,'scope':'finite seeded executable invariants; not an unbounded theorem proof'}
        if output:
            destination = Path(output)
            destination.parent.mkdir(parents=True,exist_ok=True)
            destination.write_text(json.dumps(result,indent=2),encoding='utf-8')
        return result
