"""Calibration topology."""
from __future__ import annotations
import copy
import json
import math
import random
from dataclasses import dataclass,asdict
from pathlib import Path
from verikernel.m1_contract.compiler import canonical_json
from verikernel.omnibor import gitoid_sha256


@dataclass(frozen=True)
class QubitCalibration:
    """QubitCalibration. Complexity: O(g * 4^q + P) time and O(4^q + P) space as an upper bound; g counts gates and P is enumerated layout work."""
    t1_us: float
    t2_us: float
    oneq_error: float
    readout_error: float
    duration_us: float = .035


@dataclass(frozen=True)
class CouplerCalibration:
    """CouplerCalibration. Complexity: O(g * 4^q + P) time and O(4^q + P) space as an upper bound; g counts gates and P is enumerated layout work."""
    error: float
    duration_us: float = .35


def microseconds(value: object,unit: object) -> object:
    """microseconds. Complexity: O(g * 4^q + P) time and O(4^q + P) space as an upper bound; g counts gates and P is enumerated layout work."""
    scales = {'s':1e6,'ms':1e3,'us':1,'µs':1,'ns':.001}
    if unit not in scales:
        raise ValueError('unsupported calibration time unit')
    return float(value)*scales[unit]


class HardwareCalibrationSnapshot:
    """HardwareCalibrationSnapshot. Complexity: O(g * 4^q + P) time and O(4^q + P) space as an upper bound; g counts gates and P is enumerated layout work."""
    def __init__(self,qubits: int,couplers: object,provenance: object) -> None:
        """init. Complexity: O(g * 4^q + P) time and O(4^q + P) space as an upper bound; g counts gates and P is enumerated layout work."""
        self.qubits,self.couplers,self.provenance = dict(qubits),dict(couplers),str(provenance)
        if not self.qubits:
            raise ValueError('empty calibration')
        for index,qubit in self.qubits.items():
            if type(index) is not int or index<0 or any(not math.isfinite(value) or value<=0 for value in [qubit.t1_us,qubit.t2_us,qubit.duration_us]) or any(not math.isfinite(value) or not 0<=value<1 for value in [qubit.oneq_error,qubit.readout_error]):
                raise ValueError('invalid qubit calibration')
        for (a,b),coupler in self.couplers.items():
            if a==b or a not in qubits or b not in qubits or not 0<=coupler.error<1 or not math.isfinite(coupler.duration_us) or coupler.duration_us<=0:
                raise ValueError('invalid coupler calibration')

    @classmethod
    def synthetic(cls,count: int=12,seed: int=19) -> object:
        """synthetic. Complexity: O(g * 4^q + P) time and O(4^q + P) space as an upper bound; g counts gates and P is enumerated layout work."""
        if count not in {8,12}:
            raise ValueError('fixture topology requires 8 or 12 qubits')
        rng = random.Random(seed)
        qubits = {i:QubitCalibration(rng.uniform(80,220),rng.uniform(60,150),rng.uniform(.00015,.00025),rng.uniform(.009,.015)) for i in range(count)}
        edges = [(0,1),(1,2),(2,3),(3,4),(4,5),(2,6),(6,7),(7,8),(8,9),(7,10),(10,11)]
        couplers = {}
        for a,b in edges:
            if max(a,b)<count:
                calibration = CouplerCalibration(rng.uniform(.005,.009))
                couplers[a,b] = calibration
                couplers[b,a] = calibration
        return cls(qubits,couplers,'synthetic heavy-hex region; no physical device measurement')

    @classmethod
    def from_ibm_json(cls,source: object) -> object:
        """from ibm json. Complexity: O(g * 4^q + P) time and O(4^q + P) space as an upper bound; g counts gates and P is enumerated layout work."""
        data = json.loads(Path(source).read_text()) if isinstance(source,(str,Path)) else source
        single,edges = {},{}
        for gate in data['gates']:
            parameters = {p['name']:p for p in gate['parameters']}
            error = float(parameters['gate_error']['value'])
            length = parameters.get('gate_length',{'value':.035 if len(gate['qubits'])==1 else .35,'unit':'us'})
            duration = microseconds(length['value'],length['unit'])
            if len(gate['qubits'])==1 and gate['gate'] in {'x','sx','u3','u'}:
                single[gate['qubits'][0]] = (error,duration)
            elif len(gate['qubits'])==2 and gate['gate'] in {'cx','ecr','cz'}:
                edges[tuple(gate['qubits'])] = CouplerCalibration(error,duration)
        qubits = {}
        for index,properties in enumerate(data['qubits']):
            values = {p['name']:p for p in properties}
            if index not in single:
                raise ValueError('snapshot lacks a measured single-qubit gate error')
            qubits[index] = QubitCalibration(microseconds(values['T1']['value'],values['T1']['unit']),microseconds(values['T2']['value'],values['T2']['unit']),single[index][0],float(values['readout_error']['value']),single[index][1])
        return cls(qubits,edges,'imported IBM BackendProperties: '+data.get('backend_name','unnamed'))

    @property
    def identity(self) -> object:
        """identity. Complexity: O(g * 4^q + P) time and O(4^q + P) space as an upper bound; g counts gates and P is enumerated layout work."""
        return gitoid_sha256(canonical_json({'qubits':{str(q):asdict(value) for q,value in self.qubits.items()},'couplers':{f'{a},{b}':asdict(value) for (a,b),value in self.couplers.items()},'provenance':self.provenance}))

    def with_drift(self,qubit: object,factor: int=15) -> object:
        """with drift. Complexity: O(g * 4^q + P) time and O(4^q + P) space as an upper bound; g counts gates and P is enumerated layout work."""
        if qubit not in self.qubits or not math.isfinite(factor) or factor<=1:
            raise ValueError('invalid drift selection')
        qubits = dict(self.qubits)
        old = qubits[qubit]
        qubits[qubit] = QubitCalibration(old.t1_us,old.t2_us/factor,min(.99,old.oneq_error*factor),min(.99,old.readout_error*factor),old.duration_us)
        edges = {edge:CouplerCalibration(min(.99,value.error*factor) if qubit in edge else value.error,value.duration_us) for edge,value in self.couplers.items()}
        return HardwareCalibrationSnapshot(qubits,edges,self.provenance+f'; modeled q{qubit} drift x{factor}')

    def expected_fidelity(self,circuit: object,layout: object) -> object:
        """expected fidelity. Complexity: O(g * 4^q + P) time and O(4^q + P) space as an upper bound; g counts gates and P is enumerated layout work."""
        if len(layout)!=circuit.qubits or len(set(layout))!=len(layout) or any(q not in self.qubits for q in layout):
            raise ValueError('invalid physical layout')
        mapping = dict(zip(circuit.labels,layout))
        finish = dict.fromkeys(layout,0.0)
        log_score = 0.0
        for gate in circuit.gates:
            physical = tuple(mapping[q] for q in gate.qubits)
            if len(physical)==1:
                calibration = self.qubits[physical[0]]
                error,duration = calibration.oneq_error,calibration.duration_us
            else:
                calibration = self.couplers.get(physical)
                if calibration is None and gate.name in {'cz','swap'}:
                    calibration = self.couplers.get(physical[::-1])
                if calibration is None:
                    return 0.0
                error,duration = calibration.error,calibration.duration_us
            log_score += math.log1p(-error)
            end = max(finish[q] for q in physical)+duration
            for q in physical:
                finish[q] = end
        elapsed = max(finish.values())
        for physical in layout:
            q = self.qubits[physical]
            log_score += math.log1p(-q.readout_error)-elapsed/q.t1_us-elapsed/q.t2_us
        return math.exp(log_score)

    def probe_distribution(self,qubit: object,duration_us: int=10) -> object:
        """probe distribution. Complexity: O(g * 4^q + P) time and O(4^q + P) space as an upper bound; g counts gates and P is enumerated layout work."""
        probability = (1-math.exp(-duration_us/self.qubits[qubit].t2_us))/2
        return [1-probability,probability]
