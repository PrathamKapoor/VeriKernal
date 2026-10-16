"""Circuit contract."""
from __future__ import annotations
import cmath
import math
from verikernel.m1_contract.compiler import canonical_json
from verikernel.omnibor import gitoid_sha256


class CircuitContract:
    """CircuitContract. Complexity: O(g * 4^q + P) time and O(4^q + P) space as an upper bound; g counts gates and P is enumerated layout work."""
    def __init__(self, qubits: int, gates: object, transpiler_seed: int=0, layout: object=None) -> None:
        """init. Complexity: O(g * 4^q + P) time and O(4^q + P) space as an upper bound; g counts gates and P is enumerated layout work."""
        if not 1 <= qubits <= 8:
            raise ValueError("exact circuit verification supports 1 through 8 qubits")
        self.qubits, self.gates, self.seed = qubits, list(gates), transpiler_seed
        self.layout = list(range(qubits)) if layout is None else list(layout)
        if sorted(self.layout) != list(range(qubits)):
            raise ValueError("layout must be a qubit permutation")
        for gate in self.gates:
            if gate[0] not in {"H", "X", "Y", "Z", "S", "T", "RX", "RY", "RZ", "CX"}:
                raise ValueError("unsupported gate")
            required = 3 if gate[0] in {"RX", "RY", "RZ", "CX"} else 2
            if len(gate) != required or not 0 <= gate[1] < qubits:
                raise ValueError("invalid gate operands")
            if gate[0] == "CX" and (not 0 <= gate[2] < qubits or gate[1] == gate[2]):
                raise ValueError("invalid controlled gate")

    @property
    def identity(self) -> object:
        """identity. Complexity: O(g * 4^q + P) time and O(4^q + P) space as an upper bound; g counts gates and P is enumerated layout work."""
        return gitoid_sha256(canonical_json({"qubits": self.qubits, "gates": self.gates, "seed": self.seed, "layout": self.layout}))

    def state(self, basis: int=0) -> object:
        """state. Complexity: O(g * 4^q + P) time and O(4^q + P) space as an upper bound; g counts gates and P is enumerated layout work."""
        state = [0j] * (1 << self.qubits)
        state[basis] = 1
        for gate in self.gates:
            name, logical = gate[:2]
            bit = 1 << self.layout[logical]
            if name == "CX":
                target = 1 << self.layout[gate[2]]
                for i in range(len(state)):
                    if i & bit and not i & target:
                        state[i], state[i | target] = state[i | target], state[i]
                continue
            if name == "H":
                matrix = (1/math.sqrt(2), 1/math.sqrt(2), 1/math.sqrt(2), -1/math.sqrt(2))
            elif name == "X":
                matrix = (0, 1, 1, 0)
            elif name == "Y":
                matrix = (0, -1j, 1j, 0)
            elif name in {"Z", "S", "T"}:
                matrix = (1, 0, 0, {"Z": -1, "S": 1j, "T": cmath.exp(1j*math.pi/4)}[name])
            else:
                angle = float(gate[2])
                if not math.isfinite(angle):
                    raise ValueError("rotation must be finite")
                c, s = math.cos(angle/2), math.sin(angle/2)
                matrix = (c, -1j*s, -1j*s, c) if name == "RX" else (c, -s, s, c) if name == "RY" else (cmath.exp(-1j*angle/2), 0, 0, cmath.exp(1j*angle/2))
            a, b, c, d = matrix
            for i in range(len(state)):
                if not i & bit:
                    x, y = state[i], state[i | bit]
                    state[i], state[i | bit] = a*x+b*y, c*x+d*y
        return state

    def equivalent(self, other: object, tolerance: float=1e-9, observable: object=None) -> bool:
        """equivalent. Complexity: O(g * 4^q + P) time and O(4^q + P) space as an upper bound; g counts gates and P is enumerated layout work."""
        if self.qubits != other.qubits:
            return False
        dimension = 1 << self.qubits
        if observable is not None:
            if len(observable) != dimension:
                raise ValueError("observable diagonal has wrong dimension")
            left = [self.state(i) for i in range(dimension)]
            right = [other.state(i) for i in range(dimension)]
            for i in range(dimension):
                for j in range(dimension):
                    a = sum(left[i][k].conjugate()*observable[k]*left[j][k] for k in range(dimension))
                    b = sum(right[i][k].conjugate()*observable[k]*right[j][k] for k in range(dimension))
                    if abs(a-b) > tolerance:
                        return False
            return True
        phase = None
        for basis in range(dimension):
            a, b = self.state(basis), other.state(basis)
            for x, y in zip(a, b):
                if phase is None:
                    if abs(y) <= tolerance:
                        if abs(x) > tolerance:
                            return False
                        continue
                    phase = x/y
                    if abs(abs(phase)-1) > tolerance:
                        return False
                if abs(x-phase*y) > tolerance:
                    return False
        return True
