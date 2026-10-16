"""Qasm parser."""
from __future__ import annotations
import ast
import math
import operator
import re
from dataclasses import dataclass
import numpy as np


def angle_value(expression: object) -> object:
    """angle value. Complexity: O(g * 4^q + P) time and O(4^q + P) space as an upper bound; g counts gates and P is enumerated layout work."""
    operations = {ast.Add:operator.add,ast.Sub:operator.sub,ast.Mult:operator.mul,ast.Div:operator.truediv}
    def visit(node: object) -> object:
        """visit. Complexity: O(g * 4^q + P) time and O(4^q + P) space as an upper bound; g counts gates and P is enumerated layout work."""
        if isinstance(node,ast.Constant) and type(node.value) in {int,float}:
            return float(node.value)
        if isinstance(node,ast.Name) and node.id in {'pi','tau'}:
            return getattr(math,node.id)
        if isinstance(node,ast.UnaryOp) and isinstance(node.op,(ast.UAdd,ast.USub)):
            return visit(node.operand)*(1 if isinstance(node.op,ast.UAdd) else -1)
        if isinstance(node,ast.BinOp) and type(node.op) in operations:
            return operations[type(node.op)](visit(node.left),visit(node.right))
        raise ValueError('unsupported rotation expression')
    try:
        result = visit(ast.parse(expression,mode='eval').body)
        if not math.isfinite(result):
            raise ValueError('nonfinite rotation')
        return result
    except (SyntaxError,ZeroDivisionError,OverflowError,RecursionError) as error:
        raise ValueError('invalid rotation') from error


@dataclass(frozen=True)
class Gate:
    """Gate. Complexity: O(g * 4^q + P) time and O(4^q + P) space as an upper bound; g counts gates and P is enumerated layout work."""
    name: str
    qubits: tuple
    angle: float | None = None


class QuantumCircuitDAG:
    """QuantumCircuitDAG. Complexity: O(g * 4^q + P) time and O(4^q + P) space as an upper bound; g counts gates and P is enumerated layout work."""
    def __init__(self,qubits: int,gates: object,measurements: object=(),labels: object=None,classical_bits: int=0) -> None:
        """init. Complexity: O(g * 4^q + P) time and O(4^q + P) space as an upper bound; g counts gates and P is enumerated layout work."""
        if type(qubits) is not int or not 1 <= qubits <= 8:
            raise ValueError('exact dense verification supports 1 through 8 active qubits')
        self.qubits = qubits
        self.labels = tuple(range(qubits)) if labels is None else tuple(labels)
        if len(self.labels)!=qubits or len(set(self.labels))!=qubits or any(type(q) is not int or q<0 for q in self.labels):
            raise ValueError('invalid active wire labels')
        self.gates = tuple(gates)
        self.measurements = tuple(tuple(pair) for pair in measurements)
        self.classical_bits = classical_bits
        for gate in self.gates:
            arity = 2 if gate.name in {'cx','cz','swap'} else 1
            if gate.name not in {'id','h','x','y','z','s','t','rx','ry','rz','cx','cz','swap'} or len(gate.qubits)!=arity or len(set(gate.qubits))!=arity or any(q not in self.labels for q in gate.qubits):
                raise ValueError('invalid gate')
            if gate.name in {'rx','ry','rz'}:
                if gate.angle is None or not math.isfinite(gate.angle):
                    raise ValueError('rotation requires a finite angle')
            elif gate.angle is not None:
                raise ValueError('unexpected gate parameter')
        if any(q not in self.labels or not 0<=bit<classical_bits for q,bit in self.measurements):
            raise ValueError('invalid measurement assignment')

    @property
    def edges(self) -> object:
        """edges. Complexity: O(g * 4^q + P) time and O(4^q + P) space as an upper bound; g counts gates and P is enumerated layout work."""
        last, edges = {}, set()
        for index,gate in enumerate(self.gates):
            for qubit in gate.qubits:
                if qubit in last:
                    edges.add((last[qubit],index))
                last[qubit] = index
        return tuple(sorted(edges))

    def remap(self,layout: object) -> object:
        """remap. Complexity: O(g * 4^q + P) time and O(4^q + P) space as an upper bound; g counts gates and P is enumerated layout work."""
        if len(layout)!=self.qubits or len(set(layout))!=self.qubits:
            raise ValueError('layout must be injective')
        mapping = dict(zip(self.labels,layout))
        return QuantumCircuitDAG(self.qubits,[Gate(g.name,tuple(mapping[q] for q in g.qubits),g.angle) for g in self.gates],[(mapping[q],b) for q,b in self.measurements],layout,self.classical_bits)

    def to_unitary(self) -> object:
        """to unitary. Complexity: O(g * 4^q + P) time and O(4^q + P) space as an upper bound; g counts gates and P is enumerated layout work."""
        dimension = 1<<self.qubits
        result = np.eye(dimension,dtype=np.complex128)
        ranks = {label:index for index,label in enumerate(sorted(self.labels))}
        for gate in self.gates:
            name = gate.name
            bit = 1<<ranks[gate.qubits[0]]
            if len(gate.qubits)==2:
                target = 1<<ranks[gate.qubits[1]]
                for row in range(dimension):
                    if name=='cz' and row&bit and row&target:
                        result[row] *= -1
                    elif name=='cx' and row&bit and not row&target:
                        result[[row,row|target]] = result[[row|target,row]]
                    elif name=='swap' and row&bit and not row&target:
                        other = row ^ bit ^ target
                        result[[row,other]] = result[[other,row]]
                continue
            if name in {'rx','ry','rz'}:
                c,s = math.cos(gate.angle/2),math.sin(gate.angle/2)
                matrix = ((c,-1j*s),(-1j*s,c)) if name=='rx' else ((c,-s),(s,c)) if name=='ry' else ((np.exp(-.5j*gate.angle),0),(0,np.exp(.5j*gate.angle)))
            else:
                matrix = {'id':((1,0),(0,1)),'h':((2**-.5,2**-.5),(2**-.5,-2**-.5)),'x':((0,1),(1,0)),'y':((0,-1j),(1j,0)),'z':((1,0),(0,-1)),'s':((1,0),(0,1j)),'t':((1,0),(0,np.exp(.25j*math.pi)))}[name]
            for row in range(dimension):
                if not row&bit:
                    a,b = result[row].copy(),result[row|bit].copy()
                    result[row] = matrix[0][0]*a+matrix[0][1]*b
                    result[row|bit] = matrix[1][0]*a+matrix[1][1]*b
        return result

    def to_qasm3(self) -> object:
        """to qasm3. Complexity: O(g * 4^q + P) time and O(4^q + P) space as an upper bound; g counts gates and P is enumerated layout work."""
        ranks = {label:index for index,label in enumerate(self.labels)}
        lines = ['OPENQASM 3.0;','include "stdgates.inc";',f'qubit[{self.qubits}] q;']
        if self.classical_bits:
            lines.append(f'bit[{self.classical_bits}] c;')
        for gate in self.gates:
            parameter = '' if gate.angle is None else '('+repr(gate.angle)+')'
            lines.append(gate.name+parameter+' '+','.join(f'q[{ranks[q]}]' for q in gate.qubits)+';')
        lines.extend(f'c[{bit}] = measure q[{ranks[q]}];' for q,bit in self.measurements)
        return '\n'.join(lines)+'\n'


def parse_qasm(source: object) -> object:
    """parse qasm. Complexity: O(g * 4^q + P) time and O(4^q + P) space as an upper bound; g counts gates and P is enumerated layout work."""
    source = re.sub(r'/\*.*?\*/|//[^\n]*','',source,flags=re.S)
    if not re.fullmatch(r'\s*OPENQASM\s+(?:2\.0|3\.0)\s*;.*',source,flags=re.S):
        raise ValueError('OpenQASM version header required')
    if not source.rstrip().endswith(';'):
        raise ValueError('unterminated statement')
    quantum,classical,gates,measurements = {},{},[],[]
    qcount,bcount = 0,0
    def operands(text: object,registers: object) -> object:
        """operands. Complexity: O(g * 4^q + P) time and O(4^q + P) space as an upper bound; g counts gates and P is enumerated layout work."""
        match = re.fullmatch(r'([A-Za-z_]\w*)(?:\[(\d+)\])?',text.strip())
        if not match or match[1] not in registers:
            raise ValueError('unknown register operand')
        offset,size = registers[match[1]]
        if match[2] is None:
            return list(range(offset,offset+size))
        index = int(match[2])
        if index>=size:
            raise ValueError('register index out of range')
        return [offset+index]
    for statement in source.split(';')[1:-1]:
        statement = statement.strip()
        if re.fullmatch(r'include\s+"(?:stdgates|qelib1)\.inc"',statement):
            continue
        declaration = re.fullmatch(r'(qreg|creg)\s+(\w+)\[(\d+)\]',statement)
        modern = re.fullmatch(r'(qubit|bit)(?:\[(\d+)\])?\s+(\w+)',statement)
        if declaration or modern:
            kind,name,size = (declaration[1],declaration[2],int(declaration[3])) if declaration else (modern[1],modern[3],int(modern[2] or 1))
            if size<1 or name in quantum or name in classical:
                raise ValueError('invalid or duplicated declaration')
            if kind in {'qreg','qubit'}:
                quantum[name] = (qcount,size)
                qcount += size
            else:
                classical[name] = (bcount,size)
                bcount += size
            continue
        measurement = re.fullmatch(r'measure\s+(.+?)\s*->\s*(.+)',statement)
        assignment = re.fullmatch(r'(.+?)\s*=\s*measure\s+(.+)',statement)
        if measurement or assignment:
            q,b = (measurement[1],measurement[2]) if measurement else (assignment[2],assignment[1])
            qbits,cbits = operands(q,quantum),operands(b,classical)
            if len(qbits)!=len(cbits):
                raise ValueError('measurement widths differ')
            measurements.extend(zip(qbits,cbits))
            continue
        if measurements:
            raise ValueError('only terminal measurements have a coherent-prefix unitary')
        gate = re.fullmatch(r'([a-z]+)(?:\((.+)\))?\s+(.+)',statement)
        if not gate:
            raise ValueError('unsupported OpenQASM statement')
        groups = [operands(item,quantum) for item in gate[3].split(',')]
        if len({len(group) for group in groups})!=1:
            raise ValueError('gate broadcast widths differ')
        parameter = angle_value(gate[2]) if gate[2] is not None else None
        gates.extend(Gate(gate[1],tuple(group[index] for group in groups),parameter) for index in range(len(groups[0])))
    return QuantumCircuitDAG(qcount,gates,measurements,classical_bits=bcount)


def basis_permutation(labels: object) -> object:
    """basis permutation. Complexity: O(g * 4^q + P) time and O(4^q + P) space as an upper bound; g counts gates and P is enumerated layout work."""
    labels = tuple(labels)
    ranks = {label:index for index,label in enumerate(sorted(labels))}
    matrix = np.zeros((1<<len(labels),1<<len(labels)),dtype=np.complex128)
    for logical in range(len(matrix)):
        physical = sum(((logical>>index)&1)<<ranks[label] for index,label in enumerate(labels))
        matrix[physical,logical] = 1
    return matrix


def unitary_fidelity(original: object,remapped: object) -> object:
    """unitary fidelity. Complexity: O(g * 4^q + P) time and O(4^q + P) space as an upper bound; g counts gates and P is enumerated layout work."""
    if original.qubits!=remapped.qubits:
        raise ValueError('unitary dimensions differ')
    a,b = original.to_unitary(),remapped.to_unitary()
    left,right = basis_permutation(original.labels),basis_permutation(remapped.labels)
    overlap = np.trace((left.conj().T@a@left).conj().T @ right.conj().T@b@right)
    return float(min(1.0,abs(overlap)/len(a)))
