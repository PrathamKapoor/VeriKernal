"""Independent finite reference campaigns; O(T*N^2 + P*2^M*M) work."""
from __future__ import annotations
import hashlib
import json
from pathlib import Path
import random
import ssl
import time
from verikernel.m3_fault.ddmin import DeltaDebuggingShrinker
from verikernel.rust_bridge import BatchEngine, LatticeEngine

Q = 8380417
ROOT = Path(__file__).resolve().parents[1]


def schoolbook_negacyclic_mul(a: list[int], b: list[int], q: int = Q) -> list[int]:
    """Multiply by the defining ring relation; O(N^2) time, O(N) space."""
    if len(a) != 256 or len(b) != 256:
        raise ValueError('reference polynomials must contain 256 coefficients')
    result = [0]*256
    for i, left in enumerate(a):
        for j, right in enumerate(b):
            degree = i+j
            result[degree % 256] += left*right*(1 if degree < 256 else -1)
    return [value % q for value in result]


def verify_ntt_reference(trials: int = 100) -> dict[str, object]:
    """Compare native products with direct convolution; O(T*N^2) time, O(N) space."""
    if trials < 1:
        raise ValueError('a positive trial count is required')
    rng, engine = random.Random(310033), LatticeEngine()
    started = time.perf_counter()
    for trial in range(trials):
        a, b = [[rng.randrange(Q) for _ in range(256)] for _ in range(2)]
        actual, expected = engine.multiply(a, b), schoolbook_negacyclic_mul(a, b)
        if actual != expected:
            index = next(i for i in range(256) if actual[i] != expected[i])
            raise AssertionError(f'NTT differential mismatch at trial {trial}, coefficient {index}')
    return {'verified': True, 'pairs': trials, 'coefficients_checked': 256*trials,
            'seed': 310033, 'seconds': time.perf_counter()-started,
            'reference': 'integer schoolbook reduction by X^256 + 1'}


def verify_ddmin_reference(trials: int = 20) -> dict[str, object]:
    """Enumerate complete truth tables and minimal sets; O(T*2^M*M) time and space."""
    if trials < 1:
        raise ValueError('a positive trial count is required')
    rng, cases = random.Random(330010), []
    started = time.perf_counter()
    for _ in range(trials):
        terms = [sum(1 << site for site in rng.sample(range(10), rng.randint(1, 4)))
                 for _ in range(rng.randint(1, 4))]
        truth = [any(mask & term == term for term in terms) for mask in range(1024)]
        minimal = {mask for mask in range(1024) if truth[mask] and
                   all(not truth[mask ^ (1 << bit)] for bit in range(10) if mask & (1 << bit))}
        def oracle(sites: list[int]) -> bool:
            """Query the independent exhaustive truth table; O(M) time, O(1) space."""
            return truth[sum(1 << site for site in sites)]
        shrinker = DeltaDebuggingShrinker(oracle)
        selected = shrinker.shrink(list(range(10)))
        mask = sum(1 << site for site in selected)
        if mask not in minimal or shrinker.evaluations >= 250:
            raise AssertionError('shrinker differs from exhaustive 1-minimal oracle')
        cases.append({'terms': terms, 'minimal_masks': sorted(minimal),
                      'selected_sites': selected, 'oracle_evaluations': shrinker.evaluations})
    return {'verified': True, 'predicates': trials, 'subsets_per_predicate': 1024,
            'max_oracle_evaluations': max(row['oracle_evaluations'] for row in cases),
            'seed': 330010, 'seconds': time.perf_counter()-started, 'cases': cases}


def reference_tree(leaves: list[bytes]) -> bytes:
    """Compute the defining SHA-256 tree without production helpers; O(N log N) work."""
    if not leaves:
        return hashlib.sha256(b'').digest()
    if len(leaves) == 1:
        return hashlib.sha256(b'\x00'+leaves[0]).digest()
    split = 1 << ((len(leaves)-1).bit_length()-1)
    return hashlib.sha256(b'\x01'+reference_tree(leaves[:split])+reference_tree(leaves[split:])).digest()


def verify_hash_reference() -> dict[str, object]:
    """Compare native hash and tree with independent hashlib calls; O(B+N log N) work."""
    rng, engine = random.Random(330256), BatchEngine()
    if not engine.native:
        raise OSError('compiled batch engine is required for differential verification')
    lengths = [0, 1, 55, 56, 63, 64, 65, 127, 128, 129, 511, 512, 1000, 1024]
    for size in lengths:
        data = rng.randbytes(size)
        if engine.sha256(bytearray(data)) != hashlib.sha256(data).digest():
            raise AssertionError(f'SHA-256 differs at length {size}')
    counts = [0, 1, 2, 3, 7, 16, 63, 128]
    for count in counts:
        leaves = [rng.randbytes(128) for _ in range(count)]
        if engine.root(bytearray(b''.join(leaves))) != reference_tree(leaves):
            raise AssertionError(f'Merkle root differs at size {count}')
    return {'verified': True, 'hash_cases': len(lengths), 'lengths': lengths,
            'tree_cases': len(counts), 'tree_sizes': counts,
            'hashlib_provider': type(hashlib.sha256()).__module__, 'openssl': ssl.OPENSSL_VERSION}


def run_differential_verification(output: Path | None = None) -> dict[str, object]:
    """Run and optionally persist independent campaigns; O(T*N^2+P*2^M*M) work."""
    report = {'ntt': verify_ntt_reference(), 'ddmin': verify_ddmin_reference(),
              'hash': verify_hash_reference(), 'verified': True}
    if output is not None:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(report, indent=2), encoding='utf-8')
    return report


if __name__ == '__main__':
    print(json.dumps(run_differential_verification(ROOT/'benchmarks/results/differential_reference.json'), indent=2))
