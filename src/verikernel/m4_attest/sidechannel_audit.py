"""Randomly interleaved timing evidence; O(n) samples and O(n) measurement storage."""
from __future__ import annotations
import math
import random
import statistics
import time
from typing import Callable
from verikernel.schemas import KernelTelemetryEvent
from .ratchet import ForwardSecureRatchet,verify_ratchet_chain
from .merkle_tiles import mth,prove_inclusion,verify_inclusion
from .pqc_signer import MLDSA65Signer


def welch_statistic(first: list[float], second: list[float]) -> float:
    """Welch's unequal-variance statistic; O(n) time and O(1) workspace."""
    if min(len(first),len(second))<2:
        raise ValueError('two samples per class are required')
    variance = statistics.variance(first)/len(first)+statistics.variance(second)/len(second)
    difference = statistics.mean(first)-statistics.mean(second)
    if variance==0:
        return 0.0 if difference==0 else math.copysign(1e300,difference)
    return difference/math.sqrt(variance)


def run_welch_t_test_audit(num_samples: int = 2000) -> dict[str,object]:
    """Measure first/last corruption classes, O(n) calls and storage.

    Public malformed encodings may take different paths. A low statistic is
    finite evidence, never certification of secret-independent execution.
    """
    if num_samples<2:
        raise ValueError('at least two samples per class are required')
    seed = bytes([66])*32
    ratchet = ForwardSecureRatchet(seed)
    events = [KernelTelemetryEvent(seq_no=i) for i in range(3)]
    for event in events:
        ratchet.tag(event)
    altered = []
    for offset in [0,31]:
        copied = [KernelTelemetryEvent.from_bytes(e.to_bytes()) for e in events]
        tag = bytearray(copied[0].ratchet_tag); tag[offset]^=1; copied[0].ratchet_tag=bytes(tag)
        altered.append(copied)
    leaves = [event.to_bytes() for event in events]
    root = mth(leaves)
    proof = prove_inclusion(0,leaves)
    proofs = []
    for offset in [0,31]:
        changed = list(proof)
        node = bytearray(changed[0]); node[offset]^=1; changed[0]=bytes(node)
        proofs.append(changed)
    signer = MLDSA65Signer(seed=bytes([153])*32)
    message = b'VeriKernel timing evidence'
    signature = signer.sign(message)
    signatures = []
    for offset in [0,3308]:
        changed = bytearray(signature); changed[offset]^=1; signatures.append(bytes(changed))
    paths: dict[str,Callable[[int],bool]] = {
        'ratchet_tag':lambda group:verify_ratchet_chain(altered[group],seed,ratchet.commitment,ratchet.terminal),
        'merkle_proof':lambda group:verify_inclusion(leaves[0],0,len(leaves),proofs[group],root),
        'ml_dsa_signature':lambda group:MLDSA65Signer.verify(signer.public_key,message,signatures[group])}
    rows: dict[str,object] = {}
    rng = random.Random(20261015)
    for name,function in paths.items():
        for _ in range(40):
            function(0); function(1)
        order = [0,1]*num_samples
        rng.shuffle(order)
        samples: list[list[float]] = [[],[]]
        rejected = True
        for group in order:
            start = time.perf_counter_ns()
            accepted = function(group)
            elapsed = time.perf_counter_ns()-start
            samples[group].append(float(elapsed))
            rejected &= not accepted
        statistic = welch_statistic(samples[0],samples[1])
        rows[name] = {'t_statistic':statistic,'threshold':4.5,'below_threshold':abs(statistic)<4.5,'mean_first_ns':statistics.mean(samples[0]),'mean_last_ns':statistics.mean(samples[1]),'all_rejected':rejected,'interpretation':'public-encoding paths can differ; no secret-leak conclusion from this classification' if name=='ml_dsa_signature' else 'finite first/last corruption timing evidence'}
    return {'samples_per_class':num_samples,'randomized_interleaving':True,'paths':rows,'all_below_threshold':all(row['below_threshold'] for row in rows.values()),'constant_time_certification':False,'scope':'end-to-end first-byte versus last-byte corruption; unfiltered observations, no resampling to obtain acceptance'}
