# VeriKernel measured benchmark report

Runtime: {'python': '3.13.15', 'platform': 'Windows-11-10.0.26100-SP0', 'machine': 'ARM64', 'interpreter_platform': 'win-arm64', 'signing_backend': 'fips204-rust-native', 'windows_arm64_x64_emulation': False}

I measured controlled fixtures, without executing external comparison tools.
I do not infer kernel throughput, atomic path mediation, or bounded-memory zero loss from this run.

| Transport | Drops (%) | Inversions | p50 (us) | p99 (us) | Input events/s |
|---|---:|---:|---:|---:|---:|
| bounded_per_cpu | 97.44 | 3 | 0.400 | 0.500 | 558250.7 |
| portable_two_level | 0.00 | 0 | 1.000 | 8.200 | 56911.7 |

| Attestation | Signature bytes | Signing CPU ms | Proof bytes | Proof construction + verification ms |
|---|---:|---:|---:|---:|
| per_event | 33090000 | 9031.250 | 0 | 9.700 |
| microbatch_128 | 261411 | 78.125 | 224 | 12.828 |
| epoch_65536 | 3309 | 15.625 | 448 | 130.835 |

| Detection fixture | Precision | Recall | F1 |
|---|---:|---:|---:|
| static_import_only | 1.000 | 0.235 | 0.381 |
| raw_trace_fixture | 0.917 | 0.647 | 0.759 |
| portable_hybrid | 1.000 | 0.941 | 0.970 |

I reduced 32 faults to 2 sites [7, 23] in 30 oracle evaluations.
Reduction: 93.75%; replay: 100.00% across 20 runs.
The controlled double-rerun fixture reproduced both failures in 0.00% of trials.

The v0.2 transport uses the bounded native lock-free FIFO when built, with synchronized per-CPU staging and contiguous sequence release. The signing consumer seals asynchronous periodic epochs.
The attestation scaling experiment signs its 10,000-event tree once; the 65,536-fold figure is arithmetic for a full epoch, not this run.
Detection includes a real directory symlink or junction and a child-process false negative; no concurrent symlink swap is claimed.

Native Rust library loaded: True.
The 1,024-byte FNV-1a comparison measured 44.795x speedup across 20000 calls, including ctypes overhead.


## Batch SHA-256 and chained ledger

| Engine | Seal events/s | Verify events/s | Merkle events/s | Dedup events/s |
|---|---:|---:|---:|---:|
| python | 161428.6 | 186676.5 | 171924.1 | 1025294.0 |
| native | 255838.2 | 260376.0 | 277848.0 | 9247272.1 |

I verify 4 chained epochs and 10,000 cumulative leaves in median 372.822 ms. The last consistency proof occupies 416 bytes.

| Timing path | Welch t | Below 4.5 | Rejected both classes |
|---|---:|---|---|
| ratchet_tag | -0.148422 | True | True |
| merkle_proof | 1.013594 | True | True |
| ml_dsa_signature | -0.283134 | True | True |

I retain unfiltered first/last corruption measurements with 2,000 observations per class. These are finite timing observations, not constant-time certification.


## Native target and distribution verification

Compiled comparator architecture: aarch64; branch-free body instructions: 132.
Real native workload: 5 events in 150.048 ms; strict undeclared-file denial: True.
Native ENOSPC minimal site: [2]; oracle evaluations: 6.
Normalized wheel equality: True; clean offline installation: True.
Native telemetry uses the trusted linked adapter. The instruction finding applies only to the inspected comparator body.


## Fixed-schedule lattice arithmetic and kernel resource limits

| Exported arithmetic body | Decoded instructions | Conditional branches |
|---|---:|---:|
| vk_constant_time_compare_32 | 132 | 0 |
| vk_montgomery_reduce_ct | 8 | 0 |
| vk_caddq_ct | 5 | 0 |
| vk_ntt_256_ct | 11991 | 0 |
| vk_inv_ntt_256_ct | 20066 | 0 |
| vk_poly_chknorm_ct | 876 | 0 |

Independent convolution: 100 pairs, 25600 coefficients.
Exhaustive fault predicates: 20; 1,024 subsets each; maximum ddmin oracle calls 43.
SHA-256 boundary cases: 14; independent tree cases: 8.
Kernel resource backend: windows-nt-job; child creation denied: True; 128 MiB allocation denied: True.
Unrestricted controls execute the child and touch the full allocation. The aggregate kernel accounting payload is bound to a signed ledger leaf.
The instruction audit covers six fixed-schedule arithmetic bodies, not the complete signature protocol or microarchitectural timing.
