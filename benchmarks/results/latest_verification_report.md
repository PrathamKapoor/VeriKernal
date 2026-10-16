# VeriKernel execution verification

The following tables summarize executed local verification checks.

| Check | Name | Successful | Seconds |
|---|---|---|---:|
| 1 | workspace | True | 0.006 |
| 2 | identity | True | 0.333 |
| 3 | source | True | 2.769 |
| 4 | rust | True | 142.281 |
| 5 | python | True | 114.475 |
| 6 | cli | True | 37.793 |
| 7 | linux | True | 71.215 |
| 8 | evidence | True | 4.032 |
| 9 | quality | True | 1.637 |
| 10 | release_boundaries | True | 4.860 |
| 11 | lattice_reference | True | 2.557 |
| 12 | confinement | True | 13.670 |

### Verification

I execute 109 Python tests with zero failures, errors or skips, 14 native ARM64 Rust tests and 14 host x64 Rust tests.
All twelve local CI verification checks succeed. Remote matrix execution is reported separately.

| Capability | Observed result |
|---|---|
| Machine-code inspection | Six release arithmetic bodies; no conditional transfers/calls after public guards; aarch64 |
| Independent polynomial oracle | 100 pairs; 25,600 coefficients match schoolbook convolution |
| Exhaustive fault oracle | 20 predicates; 1,024 subsets each; at most 43 ddmin calls |
| SHA-256 / independent tree oracle | 14 block-boundary inputs / eight tree sizes |
| Native kernel resource limits | Child creation and 128 MiB allocation denied; windows-nt-job; signed accounting verified |
| Linux native confinement | qemu-linux; UID 65534; socket/spawn/Landlock EACCES 13/13/13 |
| Source audit | 72 Python files; 18 Rust files; zero package catch-all annotations |
| Distribution | Two identical 178,014-byte wheels; contained offline installation verified |

Release library SHA-256: `7952b9228e37ce8dd10e144f4d719eb1f2fa8a9c8f9a5deca8f8b4f8406b9899`.
Wheel SHA-256: `1a734d9a8d60e3f869e394f1f50b90a76537dbd4141f3f878e31093b628ab5e6`.
Wheel GitOID: `gitoid:blob:sha256:eebdd78da565304b8c132c7f554b877a5132dd787007875f4bc1583f2dff12b1`.

I inspect fixed-schedule arithmetic, not the complete ML-DSA rejection sampler or microarchitectural timing. The selectable native-ring provider uses these primitives in the standard protocol; the maintained native signer remains the default.
Windows Job Objects constrain resources and child count. Linux pre-exec seccomp and Landlock restrict the tested syscall/filesystem capabilities. I retain unrestricted controls, real kernel errors and a signed aggregate accounting receipt; these do not imply universal syscall capture or complete hostile-code isolation.
I retain protected audit-seed, trusted-kernel, immutable executable and external-checkpoint assumptions. Quantum calibration remains modeled. The fixed-source wheel comparison excludes native compiler reproducibility.

Development caches and build artifacts are excluded from version control.

Reproduction: `python scripts/preflight_ci.py`, `python scripts/verify_constant_time_asm.py`, `python scripts/differential_oracles.py`, and `python scripts/verify_native_confinement.py`.

I retain [the verification report](latest_verification_report.md), [29 decisions](../../decisions.md), [the threat model](../../docs/threat-model.md), [the paper](../../docs/paper.md), and [the dashboard](demo_mission_control.html).

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

## Evidence custody

Full decoded bytes are in crypto_disassembly.json; independent seeds/results are in differential_reference.json. Kernel controls and actual accounting are in kernel_confinement.json and native_linux_confinement.json. The signed accounting ledger remains under the reported ignored dist/ path. Bundled signatures establish integrity; identity requires a separately trusted public key.

The benchmark tables record the CLI verification run against the inspected release library. Timing samples are retained without filtering.

## Real kernel accounting

| Attack | Denied | Native result | Peak process bytes | Page faults | User / kernel 100 ns |
|---|---|---|---:|---:|---|
| spawn | True | 1816 | 1568768 | 4347 | 156250 / 0 |
| memory | True | memory allocation failed because the memory allocator returned an error | 1572864 | 4133 | 156250 / 156250 |

Signed aggregate accounting ledger: `dist\preflight\kernel-accounting-8e0165f634c14bf1aa93975cdf6cef83`. Values are observed counters, including unsuccessful process-creation attempts; they are not inferred syscall counts.

## Guest startup correction

An earlier combined run exposed a slow guest startup. I replace its 274 MB development image with a deterministic minimal Python runtime, use 1024 MiB guest RAM and a bounded 240-second cold-boot budget. The final payload image is 19,199,864 bytes; actual console readiness took 5.747 seconds. The complete suite and both kernel checks are repeated after this change.
