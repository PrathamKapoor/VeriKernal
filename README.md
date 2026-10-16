# VeriKernel

![License: MIT](https://img.shields.io/badge/license-MIT-blue)
![Python: 3.12+](https://img.shields.io/badge/python-3.12%2B-blue)
![Runtime: Windows and Linux](https://img.shields.io/badge/runtime-Windows_and_Linux-blue)

I combine executable dependency contracts, portable execution auditing, deterministic boundary faults,
counterexample reduction, post-quantum execution receipts, and a quantum uncertainty policy.
I bind 128-byte telemetry records to a forward-evolving key chain, an RFC 9162-shaped Merkle tree,
and an ML-DSA-65 signature over a DSSE in-toto statement.

I implemented the portable workflows and measured the fixtures below on Windows 11 ARM64.
I also verified the baseline Python suite under Windows x64 emulation; current target scope is recorded below.
I build and test the Rust core on Windows ARM64 and x64, and cross-build Linux ARM64 artifacts.
I execute Linux tests in a contained QEMU guest with a real kernel.
The Linux backend activates rust-landlock filesystem restrictions and seccomp user notifications.
The separate aya loader seeds per-CPU cryptographic ratchets, attaches CO-RE probes, and reports losses.
I keep kernel capture and portable replay as explicit backend choices with distinct coverage.

Author: Pratham Kapoor <prathamkapoor027@gmail.com>

[Source repository](https://github.com/PrathamKapoor/VeriKernal) | Python package: `verikernel`

## Overview

I expose eleven commands: `compile`, `trace`, `enforce`, `fault`, `shrink`, `verify`, `quantum-audit`, `bench`, `demo`, `ui`, and `inspect`.
The compiler recognizes Python imports and literal operations, ELF dynamic imports, PE import directories,
environment keys, declared distribution aliases, and Git blob identities.
The portable interceptor observes supported Python audit events and wraps regular-file I/O, clocks,
and environment reads during a session. It also observes participating worker threads.
The fault engine persists stack/operation/ordinal identities and refuses a mismatched scheduled site.
The shrinker minimizes a reproduced failure through an explicit predicate and subset memoization.
The verifier checks framing, signatures, signed manifest equality, event count, Merkle root,
ratchet commitments, and optional inclusion proofs.

I prefer the native Rust `fips204` ML-DSA-65 implementation and retain the maintained `dilithium-py` standard implementation as a portable fallback. The optional oqs provider uses ML-DSA-65 when installed.
The optional `pqcrypto` provider accelerates randomized benchmark signatures with the same key encoding.
I also expose an explicit `native-ring` provider that runs the standard ML-DSA protocol with the new compiled fixed-schedule NTT, inverse, pointwise and norm operations. It matches deterministic standard signatures; selecting it does not change the default provider.
The signer uses the standard ML-DSA-65 challenge and encoding parameters.
I have not obtained a cryptographic implementation certification or established constant-time Python execution.

## Core Problem: OS-Boundary Verification vs. Runtime Overhead

An import statement describes one language boundary. A native extension can load a DLL or shared object,
launch a child, read an environment variable, or contact a service without adding another Python import.
I combine source declarations and executable imports with observations, while keeping their coverage visible.
The portable backend cannot see arbitrary native-extension syscalls or a child's internal operations.
Its 20-case benchmark deliberately includes that child-process false negative.

Instruction replay additionally needs scheduling, memory, randomness, and clock control.
A deterministic fault schedule alone does not reproduce all those conditions.
I reject a replay site that has changed its operation, stack hash, or ordinal.
The current bundle binds the source bytes and contract; it does not snapshot the whole filesystem.
Workloads used for shrinking must restore their own mutable state between oracle evaluations.

Per-event post-quantum signing also competes with the event consumer.
I measured 33,090,000 signature bytes for 10,000 events,
compared with 3,309 bytes for one epoch signature.
A ratchet detects altered or missing events against a previously sealed terminal state.
It cannot prove an unsealed tail existed if an adversary can replace the entire sealing process.

## Architectural Trade-offs

I retain operation-boundary fault schedules instead of instruction-level single-core replay.
This supports portable experiments without rewriting a workload around a special scheduler.
I sacrifice control over native instructions, thread interleavings, child internals, and aliases captured
before a wrapper is installed. Python audit hooks are observations and policy checks within a trusted process.
They do not form a security boundary against malicious native code.

I amortize signatures over Merkle roots and authenticate each recorded event with a cryptographic ratchet.
The mutable key storage is overwritten at each step; immutable Python temporaries may retain copies.
The producer and signing code currently share an address space. I do not claim protected key custody.
CLI execution seals periodic epochs every 65,536 events or 100 ms, then flushes the final epoch. A signing worker verifies producer tags, signs cumulative roots, and links checkpoints with consistency proofs and the previous envelope digest. The deadline bounds idle seal scheduling, not signing completion under overload.

I use synchronized per-CPU staging followed by a bounded Rust crossbeam MPMC FIFO.
The native shared queue is lock-free; Python staging, ratchet admission and deduplication use synchronization.
Streaming drains retain later events until earlier sequence numbers or explicit deduplication skips arrive.
The asynchronous attestor applies backpressure if its native queue fills.
The standalone staging transport raises a capacity error rather than silently dropping accepted events.
A working SimpleQueue fallback reports that its transport is portable instead of native lock-free.
I publish both local integrity-framed tiles and headerless C2SP/Tessera tile paths atomically.
The BLAKE3 profile needs compatible readers; it is not the default SHA256 Tessera checkpoint protocol.

## Engineering Post-Mortem: What Broke in v0.1

I preserve a deliberately bounded per-CPU transport fixture to reproduce overflow and CPU-order draining.
For the measured burst it dropped 97.44% of inputs and produced 3 inversions.
The portable transport delivered its accepted events with 0.00% observed capacity drops
and 0 inversions in the ordered stream. It suppressed 8,499 repeated events.
Suppressed events are counted separately from drops and are not authenticated individually by that fixture.
I do not present these controlled fixtures as historical production incidents.

The raw path fixture trusts a string prefix and rejects normalized parent components indiscriminately.
A real directory junction on Windows, or directory symlink on Linux, demonstrates the prefix error.
Canonical path checks resolve that static case. Runtime regular-file reads resolve the retained OS handle.
The pre-open policy still has a race and may run before a destructive open mode takes effect.
I do not claim atomic VFS mediation or protection from a concurrent path swap.

The baseline consumer signs 128-event batches synchronously.
The improved burst fixture drains concurrently and seals through the asynchronous epoch service.
The separate scaling experiment compares actual per-event, microbatch and single-root signature workloads.

## Benchmarks & Empirical Evaluation


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


### Batch SHA-256 and chained ledger

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


### Native target and distribution verification

Compiled comparator architecture: aarch64; branch-free body instructions: 132.
Real native workload: 5 events in 150.048 ms; strict undeclared-file denial: True.
Native ENOSPC minimal site: [2]; oracle evaluations: 6.
Normalized wheel equality: True; clean offline installation: True.
Native telemetry uses the trusted linked adapter. The instruction finding applies only to the inspected comparator body.


### Fixed-schedule lattice arithmetic and kernel resource limits

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

## Technology Choices & Rationale

| Choice | Reason | Current implementation boundary |
|---|---|---|
| Rust schema and core | Explicit wire layout, cryptographic core, reusable typed interfaces | Native builds and unit tests on Windows ARM64 and x64; Linux ARM64 execution checks |
| Python 3.12+ | AST, TOML, packaging, portable audit hooks and orchestration | Verified here with Python 3.13 |
| Linux CO-RE and aya direction | Native VFS observation can bind resolved objects | aya loader, CO-RE compilation, per-CPU seed provisioning and authenticated capture verification |
| BPF_MAP_TYPE_RINGBUF | One shared reservation channel can reduce CPU-order merging errors | Finite kernel capacity can fail reservations |
| Landlock and seccomp notification | Unprivileged filesystem confinement and supervised syscall decisions | Real ruleset activation and seccomp supervisor; declared-file allow/deny verified as root and UID 65534 |
| PEP 578 and reversible wrappers | Portable observations and reproducible Python boundary faults | Native syscalls, captured aliases and child internals remain outside coverage |
| Inode LRU | Constant-time Python cache lookup and mtime-sensitive invalidation | Deduplication deliberately omits repeated observations |
| BLAKE3 and RFC 9162 construction | Fast hashing, domain separation, uneven-tree proofs | Custom hash profile, without Certificate Transparency interoperability |
| Content-addressed static tiles | Inspectable bounded artifacts with body integrity | Local framing plus C2SP hierarchy, 256-hash tiles, partial suffixes and immutable atomic publication |
| OmniBOR GitOIDs | Canonical Git blob framing for file and input-manifest identity | Identity alone does not authenticate a publisher |
| ML-DSA-65 | Standard post-quantum signature encoding, 1,952-byte public keys and 3,309-byte signatures | Native Rust, optional oqs/pqcrypto and standard Python fallback; no universal latency guarantee |
| Expanded Rust NTT and norm check | Fixed coefficient-independent arithmetic schedules and standard Montgomery conventions | Six decoded release bodies checked; optional native-ring protocol provider; rejection sampling and other providers excluded |
| Windows Job Objects | Kernel-enforced active-process and committed-memory limits before first target instruction | Suspended assignment and explicit inherited handles; resource limits do not enforce arbitrary filesystem/network policy |
| Linux pre-exec confinement | No-new-privileges, ABI-checked syscall denials and Landlock before native exec | Actual uncooperative ELF targets in a real guest; specific rights and syscall coverage |
| Independent differential oracles | Detect shared round-trip errors and nonminimal fault schedules | Exact schoolbook products, exhaustive ten-site truth tables and separate hashlib tree definitions |
| DSSE and in-toto | Binds payload type, execution context, roots and counts | Identity requires a separately pinned public key |
| Zeller ddmin | Explicit 1-minimal failure schedules with memoized oracle runs | Worst-case quadratic; no universal logarithmic oracle bound |
| Quantum uncertainty decomposition | Separates model disagreement, shot variance and calibration drift | Policy evidence and small dense circuits, not hardware certification |

I chose integer-based ML-DSA arithmetic instead of implementing floating-point lattice sampling.
I retain a standard implementation instead of inventing size-compatible cryptography.
Ed25519 does not provide the requested post-quantum primitive; SLH-DSA and Falcon have different
signature size, performance, and implementation trade-offs requiring separate evaluation.

## Repository Layout

| Path | Contents |
|---|---|
| `crates/` | Telemetry schema, native execution core, test workload and confinement launcher |
| `src/verikernel/` | Contract compiler, interceptors, fault replay, attestations and quantum policy |
| `tests/` | Unit, differential, invariant and end-to-end verification |
| `examples/` | Native dependency, transactional journal and circuit rerouting case studies |
| `scripts/` | Build, packaging, source audit and kernel verification tools |
| `benchmarks/` | Reproducible experiments and measured results |
| `docs/` | Architecture defense, demo guide, threat model and research paper |

## Quickstart & CLI Usage

I keep development artifacts under the repository root. In PowerShell:

```powershell
Set-Location C:\Pratham\VeriKernel
. ./scripts/env.ps1
$env:TEMP = "$PWD\.tmp"
$env:TMP = $env:TEMP
$env:TMPDIR = $env:TEMP
$env:PYTHONDONTWRITEBYTECODE = "1"
$env:PIP_CACHE_DIR = "$PWD\.tmp\pip-cache"
New-Item -ItemType Directory -Force .tmp | Out-Null
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e '.[test]'
.\.venv\Scripts\python.exe scripts/build_native.py
.\.venv\Scripts\python.exe -m pytest -v
.\.venv\Scripts\python.exe -c "from pathlib import Path; p=Path('.tmp/data.txt').resolve(); p.write_text('checkpoint'); Path('.tmp/workload.py').write_text('with open('+repr(str(p))+') as stream:\n    print(stream.read())\n')"
```

After activating the environment, I run these workflows against an existing script inside the repository:

```text
verikernel compile .tmp/workload.py --output .tmp/contract.vk.json
verikernel trace .tmp/workload.py --contract .tmp/contract.vk.json --bundle .tmp/run.vkr
verikernel enforce .tmp/workload.py --contract .tmp/contract.vk.json --mode audit
verikernel enforce .tmp/workload.py --contract .tmp/contract.vk.json --mode strict
verikernel fault .tmp/workload.py --seed 3 --prob 0.1 --bundle .tmp/fault.vkr
verikernel shrink .tmp/fault.vkr --output .tmp/minimal.vkr
verikernel verify .tmp/run.vkr --prove-index 0 --trusted-key .tmp/run.vkr.pubkey
verikernel quantum-audit --qubits 2 --shots 1024 --drift-level 0.2 --bundle .tmp/quantum.vkr
verikernel bench --output-dir benchmarks/results
verikernel demo
verikernel ui --port 8765
verikernel ui --port 0 --self-test
verikernel inspect .tmp/run.vkr --event-seq 0 --show-merkle --show-diff --show-ddmin
verikernel inspect .tmp/run.vkr --format json
python scripts/preflight_ci.py
python -m verikernel.cli.main --help
python -m benchmarks.run_benchmarks
```

I create a failing fault bundle before invoking `shrink`; a successful workload has no failure to minimize.
`fault` captures workload errors in its receipt and exits successfully when receipt creation succeeds.
`enforce --mode strict` returns a nonzero status for a rejected or failing workload.
`verify` returns a nonzero status for invalid evidence.
An empty stream has no valid inclusion index; I omit `--prove-index` for that bundle.

Every bundle has a separate `.audit.key` verifier seed, a `.pubkey` file, and a `.tiles` directory.
I keep the audit seed confidential. POSIX mode 0600 is applied; Windows deployments need explicit ACL custody.
The public key must come from an independently trusted source to authenticate identity.
Verification without `--trusted-key` reports self-contained integrity only.
I never execute a bundle's workload during `verify`; `shrink` explicitly reruns the digest-matching script.

On Linux I use `make test`, `make rust-test`, or `make bench` after installing the corresponding tools.
For native-provider benchmarks I install `.[test,native]` under a supported interpreter.
This workspace also retains an x64 interpreter under `dist/development/python-x64`; I can rerun its benchmark with
`dist/development/python-x64/python.exe -m benchmarks.run_benchmarks` from the repository root.
I provide `Dockerfile` for Python and Rust checks, without claiming a completed container run here.
I do not claim verification on a physical quantum device. Kernel capabilities are checked separately from portable tests.
I do not certify that unrelated host processes made no filesystem writes during development.

I describe the byte-level workflows in [flow.md](flow.md), architectural decisions in
[decisions.md](decisions.md), and licensing in [LICENSE](LICENSE).

On a supported Linux host I build the supervisor with `make native` and select it with
`verikernel enforce workload.py --contract contract.vk.json --mode strict --backend linux`.
I export exact declared filesystem paths and explicit runtime paths to Landlock.
Network permissions are explicit numeric endpoints; strict mediation copies sockaddr bytes and
connects a duplicated descriptor. Missing pidfd permissions produce a denied operation.
Audit mode grants filesystem access for observation and is not isolation.
Kernel probes require BTF, Clang, bpftool, BPF LSM and appropriate attachment privileges.
I run `make probes`, then `python scripts/verify_probes.py SUPERVISOR .tmp/verikernel_probes.bpf.o`.
Return override is opt-in and refuses kernels where ksys_read is not error-injection eligible.
The BPF inode digest is distinct from portable canonical target digests; the profiles remain explicit.

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

I retain [the verification report](benchmarks/results/latest_verification_report.md), [29 decisions](decisions.md), [the threat model](docs/threat-model.md), [the paper](docs/paper.md), and [the dashboard](benchmarks/results/demo_mission_control.html).
