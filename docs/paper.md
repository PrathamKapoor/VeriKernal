# VeriKernel: Boundary-Deterministic Fault Replay, Live Dependency Contract Enforcement, and Forward-Secure Post-Quantum Provenance at the OS Boundary

Pratham Kapoor · PrathamKapoor · prathamkapoor027@gmail.com

## Abstract

I present an execution-verification system that binds static dependency
contracts, runtime boundary observations, deterministic fault schedules, and
post-quantum receipts. I use a 128-byte event ABI, producer key evolution,
domain-separated Merkle trees, and ML-DSA-65 signatures over DSSE statements.
I expose portable, cooperative process-tree, cooperative compiled-target, and
Linux restricted profiles rather than give them interchangeable coverage claims.
I combine native batch cryptography, append-only epoch checkpoints, and
counterexample minimization with explicit trust anchors. A recorded development
run measured 11.746740 million deduplication events/s, zero transport drops in
its controlled fixture, and a 32-to-2 fault reduction. I provide fresh release
measurements in the linked artifacts. I state four conditional theorems and
separate mathematical arguments, finite property tests, instruction inspection,
and timing evidence. The implementation is not an independently certified
cryptographic module or a proof of arbitrary native capture completeness.

## 1. Introduction

Language imports omit dependencies introduced by native dynamic linking,
environment variables, process trees, and runtime-selected endpoints.
Conversely, a syscall stream does not identify the source contract that
authorized it. Transient I/O failures introduce another separation: two runs
of the same source can encounter different operation-boundary failures.
An attestation over an unexplained final manifest leaves both relationships
implicit. I make the contract identity, captured operation stream, fault
schedule, and verification profile explicit inputs to one execution receipt.

My contributions are an interoperable fixed-width event representation,
native in-place SHA-256 ratchet/Merkle batches, a chained multi-epoch ledger,
and a replayable boundary-fault reducer. I additionally bind modeled quantum
uncertainty and physical-layout selection to signed execution evidence.
I use a compiled native checkpoint workload to test actual PE imports,
filesystem operations, policy denial, and write-fault minimization.
Its linked adapter is part of the TCB; I do not infer generic native confinement
from an instrumented target experiment.

## 2. System and adversary model

I model an event E as exactly 128 little-endian bytes: sequence and timestamp,
process/thread identifiers, operation and signed fault code, device/inode/mtime,
stack key, 32-byte target digest, and 32-byte authentication tag. The source
contract C binds inspected inputs using Git blob SHA-256 identifiers.
A verifier selects the explicit hash profile and a trusted public key P.
A separately retained checkpoint A is required to reject restoration of a
complete older ledger directory. Full definitions and prioritized abuse paths
appear in [the threat model](threat-model.md).

I consider ghost dependency injection, mutable namespace races, captured-log
editing after compromise, and quantum cryptanalysis/calibration manipulation.
I assume correct trusted components, valid C-ABI buffers, and cryptographic
primitives with their stated properties. A cooperative profile additionally
assumes its interpreter or linked boundary adapter cannot be bypassed.
The Linux profile relies on installed kernel policy rather than that assumption.
I do not assume `realpath` makes check/use sequences atomic.

## 3. Architecture and algorithms

### 3.1 Contracts and observations

I traverse Python AST nodes for literal imports and operations and parse ELF
dynamic tables and PE import tables directly. I normalize declared dependency
aliases and compute a canonical input manifest. Observed targets are compared
to capability fields; undeclared observations form a machine-applicable patch.
Static tables cannot enumerate all future runtime loads. Producer-side inode
deduplication suppresses repeated operation/object/version tuples, retaining
new modification times as new keys. It changes telemetry multiplicity and
must not be interpreted as a complete per-read accounting ledger.

### 3.2 Replay and minimization

I derive fault-site decisions from seeded stack, operation, and ordinal keys.
Replay rejects a changed site identity. The oracle restores its workload state
before each experiment and returns whether the failure remains. I partition
the active set, test subsets and complements, and increase granularity when
neither reduces the counterexample. Memoization avoids repeated identical
subset evaluations. I promise 1-minimality under a deterministic oracle,
not a globally minimum explanation or a logarithmic worst-case bound.

### 3.3 Cryptographic stream and ledger

For the SHA-256 batch profile I compute

\[
C_0=H(\texttt{VK-RATCHET-COMMIT-V1}\Vert K_0),\quad
T_i=H(\texttt{VK-RATCHET-TAG-V1}\Vert K_i\Vert E_i[0:96]),
\]
\[
K_{i+1}=H(\texttt{VK-RATCHET-STEP-V1}\Vert K_i\Vert T_i).
\]

I overwrite mutable intermediate key storage. This is not proof that runtime,
allocator or stack copies never existed. Portable historical profiles explicitly
declare BLAKE3 or BLAKE2b-256 and cannot be silently verified as SHA-256.
The Merkle functions use H(empty), H(0x00 || leaf), and H(0x01 || left || right),
splitting at the largest power of two strictly below the current leaf count.
I use the algorithms of [RFC 9162](https://www.rfc-editor.org/rfc/rfc9162.html#section-2.1)
for inclusion and append-only consistency paths; this is not a complete CT server.

Each signed checkpoint commits to epoch index, cumulative size/root,
predecessor checkpoint hash, local root, and previous/current ratchet endpoints.
DSSE authenticates the exact serialized payload and payload type through its
[pre-authentication encoding](https://github.com/secure-systems-lab/dsse/blob/master/protocol.md).
I use standard-sized ML-DSA-65 keys/signatures from maintained implementations,
with frozen vectors checked against an independent reference.

## 4. Conditional theorems and proofs

### Theorem 1: Wire bijection and deterministic 1-minimal reduction

For representable field values with 32-byte digests, encoding then decoding
the event representation is the identity (I1). For a finite initial failing
fault set C and deterministic oracle f, the implemented reducer returns C*
with f(C*) true and f(C* minus {x}) false for every x in C* (I4).

Proof. Fixed offsets partition all 128 bytes, and each bounded integer has a
unique little-endian representation. The signed fault is encoded modulo 2^32
and decoded by subtracting 2^32 exactly when its high bit is set. Every other
field is copied without loss, establishing the bijection. For reduction, every
accepted step strictly decreases a finite set and preserves f=true. At final
granularity each removable singleton complement has been tested; a successful
one would force another reduction. A failing empty set is handled separately.
Termination and 1-minimality follow. Nondeterministic oracles invalidate the
memoization premise. Worst-case oracle work is O(|C|^2), not O(log |C|).

### Theorem 2: Anchored Merkle prefix integrity

Under collision resistance of the declared H, authentic fixed checkpoint
roots, and correct verification, a different leaf sequence cannot validate
as the same tree except with a hash collision. Valid consistency paths bind
the old sequence as a prefix of the new sequence (I2).

Proof. Domain separation prevents interpreting a leaf preimage as an internal
node preimage. For a single leaf, two distinct accepted leaves with equal root
give a collision. Inductively, unequal sequences at a fixed split have an unequal
child sequence. Equal parent hashes imply either an equal ordered child pair,
contradicting the induction hypothesis, or a collision in H. Inclusion reconstructs
exactly those ordered ancestors. Consistency paths reconstruct both roots from
their common prefix decomposition. A changed prefix accepted for fixed old/new
roots therefore yields the same collision argument. Signature authenticity of
the roots requires the separate unforgeability assumption. An old complete
history with no external newer anchor is not a prefix-integrity violation.

### Theorem 3: Retained-endpoint ratchet mutation detection

Assume correct capture, an independently fixed C0 and KN, confidential historical
keys/audit seed, and the deployed hash-chain/tag construction's required
unpredictability and preimage properties. Alteration, deletion or reordering
that changes authenticated event prefixes is rejected unless a valid replacement
tag/state chain reaching those endpoints is forged (I3).

Proof. Before the first altered prefix, the verifier and producer share the same
state. At the first altered prefix, the expected tag differs except if the tag
function collides or the adversary produces an accepted replacement chain.
An interior deletion or swap additionally changes authenticated sequence fields.
A shortened tail has the wrong terminal key unless a state collision occurs.
The claim is conditional on protected endpoints and erased old keys: it does
not apply to a stolen audit seed, a replaced signer, or an unsealed tail whose
existence was never committed. I do not claim collision resistance by itself
proves that this concatenated-hash construction is a forward-secure PRF.
The memory-erasure and compromise assumptions are not mechanically established.

### Theorem 4: Unitary invariance under physical rebinding

Let a bijective basis permutation P represent a valid logical-to-physical
embedding on the active subspace. For ideal gates rebound consistently,
U_physical = P U_logical P-dagger, so normalized trace fidelity after undoing
the permutation equals one (I5).

Proof. Substitute the equality into Tr(U-dagger P-dagger U_physical P).
Using P-dagger P=I and U-dagger U=I gives Tr(I)=2^Q. Its absolute value divided
by 2^Q equals one. Dense floating-point calculations check this relation within
the declared tolerance. Calibration survival scoring is a separate probabilistic
model and supplies no theorem about actual noisy hardware performance.

## 5. Implementation and machine-code evidence

I implement the event ABI in Rust and Python, passing mutable contiguous
bytearrays through ctypes without copying the event array. Rust hashes packed
leaves, evolves/erases key state, and deduplicates tuple keys. Native pointers
must still reference valid allocated buffers; null guards do not establish
arbitrary caller memory safety. I use explicit hash-profile names in receipts.

The comparator performs 32 unrolled volatile byte reads from each input,
XOR/OR accumulation, and arithmetic conversion to equality. I inspect the
exported symbol in the built library with a real instruction decoder and direct
PE export mapping. After public null guards, the checked body contains no
conditional branches or calls. The report binds architecture, decoded instruction
count, exact bytes and library digest. This property is narrower than whole-program
constant-time execution. Constant-address memory reads and branch absence do not
certify caches, compiler changes, allocation, the signer, or the operating system.

I run interleaved first/last-byte corruption experiments using Welch's statistic
and retain all samples. Like the [dudect project](https://github.com/oreparaz/dudect),
this is a timing investigation, not a universal absence-of-leakage proof.
I validate structured JSON, C layout and handled audit tuples; the source audit
rejects dynamic catch-all annotations in the package. `object` annotations remain
for opaque runtime values, so this is not equivalent to a sound strict type-checker.

## 6. Empirical evaluation

I retain machine-readable run outputs in
[latest_benchmark_metrics.json](../benchmarks/results/latest_benchmark_metrics.json),
[preflight_ci.json](../benchmarks/results/preflight_ci.json), and
[latest_verification_report.md](../benchmarks/results/latest_verification_report.md).
The following earlier development sample used Windows 11 ARM64, Python 3.13.15,
the native Rust signer and 10,000 input events. It is not an external-tool benchmark.

| Earlier development measurement | Observed result |
|---|---:|
| Native batch inode deduplication | 11,746,740.289 events/s |
| Native batch sealing | 306,719.300 events/s |
| Native batch verification | 224,099.200 events/s |
| Controlled transport drop rate / inversions | 0.00% / 0 |
| Four-epoch, 10,000-leaf anchored verification | 290.364 ms median |
| Last consistency proof | 416 bytes |
| 32-site fault campaign | 2 sites, 93.75% reduction |
| Stable replay | 20/20 |
| Signature corruption Welch statistic | 0.114070 |

The repeated-key workload, event count, cache capacity and consumer schedule
affect throughput and drop observations. I do not extrapolate a universal zero-loss
guarantee from a finite burst. The original hybrid fixture retains a child-process
false negative; the explicit multiprocess backend is tested separately.
The quantum example uses modeled calibration, not a physical QPU run.
Current release values supersede historical performance comparisons in the
release report. Repeated builds compare independently read source snapshots,
normalized ZIP metadata, wheel RECORD contents, SHA-256 and GitOID, followed
by a contained offline clean install. This does not establish reproducible
native compiler output across different compilers or dependency versions.

## 7. Related work

I use [rr](https://rr-project.org/) as a distinct instruction-replay approach;
VeriKernel's scheduled boundary faults do not reproduce every instruction or
thread interleaving. I use standard
[ML-DSA](https://csrc.nist.gov/pubs/fips/204/final) rather than a same-sized
custom signature construction. DSSE supplies payload/type binding and RFC 9162
supplies append-only tree algorithms; neither supplies workload capture.
Python audit hooks supply language-runtime observations and Landlock supplies
Linux access control, with substantially different trust boundaries.
I combine these mechanisms with explicit producer, key-custody, and checkpoint
assumptions. I make no novelty claim for the underlying primitives.

## 8. Fixed-schedule lattice arithmetic and uncooperative resource controls

I add standard modulus-q Montgomery arithmetic, the bit-reversed 256-point transform and inverse-to-Montgomery transform, pointwise multiplication and a full-scan norm check. I expand the fixed butterfly schedule and inspect six exported release symbols against their actual bytes. The claim is absence of conditional control transfers/calls in those arithmetic bodies after public guards. Under valid fixed-size addresses and operand-independent instruction latency, these bodies have coefficient-independent instruction and access schedules. This is a conditional arithmetic result, not a constant-time certification of the complete signature protocol. The default maintained fips204 provider remains separate; native-ring explicitly selects the new arithmetic within the standard protocol.

I independently evaluate 100 uniformly seeded polynomial pairs against the defining O(N^2) negacyclic convolution, checking 25,600 coefficients. Twenty monotone failure predicates are evaluated over all 1,024 subsets; the chosen ddmin result must be a member of the exhaustively computed 1-minimal sets, using fewer than 250 oracle calls. Fourteen SHA-256 input lengths straddle padding/block boundaries, and eight tree sizes include empty and uneven trees. These are finite reference campaigns, with seeds and exact current counts in differential_reference.json.

I separate cooperative capture from kernel-enforced resource restrictions. Windows creates a suspended process, assigns a configured one-process/16 MiB Job Object, then resumes it. An explicit inherited-handle list excludes the Job Object handle. Controls create a child and touch 128 MiB successfully; restricted versions obtain actual kernel denials. Linux installs no-new-privileges, architecture-checked seccomp socket/process restrictions and optional Landlock rules before exec. Compiled uncooperative targets run at UID 65534 in a real Linux guest. The current release report retains the measured kernel version, backend, error codes and accounting counters.

These controls establish particular denied capabilities. Job Objects alone do not enforce arbitrary filesystem or network policy, and the Linux filter is not a universal syscall allowlist. I bind the canonical aggregate accounting payload to a signed ledger event and verify that binding separately. The PE thunk parser demonstrates safe mapped-image enumeration and conditional slot replacement; it is not the kernel enforcement boundary. ADR-027 through ADR-029 record the implementation trade-offs and independent references.

## 9. Reproduction and interpretation

I build with `python scripts/build_native.py`, execute `pytest -v`, inspect
the comparator with `python scripts/verify_constant_time_asm.py`, and compare
packages with `python scripts/build_reproducible_dist.py`. The final preflight
also runs the native target and the complete benchmark/demo workflows.
I retain actual outputs and distinguish the local Windows run, contained Linux
kernel experiment, and configured but unexecuted remote jobs. The four proofs
are mathematical arguments under stated assumptions; finite randomized tests
are implementation checks, and no external mechanized proof checker or peer review is claimed.

## 10. Current release measurements

| Current release experiment | Measured result |
|---|---:|
| Native inode deduplication | 9247272.055 events/s |
| Anchored four-epoch verification | 372.822 ms |
| Portable burst drops / inversions | 0.00% / 0 |
| Independent polynomial pairs | 100 |
| Maximum exhaustive-reference ddmin calls | 43 |
| Successful local preflight checks | 12 |
