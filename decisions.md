# VeriKernel architectural decisions

Author: Pratham Kapoor <prathamkapoor027@gmail.com>

Status: implemented portable workflows, native Rust FIFO and signer, asynchronous epochs,
Linux Landlock/seccomp supervision, and an aya CO-RE capture loader.
I record measured outcomes in benchmarks/results/latest_benchmark_metrics.json.
I execute Windows ARM64 and x64 tests and Linux ARM64 guest checks separately.
Prospective acceptance criteria below are distinct from measured fixtures.
I do not present prescribed percentages as observed results.
The required literal algorithms conflict with several claimed guarantees.
I identify those conflicts so implementation cannot silently inherit them.

## ADR-001: boundary replay scope

### 1. Context & Problem

I need reproducible fault schedules without recording every instruction.
I also need to state which nondeterminism remains outside that schedule.

### 2. Decision Made

I define replay around operation identity, filtered stack identity, and site ordinal.
I bind the schedule to workload bytes and execution configuration.

### 3. Alternatives Rejected (With Specific Technical Reasons)

I reject full instruction replay as the portable backend because its platform and scheduling requirements differ.
I reject seed-only replay because changes in call order can shift the injected operations.

### 4. Trade-Offs Accepted

I retain nondeterministic thread scheduling and native execution outside mediated operations.
I report replay divergence instead of asserting whole-program determinism.

### 5. What Went Wrong Initially in v0.1 & How Improvement Was Measured in v0.2

I model the v0.1 unscheduled double rerun with real socket reads and journal writes. In v0.2 I reproduce the persisted schedule on 20 of 20 runs. I retain instruction scheduling as an explicit limitation.

## ADR-002: shared transport and admission order

### 1. Context & Problem

Independent per-CPU queues can lose events under burst pressure and invert cross-CPU order.
Finite capacity cannot promise lossless admission at arbitrary producer rates.

### 2. Decision Made

I use per-CPU staging and a shared transport with an explicit global admission sequence.
I require backpressure, durable spill, or authenticated loss reporting on capacity exhaustion.

### 3. Alternatives Rejected (With Specific Technical Reasons)

I reject uncoordinated perf-buffer merging because CPU drain order does not establish event sequence order.
I reject an unlimited zero-drop claim for BPF_MAP_TYPE_RINGBUF because reservation can fail.

### 4. Trade-Offs Accepted

Ordering may wait for an outstanding earlier reservation.
Lossless bounded operation requires producer delay or durable storage, and Python synchronization is not automatically lock-free.

### 5. What Went Wrong Initially in v0.1 & How Improvement Was Measured in v0.2

I measure the v0.1 bounded per-CPU fixture at 97.44% loss and three inversions. The v0.2 native FIFO fixture has zero capacity drops and zero inversions, with 8.400 us producer p99. These are controlled fixtures rather than historical production incidents.

## ADR-003: resolved object identity

### 1. Context & Problem

Raw entry path strings have aliases and can race with filesystem changes.
Path normalization cannot atomically bind a later open to the previously checked object.

### 2. Decision Made

I use canonical paths for display and resolved kernel objects or secure handle mediation for authorization.
I require separate prevention semantics for create and truncate operations.

### 3. Alternatives Rejected (With Specific Technical Reasons)

I reject string-prefix permission checks because relative components and symlinks can cross a boundary.
I reject realpath followed by ordinary open as a TOCTOU defense because the path can change between them.

### 4. Trade-Offs Accepted

Secure mediation requires platform-specific APIs and a carefully designed supervisor.
A portable normalization test proves lexical behavior, not race-free enforcement.

### 5. What Went Wrong Initially in v0.1 & How Improvement Was Measured in v0.2

The v0.1 string-prefix fixture accepts a static symlink escape and misclassifies parent components. I verify real symlink or junction resolution and retained-handle read identity in v0.2. I separately verify atomic Landlock file access policy; portable pre-open checks do not establish a concurrent-swap guarantee.

## ADR-004: inode LRU deduplication

### 1. Context & Problem

Repeated file observations can dominate producer traffic.
Suppressing them after transport consumes capacity before filtering.

### 2. Decision Made

I index an LRU by syscall, device, inode, and modification time.
I keep authorization and injected-fault decisions outside duplicate suppression.

### 3. Alternatives Rejected (With Specific Technical Reasons)

I reject userspace-only post-filtering because it cannot recover ring capacity already consumed.
I reject pathname-only deduplication because aliases can name the same inode.

### 4. Trade-Offs Accepted

Metadata equivalence does not prove content equivalence, and inode reuse needs consideration.
Suppressed observations remain counted so traffic reduction cannot be mistaken for complete logging.

### 5. What Went Wrong Initially in v0.1 & How Improvement Was Measured in v0.2

The v0.1 fixture submits every repeated observation. I suppress 8,499 of 10,000 inputs in v0.2, or 84.99% of all traffic and more than 99% of the designated repeated subset. I verify changed mtime and distinct syscall operations re-emit records.

## ADR-005: epoch Merkle amortization

### 1. Context & Problem

Per-event post-quantum signatures add storage and signer work proportional to every event.
Epoch trees amortize that signature work but need explicit completion and loss semantics.

### 2. Decision Made

I authenticate epoch size and root with one ML-DSA-65 signature.
I use the RFC 9162 tree construction with an explicitly named 32-byte hash profile.

### 3. Alternatives Rejected (With Specific Technical Reasons)

I reject per-event signing for high-rate transport because it couples signer service time to producer pressure.
I reject duplicate-last-leaf trees because they differ from the specified RFC recursion.

### 4. Trade-Offs Accepted

An unfinished epoch has no final signature, and the tree still requires hashing every retained event.
A BLAKE3 tree profile is not automatically a compliant Certificate Transparency deployment.

### 5. What Went Wrong Initially in v0.1 & How Improvement Was Measured in v0.2

The v0.1 microbatch fixture pauses its consumer during real signing. I measure 33090000 per-event signature bytes and 3309 epoch signature bytes at N=10,000. Signing CPU is 8375.000 ms versus 46.875 ms. A full 65,536-event epoch has the stated arithmetic signature reduction; this fixture has 10,000 events.

## ADR-006: ratchet threat boundary

### 1. Context & Problem

A later secret-state compromise must not enable recomputing earlier authentication tags.
An absent unsealed tail cannot be proven solely from a retained prefix.

### 2. Decision Made

I use the specified domain-separated cryptographic ratchet and bind count and terminal state into signed epochs.
I require an independent authenticated checkpoint for claims about an unfinished tail.

### 3. Alternatives Rejected (With Specific Technical Reasons)

I reject an unchanged shared MAC key because its compromise exposes the entire history.
I reject public K0 distribution because it permits reconstructing all historical tag keys.

### 4. Trade-Offs Accepted

Confidential audit material and checkpoint lifecycle need separate storage policies.
Overwriting a Python bytearray cannot guarantee erasure of immutable intermediate copies.

### 5. What Went Wrong Initially in v0.1 & How Improvement Was Measured in v0.2

The v0.1 unsigned-memory window motivates producer tagging. I verify mutation rejection, mutable old-state erasure, deletion or truncation against a sealed terminal key, and intermediate checkpoint ratchets. I do not claim unsealed-tail existence can be proved without an independent commitment.

## ADR-007: ML-DSA-65 conformance

### 1. Context & Problem

I need post-quantum signatures with standard encodings and independent interoperability evidence.
The requested fallback uses a 32-byte challenge where ML-DSA-65 requires 48 bytes.

### 2. Decision Made

I require the FIPS 204 algorithm, including compression, hints, message-domain handling, and all rejection checks.
I treat a conformant provider or a fully validated standard implementation as a prerequisite.

### 3. Alternatives Rejected (With Specific Technical Reasons)

Ed25519 does not meet the post-quantum requirement.
SLH-DSA alternatives have different size and throughput costs depending on parameter set.
Falcon requires a different implementation and numerical side-channel review.
I reject a padded nonstandard lattice signature because matching 3309 bytes does not establish ML-DSA conformance.

### 4. Trade-Offs Accepted

Provider installation and test vectors become deployment requirements.
Pure Python does not provide constant-time execution, and a universal eight-millisecond limit is unsupported.

### 5. What Went Wrong Initially in v0.1 & How Improvement Was Measured in v0.2

I replace a size-compatible custom-signature proposal with standard ML-DSA-65 providers. I verify exact key and signature sizes, deterministic signing, message/key/signature corruption rejection, and Rust public/secret key equality against the independent Python reference. Native signing is measured directly, without an unconditional eight-millisecond claim or certification claim.

## ADR-008: immutable tiles and input manifests

### 1. Context & Problem

Large logs need bounded retrieval and stable evidence identities.
Input provenance and event-tree storage solve different addressing problems.

### 2. Decision Made

I use immutable content-addressed tile artifacts and canonical OmniBOR Git blob manifests.
I distinguish a local tile frame from published Tessera interoperability.

### 3. Alternatives Rejected (With Specific Technical Reasons)

I reject mandatory remote transparency service dependence for offline replay.
I reject a single mutable database as the sole portable evidence artifact because snapshots need additional authenticity rules.

### 4. Trade-Offs Accepted

Static artifacts need atomic publication, garbage collection, and partial-tile handling.
Public transparency and independent witnessing are separate capabilities that local tiles do not provide.

### 5. What Went Wrong Initially in v0.1 & How Improvement Was Measured in v0.2

The v0.1 monolithic artifact motivates bounded tiles. I verify 257-leaf local tile integrity, immutable publication conflicts, the headerless 256-hash C2SP hierarchy, partial suffixes and upper-level roots. I keep the custom hash profile explicit; default Tessera SHA256 checkpoint interoperability is not claimed.

## ADR-009: boundary fault sites

### 1. Context & Problem

Source failpoint macros require code changes and cannot reach every external operation.
Portable wrappers cannot reach arbitrary native syscalls either.

### 2. Decision Made

I define stable fault-site identifiers and explicitly enumerate the operations each backend can mediate.
I preserve source bytes while wrapping supported boundary operations.

### 3. Alternatives Rejected (With Specific Technical Reasons)

I reject mandatory fail-rs-style macros because they change target source integration.
I reject replacing the workload runtime with Turmoil or MadSim because that changes the execution environment being observed.

### 4. Trade-Offs Accepted

Stack locations can change when source changes, and replay must reject such divergence.
Native fault coverage requires a separately implemented kernel or process-supervision backend.

### 5. What Went Wrong Initially in v0.1 & How Improvement Was Measured in v0.2

I replace seed-only global fault positions with operation, filtered stack and site ordinal identities. I reject schedule divergence and mediate ordinary socket/file operations without source macros. I cache canonical stack filenames to avoid resolving every framework frame at every boundary.

## ADR-010: ddmin and oracle semantics

### 1. Context & Problem

A rerun alone does not isolate which injected fault causes a failure.
An unstable failure predicate can invalidate minimization results.

### 2. Decision Made

I use Zeller's ddmin with immutable subset memoization and explicit outcome classification.
I guarantee 1-minimality only under the stated stable-oracle assumptions.

### 3. Alternatives Rejected (With Specific Technical Reasons)

I reject two-run confirmation as a minimization method because it tests no causal reductions.
I reject an unconditional logarithmic oracle bound because general ddmin predicates can require substantially more work.

### 4. Trade-Offs Accepted

The result may be locally minimal rather than globally smallest.
Statistical handling of flaky workloads costs more evaluations and requires a declared confidence policy.

### 5. What Went Wrong Initially in v0.1 & How Improvement Was Measured in v0.2

The v0.1 double-rerun fixture reproduces both failures in 0.00% of its trials. I shrink 32 faults to sites 7 and 23 with 30 oracle evaluations, a 93.75% reduction, and reproduce the minimum 20 of 20 times. I check 1-minimality without promising logarithmic worst-case complexity.

## ADR-011: two interception capability tiers

### 1. Context & Problem

Development on Windows cannot execute Linux LSM programs.
Python auditing does not provide equivalent coverage or isolation.

### 2. Decision Made

I expose a portable runtime tier and a separately verified Linux kernel tier.
I publish a capability manifest and refuse unsupported strict-enforcement guarantees.

### 3. Alternatives Rejected (With Specific Technical Reasons)

I reject a Linux-only deliverable because it prevents native Windows workflow testing.
I reject presenting PEP 578 as a security sandbox because it is explicitly not one.

### 4. Trade-Offs Accepted

The portable tier supports development, bounded interception, and replay, with incomplete native and descendant coverage.
Landlock ABI, seccomp notification, BPF attachment privileges, and eligible override sites need individual checks.

### 5. What Went Wrong Initially in v0.1 & How Improvement Was Measured in v0.2

I replace implicit kernel availability with explicit backend selection. I verify portable behavior on Windows and Linux confinement as UID 0 and 65534, including allowed/denied files and endpoints. I compile and attach the aya CO-RE probes on a BPF-LSM-enabled kernel and verify 45 events with zero losses. I fix a seccomp shutdown race exposed by POLLHUP after child exit.

## ADR-012: Rust and Python responsibilities

### 1. Context & Problem

Binary processing needs explicit layout, while source inspection benefits from Python's AST support.
The available host currently exposes Python 3.13 rather than the requested Python 3.12 toolchain.

### 2. Decision Made

I separate a Rust wire and core library from Python compilation and command orchestration.
I require cross-language byte fixtures and identical named cryptographic profiles.

### 3. Alternatives Rejected (With Specific Technical Reasons)

I reject a pure Python BCC dependency as the portable base because it depends on Linux kernel tooling.
I reject pure C source orchestration because Python parsing and packaging would need redundant implementations.

### 4. Trade-Offs Accepted

I accept two build systems and explicit cross-language interface maintenance.
NumPy multiplication performance cannot replace standard NTT and encoding correctness checks.

### 5. What Went Wrong Initially in v0.1 & How Improvement Was Measured in v0.2

I verify the 128-byte schema and cryptographic Rust core through nine executed tests per Windows ARM64, Windows x64 and Linux ARM64 target. I run Python orchestration tests independently and compare native ML-DSA outputs with the reference provider. I retain explicit architecture-matched shared-library loading.

## ADR-013: direct executable inspection

### 1. Context & Problem

Platform-specific inspection subprocesses are not uniformly installed and can expose untrusted executables.
Executable headers contain malformed offsets that require defensive parsing.

### 2. Decision Made

I parse bounded ELF dynamic tables and PE import directories directly from bytes.
I construct valid synthetic headers for cross-platform tests.

### 3. Alternatives Rejected (With Specific Technical Reasons)

I reject ldd because processing untrusted artifacts through platform tooling can have execution risks and host dependencies.
I reject mandatory dumpbin and objdump because they add external tool requirements and output parsing ambiguity.

### 4. Trade-Offs Accepted

I must maintain format-specific bounds checks and clearly list unsupported variants.
Static imports do not enumerate every dynamically constructed library name.

### 5. What Went Wrong Initially in v0.1 & How Improvement Was Measured in v0.2

I measure the v0.1 raw-trace fixture at recall 0.647059, and the hybrid at 0.941176 over 20 labeled cases. I test malformed and truncated ELF/PE input, dynamic dependencies and synthetic cross-platform headers. The portable child-file case remains a measured miss.

## ADR-014: envelope domain separation

### 1. Context & Problem

Detached bytes do not identify their payload type and can invite cross-protocol ambiguity.
A bundle-carried key does not establish signer identity by itself.

### 2. Decision Made

I sign DSSE PAE over an in-toto statement with a versioned predicate.
I verify against configured trust anchors and exact payload bytes.

### 3. Alternatives Rejected (With Specific Technical Reasons)

I reject raw detached root signatures because they omit event count, algorithms, and workload context.
I reject treating any embedded public key as trusted because an attacker can replace both payload and key.

### 4. Trade-Offs Accepted

Envelope encoding and trust policy add verification steps.
The statement is an authenticated claim, not proof of complete observation or trustworthy hardware.

### 5. What Went Wrong Initially in v0.1 & How Improvement Was Measured in v0.2

I replace context-free root signatures with DSSE PAE and in-toto statements. I verify payload-type binding, pinned-key mismatch rejection, signed manifest equality, count/root checks, periodic checkpoint chains and ratchet terminals. A signature over a malformed intermediate terminal now fails semantic verification.

## ADR-015: quantum uncertainty evidence

### 1. Context & Problem

Shot noise, model disagreement, and hardware drift have different remedies.
Unsigned logs cannot bind their values to the circuit and transpiler settings.

### 2. Decision Made

I record ensemble-derived epistemic uncertainty, binomial shot variance, and calibration KL drift separately.
I bind thresholds, settings, calibration identity, and verdict into the signed execution receipt.

### 3. Alternatives Rejected (With Specific Technical Reasons)

I reject a single undifferentiated confidence score because more shots cannot remove all model or calibration errors.
I reject unverified classical logging because values and circuit provenance can change independently.

### 4. Trade-Offs Accepted

The policy depends on statistical assumptions, numerical tolerances, and available calibration evidence.
Dense circuit checks have exponential cost, and a firewall verdict does not prove physical hardware correctness.

### 5. What Went Wrong Initially in v0.1 & How Improvement Was Measured in v0.2

The v0.1 conflated-uncertainty model motivates independent ensemble, shot and calibration inputs. I verify all four firewall actions, global-phase unitary equivalence and off-diagonal observable coherence. I bind the layout, transpiler seed and policy result into a signed receipt; I do not claim physical hardware validation.


## Source references

I use [FIPS 204](https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.204.pdf) as the signature conformance specification.
I use [RFC 9162](https://www.rfc-editor.org/rfc/rfc9162.html) as the Merkle proof specification.
I use [PEP 578](https://peps.python.org/pep-0578/) to bound the portable auditing claims.
I use [Linux seccomp documentation](https://docs.kernel.org/userspace-api/seccomp_filter.html) to bound notification mediation claims.
I use [Linux BPF helper definitions](https://github.com/torvalds/linux/blob/master/include/uapi/linux/bpf.h) to bound override-return claims.

## ADR-016: Native Rust C-ABI FFI Bridge

### 1. Context & Problem

I previously tested several Rust algorithms separately from Python callers. Native FIFO and signing paths already existed, but stack hashing and fault-key arithmetic lacked an explicit shared C-ABI contract.

### 2. Decision Made

I export ABI version 200, schema size, SplitMix64, FNV-1a, site-key derivation, ratchet-step and fixed-256-byte-leaf Merkle functions. I load the release cdylib through ctypes, validate its version and size, and retain bit-identical Python arithmetic fallbacks. I route runtime stack hashing and fault arithmetic through that bridge.

### 3. Alternatives Rejected (With Specific Technical Reasons)

I reject subprocess calls for individual hashes because process startup dominates the operation. I reject a Python-version-specific extension interface for this small stable surface because explicit integers and owned byte buffers suffice. A raw pointer caller remains responsible for valid memory ranges.

### 4. Trade-Offs Accepted

I accept ctypes overhead, platform library packaging and ABI maintenance. A 1,024-byte FNV speedup cannot predict scalar-call performance. The Merkle C export accepts fixed 256-byte leaves, while event Merkle operations use the ordinary arbitrary-byte API.

### 5. What Went Wrong Initially in v0.1 & How Improvement Was Measured in v0.2

Separate algorithm tests did not demonstrate Python-to-Rust execution. I now compare 1,000 seeded inputs, exercise the loaded release library and report actual FNV throughput in `benchmarks/results/rust_ffi_metrics.json`. Toolchains and native outputs reside under ignored `dist/`, leaving `.venv` with standard Python contents.

## ADR-017: Classic BPF Seccomp Verification

### 1. Context & Problem

I needed byte-level filter evidence on hosts where Docker or WSL was unavailable. A policy description alone did not establish architecture checks, jump validity or real kernel behavior.

### 2. Decision Made

I compile eight-byte little-endian sock_filter instructions for x86_64 and aarch64. I reject architecture mismatch, guard x32 numbers, emit notification or errno decisions and verify the supported instruction subset before simulation. I execute a real filter in a disposable Linux child through an available native, WSL, Docker or contained QEMU runtime.

### 3. Alternatives Rejected (With Specific Technical Reasons)

I reject treating VM simulation as kernel execution and reject an allow-by-default architecture mismatch. I reject claiming a full classic BPF verifier when only the emitted instruction subset is implemented. I keep optional runtime absence visible in capability reports.

### 4. Trade-Offs Accepted

I accept a limited instruction set and runtime setup cost. Notification without an attached listener returns ENOSYS; this experiment verifies that behavior, while the existing supervisor implements listener mediation. WSL and Docker remain preferred when available, with QEMU providing actual Linux execution on this development host.

### 5. What Went Wrong Initially in v0.1 & How Improvement Was Measured in v0.2

Earlier capability evidence depended on the available environment. I now record actual kernel version, effective uid, syscall errno outcomes, SIGSYS architecture rejection and authenticated telemetry in `linux_verification.json`. I fixed serial-console chunking and response synchronization after real guest transport failures.

## ADR-018: Localized Quantum Subgraph Re-Transpilation

### 1. Context & Problem

An abstention verdict prevented a questionable prediction but did not identify a healthy replacement hardware layout. Logical equivalence and calibration quality needed separate evidence.

### 2. Decision Made

I parse a bounded OpenQASM 2/3 gate subset, load unit-normalized calibration snapshots, enumerate valid connected embeddings and maximize the stated survival score. I compare dense logical unitaries through the actual active-physical-basis permutation, then seal the reroute result and event into a signed receipt.

### 3. Alternatives Rejected (With Specific Technical Reasons)

I reject changing physical labels without checking the corresponding basis matrix. I reject treating missing directed couplers as valid and reject presenting synthetic calibration as a measured IBM device. Global large-chip recompilation adds unnecessary search cost for these small local circuits.

### 4. Trade-Offs Accepted

I accept combinatorial layout enumeration, exponential dense matrices and a supported grammar that rejects dynamic control flow and nonterminal measurement. The survival estimate assumes the supplied error model; unitary equivalence cannot guarantee physical hardware fidelity.

### 5. What Went Wrong Initially in v0.1 & How Improvement Was Measured in v0.2

The earlier firewall only abstained. The new case applies a T2 spike to physical qubit 2, records the score loss, chooses a healthy connected layout, measures recovered survival and verifies trace fidelity before signing. The dashboard exposes the snapshot provenance and both scores rather than implying physical execution.

## ADR-019: Machine-Checked Formal Invariant Fuzzing

### 1. Context & Problem

Fixed examples left non-power-of-two trees, corrupted sequence fields and arbitrary hidden fault combinations underexplored. I needed repeatable structural checks across those input families.

### 2. Decision Made

I run at least 500 seeded wire trials, every tree size through 130 and all prefix pairs, 400 stream attacks, 100 minimality trials and 50 matrix permutation checks. I preserve the seed, counts, duration and measured results as structured evidence.

### 3. Alternatives Rejected (With Specific Technical Reasons)

I reject unseeded fuzzing that cannot reproduce a failure and tests that only compare an implementation with itself. I check altered leaves and proof nodes, single-fault-removal oracle behavior and matrix fidelity. I reject describing finite randomized checks as an unbounded theorem proof.

### 4. Trade-Offs Accepted

I accept finite input coverage and deterministic fixture distributions. Mutation detection assumes a protected sealed checkpoint. The minimality oracle must reset workload state, and its guarantee is 1-minimal rather than globally minimum cardinality.

### 5. What Went Wrong Initially in v0.1 & How Improvement Was Measured in v0.2

Mutation of seq_no exposed a diagnostic ambiguity: the claimed sequence could itself be corrupt. I now return the first corrupted position separately. I measure detections, all-prefix consistency checks and minimum unitary fidelity in `property_fuzzing.json`, with zero omitted test cases.

## ADR-020: Zero-Copy Batch Rust FFI over Contiguous 128-Byte Buffers

### 1. Context & Problem

Scalar arithmetic crossings did not establish whole-epoch cryptographic processing. I needed self-contained SHA-256 without changing the existing BLAKE3 receipt profile.

### 2. Decision Made

I expose SHA-256, in-place batch sealing, full-stream verification, RFC 9162 roots and batch-local LRU masks. Python lends mutable bytearrays through ctypes.from_buffer. I declare the SHA-256 profile in new receipts and use byte slices rather than casting unaligned storage to aligned Rust structs.

### 3. Alternatives Rejected (With Specific Technical Reasons)

I reject per-event crossings and an implicit global hash change. I reject universal throughput and clean-build deadlines independent of compiler, architecture and cached dependencies. The compression code has no crate dependency; the workspace retains its existing cryptographic and transport dependencies.

### 4. Trade-Offs Accepted

I require exclusive ownership and valid nonoverlapping pointer ranges. Native hashing costs O(n), Merkle stack space is O(log n), and LRU filtering uses expected O(n) time and O(capacity) space. The cache is local to one batch and does not omit policy checks.

### 5. What Went Wrong Initially in v0.1 & How Improvement Was Measured in v0.2

I compare nine requested event counts with hashlib and an independent LRU oracle, including empty and uneven trees. I preserve scalar-only ABI fallback and measure three operation trials in Benchmark 5. Target misses remain visible in the measured report.

## ADR-021: Multi-Process Preload IPC Telemetry Supervision

### 1. Context & Problem

In-process hooks missed participating child internals. Windows virtualenv launchers also made OS ancestry differ from interpreter ancestry.

### 2. Decision Made

I prepend a contained sitecustomize bootstrap, inherit contract and per-role fault settings, and append whole records to a separate spool per interpreter PID. I retain startup/completion markers and both parent relationships. I merge by monotonic timestamp with PID/local-sequence tie breaking, assign global sequence numbers and seal through the batch engine.

### 3. Alternatives Rejected (With Specific Technical Reasons)

I reject unsynchronized writes to one shared file and silently accepted partial records. Preload is cooperative: native executables, isolated startup, disabled site loading and cleared environments can escape observation. I do not equate it with kernel confinement.

### 4. Trade-Offs Accepted

Collection uses O(n) memory and O(n log n) merge work. An equally privileged hostile process can modify unsealed local spools. Detached or forcibly terminated workloads require explicit lifecycle management; completion of captured streams does not establish absence of escaped processes.

### 5. What Went Wrong Initially in v0.1 & How Improvement Was Measured in v0.2

The baseline detection fixture retained a child false negative. I now capture a parent, two workers and a grandchild, detect an undeclared grandchild file, exercise strict denial and seeded faults, and verify the signed stream and inclusion proof. The CLI exposes the multiprocess backend explicitly.

## ADR-022: Chained Multi-Epoch RFC 9162 Consistency Ledger

### 1. Context & Problem

Isolated epoch roots did not bind predecessors. A self-consistent old directory cannot alone establish that a later tail once existed.

### 2. Decision Made

I sign cumulative SHA-256 checkpoints with ML-DSA-65/DSSE, binding index, size, cumulative/local roots, previous checkpoint hash, previous epoch root and previous terminal key. I verify every ratchet and consistency proof, with optional separately retained checkpoint and trusted key anchors.

### 3. Alternatives Rejected (With Specific Technical Reasons)

I reject rollback claims without an external anchor, unlinked signed roots and overwriting immutable epoch records. An exclusive lock pathname serializes appenders. Supporting files are published before HEAD.

### 4. Trade-Offs Accepted

The verifier rehashes prefixes in O(t*n) work and retains O(n) data for t epochs. Wire sequences are epoch-local while Merkle positions are cumulative. Audit seeds remain private, exported history is sensitive, and Windows custody requires appropriate ACLs.

### 5. What Went Wrong Initially in v0.1 & How Improvement Was Measured in v0.2

I rewrite and re-sign a locally valid first epoch and require its successor to reject the changed link. I also corrupt proofs and delete a tail while retaining an anchor. Benchmark 5 measures four signed epochs rather than extrapolating from one bundle.

## ADR-023: Constant-Time Verification and Welch Timing Evidence

### 1. Context & Problem

Early tag rejection exposed invalid record position through execution length. Public ML-DSA hint decoding rejected last-byte corruption sooner than a challenge mutation reached lattice arithmetic.

### 2. Decision Made

I scan full ratchet streams, use constant-time digest comparison, and validate public signature encodings. A normalized work signature reaches the backend, while an independent validity flag always rejects noncanonical original bytes. I freeze independent SHA-256/FIPS 204 known answers.

### 3. Alternatives Rejected (With Specific Technical Reasons)

I reject sleep padding, fabricated timings, outlier deletion and rerunning unchanged code until a threshold holds. I retain the initial failed result and interleave 2,000 observations per class. A false verification result alone cannot prove constant-time execution.

### 4. Trade-Offs Accepted

The guard adds fixed-dimension decoding work. Python, provider internals and compiler transformations remain outside a timing proof. Welch's threshold is finite evidence, and malformed public-input timing alone does not establish secret leakage.

### 5. What Went Wrong Initially in v0.1 & How Improvement Was Measured in v0.2

I retain the baseline signature timing separation in sidechannel_baseline.json. I test rejection even if the normalized backend accepts, verify five frozen vectors against an independent implementation, and report current tag, proof and signature timing statistics alongside benchmark results.


## ADR-024: Machine-Code Constant-Time Disassembly Verification

### 1. Context & Problem

Wall-clock corruption timing cannot establish the instruction sequence emitted by a compiler.

### 2. Decision Made

I export an unrolled volatile 32-byte XOR/OR comparator, use it in batch verification, and inspect the actual exported release symbol with an instruction decoder and direct PE mapping. I record the artifact hash and reject conditional control flow or calls after the public pointer guards.

### 3. Alternatives Rejected (With Specific Technical Reasons)

I reject raw byte-opcode searches because x86 instruction immediates can contain opcode-shaped bytes. I reject treating a small Welch statistic as universal constant-time certification.

### 4. Trade-Offs Accepted

The finding applies to the checked comparison body and binary, not other cryptography or microarchitectural behavior. Native pointer validity and the decoder remain trusted.

### 5. What Went Wrong Initially in v0.1 & How Improvement Was Measured in v0.2

I previously retained only finite timing evidence. I now test every changed byte position and inspect the ARM64 release comparator, while preserving the timing campaign as a separate experiment.


## ADR-025: Explicit Serialization Types and Runtime Boundary Enforcement

### 1. Context & Problem

Catch-all annotations did not document JSON, audit tuple or native-layout assumptions.

### 2. Decision Made

I define recursive JSON values, capability/receipt TypedDict schemas, an event-sink protocol and an exact ctypes event layout. I validate contract, envelope and receipt shapes and reject invalid handled audit arguments. The source audit rejects catch-all dynamic annotations including aliases.

### 3. Alternatives Rejected (With Specific Technical Reasons)

I reject annotation-only schema declarations with no runtime validation. I reject claiming that replacing opaque values with object proves whole-program type safety.

### 4. Trade-Offs Accepted

Runtime narrowing costs O(B) traversal and copies validated JSON. Opaque runtime interfaces still require concrete guards, and annotation presence is not sound static analysis.

### 5. What Went Wrong Initially in v0.1 & How Improvement Was Measured in v0.2

I previously counted hundreds of dynamic annotation references. I now enforce zero such annotations in the package and run malformed-input, layout and complete regression tests.


## ADR-026: Cooperative Native PE/ELF Supervision and Reproducible Packaging

### 1. Context & Problem

Python hooks do not observe arbitrary native child internals, and ordinary archive timestamps make package hashes vary.

### 2. Decision Made

I add a real compiled Rust checkpoint target with authenticated linked-boundary requests, direct binary import inspection, signed attempted-operation telemetry, strict capability denial and deterministic checkpoint fault reduction. I independently build normalized wheels twice and compare SHA-256 and GitOID before a clean offline installation.

### 3. Alternatives Rejected (With Specific Technical Reasons)

I reject fabricated child records inferred from command arguments. I reject presenting linked instrumentation as hostile-native confinement. I reject a timestamp-only build comparison that ignores ZIP member order, permissions or RECORD metadata.

### 4. Trade-Offs Accepted

The native adapter and executable location are trusted. Reproducibility holds for the fixed source and ZIP toolchain; optional native libraries are separate. The wheel includes source and schema metadata rather than an architecture-mismatched shared library.

### 5. What Went Wrong Initially in v0.1 & How Improvement Was Measured in v0.2

I previously exercised scalar/native libraries separately from workload executables. I now inspect and run the actual ARM64 PE target, verify its receipt, deny an undeclared file, and shrink the real write-failure workload to one site. Two independently populated archives install successfully and match byte for byte.

## ADR-027: Fixed-Schedule Rust Lattice NTT and Norm Verification

### 1. Context & Problem

I previously inspected only the digest comparator. Lattice butterfly arithmetic and coefficient rejection checks required their own compiled-code evidence.

### 2. Decision Made

I implement the standard Dilithium Montgomery arithmetic, bit-reversed powers of 1753, forward transform, inverse-to-Montgomery transform, pointwise multiplication and full-scan norm check. I expand the fixed 256-coefficient schedule in Rust and inspect six exported machine-code bodies. I bind the operations through ctypes and provide an explicitly selected native-ring standard ML-DSA provider.

### 3. Alternatives Rejected (With Specific Technical Reasons)

I reject raw opcode-byte searches, unexplained loop exemptions, early coefficient rejection and a signature-size-compatible custom scheme. Independent schoolbook multiplication tests the ring relation without reusing the transform implementation.

### 4. Trade-Offs Accepted

Expansion increases binary size and compilation time. Inverse(NTT(a)) produces a times the Montgomery radix; inverse(pointwise(NTT(a),NTT(b))) produces the standard ring product. The maintained native fips204 provider remains the default; selecting native-ring exercises the new arithmetic in the standard Python protocol. Branch freedom covers six inspected bodies, excluding public guards, rejection sampling, SHAKE, other providers and microarchitectural effects.

### 5. What Went Wrong Initially in v0.1 & How Improvement Was Measured in v0.2

I initially had comparison-only machine evidence. I now inspect actual decoded export bytes, reject a deliberately introduced conditional branch, match standard deterministic signatures, and compare 100 polynomial pairs against independent convolution. The inverse provider retains the ring element inheritance required by the standard matrix implementation.

## ADR-028: Uncooperative Native Kernel Confinement

### 1. Context & Problem

The linked checkpoint adapter required workload cooperation. An executable ignoring its environment could bypass its checks.

### 2. Decision Made

I launch Windows children suspended, configure one-process and 16 MiB memory Job Object limits, assign the child, then resume it with an explicit inherited-handle allowlist. I query real kernel accounting and bind its canonical payload to a signed ledger leaf. The Linux launcher applies no-new-privileges, an architecture-checked seccomp denial filter and optional fail-closed Landlock roots before exec. A separate mapped-PE parser enumerates and conditionally redirects owned IAT slots.

### 3. Alternatives Rejected (With Specific Technical Reasons)

I reject environment-only authorization, assignment after resume, inherited Job Object handles, command-line-inferred telemetry and simulated kernel denials. Controls execute the same unrestricted operations successfully before their restricted runs.

### 4. Trade-Offs Accepted

Windows Job Objects enforce resource and child-count limits; they do not restrict arbitrary file or network access. Linux filters restrict the listed socket/process syscalls and Landlock filesystem rights; inherited descriptors and a compromised kernel remain trust boundaries. IAT redirection in a writable buffer demonstrates parsing and expected-value verification, not tamper-resistant enforcement. The Linux evidence requires a real runtime and fails closed when none is available.

### 5. What Went Wrong Initially in v0.1 & How Improvement Was Measured in v0.2

I previously tested cooperative native requests. I now prove successful unrestricted child creation and a touched 128 MiB allocation, then actual Job Object denials. A UID 65534 Linux guest executes compiled uncooperative attacks and obtains EACCES for socket creation, child creation and a Landlock-denied read. The accounting verifier rejects any changed sidecar bytes.

The initial combined release run exposed a guest startup failure after the 120-second deadline. I preserve that failed run, reduce both guest configurations from 2 GiB to 1 GiB and allow a bounded 240-second cold boot. The initial base guest reached its readiness output near the old deadline. I replace the 274 MB development root with a deterministic runtime image, excluding compilers, modules, site packages and workload state. I preserve standard-library bytecode and its source timestamps to avoid recompiling Python during emulated startup. Unique command-completion markers reject stale shell markers; a noninteractive command loop avoids terminal cursor queries. I retain boot timing diagnostics and repeat the entire suite; timeout changes do not substitute for actual kernel-denial evidence.

## ADR-029: Differential Reference Oracle Verification

### 1. Context & Problem

Round trips can preserve a shared implementation error. A shrinker's result can reproduce a failure without being 1-minimal.

### 2. Decision Made

I compare 100 native polynomial products with exact integer schoolbook negacyclic convolution. I enumerate all 1,024 subsets for each of 20 seeded monotone failure predicates and require the shrinker's result to belong to the complete set of 1-minimal failures. I independently compare 14 SHA-256 block-boundary inputs and eight tree sizes with hashlib definitions.

### 3. Alternatives Rejected (With Specific Technical Reasons)

I reject comparing a transform with its own inverse alone, confusing minimum cardinality with 1-minimality, and constructing the reference tree with production Merkle helpers. I retain provider identity and seeds in measured JSON.

### 4. Trade-Offs Accepted

Schoolbook verification costs O(T*N^2), and exhaustive predicates cost O(P*2^M*M). These bounded campaigns validate implementations against independent definitions; they do not establish unbounded formal verification or universal oracle complexity.

### 5. What Went Wrong Initially in v0.1 & How Improvement Was Measured in v0.2

I previously tested selected examples and direct round trips. I now require every one of 25,600 product coefficients to match, every selected fault mask to be exhaustively 1-minimal, and fewer than 250 shrinker oracle evaluations per predicate. The arithmetic verification check runs these references alongside the six-symbol machine-code inspection.
