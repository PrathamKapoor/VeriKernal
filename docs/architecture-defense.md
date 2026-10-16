# Architecture defense

I separate measured guarantees from platform capabilities and explicit trust assumptions.
The current evidence is in [the verification report](../benchmarks/results/latest_verification_report.md).

## Q1. What is deterministic about replay?

I derive each fault decision from a stack hash, operation, site ordinal and seed. A recorded schedule preserves the selected boundary faults. I do not reproduce arbitrary thread scheduling, instruction execution or remote services. Divergent workloads must be rejected or inspected rather than treated as equivalent replays.

## Q2. Why retain two interception tiers?

I use Linux confinement and kernel telemetry where available, and Python boundary shims for portable experiments. PEP 578 observes selected interpreter operations. It cannot contain arbitrary native code or all transitive child operations. Native enforcement requires the Linux supervisor and appropriate kernel capabilities.

## Q3. Does realpath eliminate symlink races?

I use canonical paths to remove relative-path ambiguity and detect the demonstrated symlink escape. Resolving a name and subsequently opening it leaves a race. Kernel VFS mediation and descriptor-based checks are the stronger boundary; portable realpath alone is not atomic authorization.

## Q4. What does the Linux seccomp experiment establish?

I install an actual filter in a disposable unprivileged child, observe injected errno and notification-without-listener behavior, authenticate the resulting event stream and require SIGSYS for an architecture mismatch. The offline VM checks policy semantics independently. It is not evidence that every Linux deployment supports every optional confinement feature.

## Q5. Why guard architecture and x32 separately?

I reject mismatched audit architectures before inspecting syscall numbers. On x86_64, the x32 syscall-number bit shares the audit architecture value, so I also reject that bit. Otherwise a filter could classify a different syscall table under the intended native numbers.

## Q6. Is the cBPF simulator a complete kernel verifier?

I implement the emitted load, equality, bit-test and return instruction subset. I validate every instruction, forward branch bounds, permitted data offsets and termination. I reject unsupported instructions. I do not claim to implement the entire Linux classic BPF instruction set or its kernel implementation.

## Q7. How are notification races handled?

I distinguish safe errno mediation from pathname-sensitive operations. Continuing an intercepted pathname syscall after userspace inspection can race target memory or filesystem changes. The Linux supervisor uses confinement rather than presenting a notification string check as an atomic filesystem sandbox.

## Q8. Why expose a C ABI instead of a Python extension API?

I keep fixed-width arithmetic and explicit byte buffers independent of Python's extension ABI. ctypes loads the platform library after checking ABI version and event size. The runtime now calls native stack hashing and fault arithmetic, extending the pre-existing native FIFO and signature paths.

I also lend contiguous mutable event arrays to the SHA-256 batch exports. This removes per-event crossings while retaining the original scalar ABI and receipt profiles. A scalar-only older library falls back for batch operations instead of failing during symbol binding.

## Q9. Can C pointer inputs be made safe for every caller?

I reject null pointers and invalid supported sizes, but a foreign caller must supply valid readable or writable ranges. A non-null dangling pointer cannot be validated by these exports. The Python bridge allocates owned ctypes buffers that remain alive throughout each synchronous call.

For batch operations I borrow the caller's bytearray without copying the event payload. The caller must not resize or concurrently modify it while ctypes releases the interpreter lock for the native call. Native event parsing uses byte slices, so Python storage does not need the Rust struct's cache-line alignment.

## Q10. What exactly is measured by the FFI speedup?

I compare repeated 1,024-byte FNV-1a calls using the same bytes and iteration count. The result includes ctypes overhead and depends on architecture, compiler and power state. It does not imply that tiny scalar SplitMix64 calls or every application become faster by the same factor.

## Q11. Is the complete pipeline lock-free and lossless?

I use a bounded native FIFO with synchronized staging and contiguous sequence release. Python coordination still uses synchronization. A finite ring cannot guarantee zero loss under an indefinitely stalled consumer without backpressure or unbounded storage. I report losses for the measured workload rather than universal zero-loss claims.

## Q12. What does inode deduplication sacrifice?

I suppress repeated operation/device/inode/mtime tuples with bounded LRU storage. A changed mtime misses the cache. This is a telemetry summarization policy, not proof of identical file content or permission decisions. I do not omit enforcement checks merely because an event was previously observed.

## Q13. What protects ratcheted events and what remains exposed?

I authenticate each event before evolving the producer key and zero mutable old storage. A protected terminal key and event count detect deletion, order changes and truncation relative to that checkpoint. An entirely uncheckpointed suffix cannot prove its own existence. Python immutable intermediates and audit-seed escrow limit memory-erasure claims.

I chain epoch checkpoints and verify cumulative consistency proofs in the new ledger. A separately retained checkpoint detects complete-tail rollback. A directory with no external anchor can prove internal consistency while still representing an older history.

## Q14. Why does the verifier report an index separately from seq_no?

I treat the event sequence field as untrusted input. A bit flip in seq_no can turn a small number into a huge integer. The verification position identifies the first corrupted record independently; the record's claimed sequence remains available as diagnostic evidence.

## Q15. How do non-power-of-two Merkle proofs work?

I split at the largest power of two strictly less than the subtree size. Inclusion proofs mirror that recursion, while consistency proofs use the RFC subproof construction. The finite campaign checks all prefix pairs through 130 leaves, as well as modified leaf and proof rejection.

## Q16. Are these ordinary public transparency-log tiles?

I use RFC 9162 domain separation with a declared BLAKE3 or BLAKE2b profile and static tile storage. Hash choice, header and serialization belong to this protocol profile. Public log interoperability requires agreement on those details; a similarly named tile layout alone does not establish compatibility.

## Q17. Why reject a hand-written FIPS-sized approximation?

I use the tested ML-DSA-65 implementation with standard encodings and exact key/signature sizes. ML-DSA-65 uses a 48-byte challenge field; an earlier requested 32-byte construction would not be FIPS 204 encoding. Matching 3,309 bytes alone would provide no conformance evidence.

I now validate canonical response and hint encodings independently, perform backend work on normalized bytes, and preserve the original validity flag. I never authorize a repaired signature. First/last corruption timing observations and frozen independent known answers are retained with the release evidence; neither constitutes implementation certification.

## Q18. What does the lattice forgery demonstration reject?

I alter the first packed response coefficient at offset 48 so its decoded magnitude violates the response norm bound, then require the actual signature verifier to reject it. I expose that concrete encoding and bound. I do not invent a polynomial residual from an opaque verifier response.

## Q19. Does DSSE establish the signer's identity?

I bind payload type and bytes with DSSE pre-authentication encoding and sign the statement. Verification against a bundled public key checks internal integrity. Establishing identity requires a trusted pinned key or a separately validated trust chain; a replaceable bundle and key do not establish external authenticity.

## Q20. What do OmniBOR identifiers attest?

I hash the Git blob header and contents, and construct sorted input manifests. This binds bytes and dependency inputs deterministically. It does not prove that an artifact was built safely, that a dependency was authorized or that a signer is trustworthy.

## Q21. Does ddmin always find the unique smallest cause in logarithmic time?

I require a failing initial schedule and memoize oracle subsets. The result is 1-minimal: removing any one retained fault removes the demonstrated failure. There can be several minimal causes, the globally smallest set is not guaranteed, and worst-case oracle cost is quadratic rather than generally logarithmic.

## Q22. How does the WAL case avoid misleading reruns?

I recreate sockets and journal state for each oracle evaluation and synchronize durable writes. The compound failure requires EAGAIN at the socket boundary and ENOSPC at the fallback journal boundary. I record the evaluated subsets and repeat the minimal schedule twenty times. This case-specific oracle models acknowledgement without durable commit.

## Q23. Are the invariants a machine-checked mathematical proof?

I execute finite seeded checks of serialization, proof algorithms, ratchet mutations, minimality and permutation fidelity. Five hundred seeds improve structural coverage and retain reproducibility. They do not prove correctness for unbounded inputs, all concurrent schedules or every adversarial construction.

The ninth preflight gate checks explicit Python annotations, documentation and parsed Rust syntax. It discloses dynamic annotation references rather than presenting presence checks as sound type inference, dead-code elimination or a proof that every numeric literal is unnecessary.

## Q24. What does quantum healing actually prove?

I parse a supported OpenQASM subset, treat terminal measurement as outside the coherent unitary, and exhaustively score small valid hardware embeddings. I compare actual matrices under the physical-basis permutation. The default calibration is explicitly synthetic; the IBM loader accepts supplied snapshots with units and directed couplers. A unitary fidelity of one establishes logical equivalence, not physical execution fidelity. Embedding enumeration is combinatorial and dense matrices scale exponentially.

## Q25. How can a reviewer trust the demo and platform claims?

I serve immutable dashboard data with loopback-only routing, Host/Origin checks and bounded request bodies. Offline HTML displays recorded execution; the server reruns each attack against the signed bundle. Reports distinguish actual local execution, historical baseline results and configured remote CI jobs. I preserve pre-existing sibling projects and cannot claim that the parent directory is empty.
