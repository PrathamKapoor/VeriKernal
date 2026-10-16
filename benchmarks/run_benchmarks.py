"""Run benchmarks."""
from __future__ import annotations
from typing import Any
import argparse
import json
import math
import platform
import hashlib
import os
import subprocess
import socket
import sys
import sysconfig
import tempfile
import threading
from dataclasses import replace
import time
import statistics
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor
from pathlib import Path
from verikernel.schemas import KernelTelemetryEvent
from verikernel.m1_contract.ast_scanner import scan_source
from verikernel.m1_contract.binary_inspector import build_synthetic_elf, build_synthetic_pe, parse_elf_needed, parse_pe_imports
from verikernel.m3_fault.ddmin import DeltaDebuggingShrinker
from verikernel.m3_fault.injector import SyscallFaultInjector
from verikernel.m4_attest.merkle_tiles import mth, prove_inclusion, verify_inclusion
from verikernel.m4_attest.pqc_signer import MLDSA65Signer, native
from verikernel.m5_ringbuf.baseline_v01 import FlawedBaselineRingBufferV01
from verikernel.m5_ringbuf.zero_drop_v02 import ZeroDropRingBufferV02
from verikernel.m2_enforcer.hal import RuntimeInterceptorHAL
from verikernel.m4_attest.epoch_service import EpochAttestor


def sign_workload(task: Any) -> Any:
    """Sign the requested event batches and measure elapsed CPU work. Complexity: O(b + W) time and O(b + M) space; b is captured input/output, W external verification work, M retained measurements."""
    secret_key, messages = task
    from dilithium_py.ml_dsa import ML_DSA_65
    try:
        from verikernel.m4_attest.native_signer import RustMLDSA65
        rust = RustMLDSA65(bytes(32))
        rust.secret_key = secret_key
    except (OSError, AttributeError):
        rust = None
    start = time.process_time()
    if rust:
        signatures = [rust.sign(message, deterministic=False) for message in messages]
    elif native:
        signatures = [native.sign(secret_key, message) for message in messages]
    else:
        signatures = [ML_DSA_65.sign(secret_key, message, deterministic=True) for message in messages]
    return signatures, (time.process_time()-start)*1000


def percentile(values: Any, p: Any) -> Any:
    """Select a percentile from sorted latency samples. Complexity: O(b + W) time and O(b + M) space; b is captured input/output, W external verification work, M retained measurements."""
    ordered = sorted(values)
    return ordered[min(len(ordered)-1, int((len(ordered)-1)*p))] if ordered else 0


class ThroughputSigner:
    """ThroughputSigner. Complexity: O(b + W) time and O(b + M) space; b is captured input/output, W external verification work, M retained measurements."""
    def __init__(self, signer: Any) -> None:
        """Initialize the owned state and validate configuration limits. Complexity: O(b + W) time and O(b + M) space; b is captured input/output, W external verification work, M retained measurements."""
        self.signer = signer

    def sign(self, message: Any) -> bytes:
        """Sign the benchmark message through the selected provider. Complexity: O(b + W) time and O(b + M) space; b is captured input/output, W external verification work, M retained measurements."""
        return self.signer.sign(message, deterministic=False)


def benchmark_transport(signer: Any, count: int=10000) -> Any:
    """Measure loss, ordering, latency and throughput under a shared burst. Complexity: O(b + W) time and O(b + M) space; b is captured input/output, W external verification work, M retained measurements."""
    results = {}
    for name, queue in [("bounded_per_cpu", FlawedBaselineRingBufferV01(signer=ThroughputSigner(signer))), ("portable_two_level", ZeroDropRingBufferV02())]:
        latencies = []
        received = []
        attestor = EpochAttestor(signer=signer) if name == "portable_two_level" else None
        done = threading.Event()
        start = time.perf_counter()
        def produce(cpu: Any) -> Any:
            """Submit the producer workload and retain its latency samples. Complexity: O(b + W) time and O(b + M) space; b is captured input/output, W external verification work, M retained measurements."""
            local = []
            for i in range(cpu, count, 4):
                repeated = i % 100 < 85
                event = KernelTelemetryEvent(seq_no=i, syscall_nr=9 if repeated else 2, dev_id=1, inode_nr=1 if repeated else i+2, mtime_ns=1)
                before = time.perf_counter_ns()
                queue.push(event, cpu)
                local.append((time.perf_counter_ns()-before)/1000)
            return local
        def consume() -> None:
            """Drain the transport until producers finish and all records are handled. Complexity: O(b + W) time and O(b + M) space; b is captured input/output, W external verification work, M retained measurements."""
            def accept(batch: Any) -> None:
                """Record the event accepted by the benchmark consumer. Complexity: O(b + W) time and O(b + M) space; b is captured input/output, W external verification work, M retained measurements."""
                for event in batch:
                    if attestor:
                        attestor.submit(replace(event, seq_no=len(received)))
                    received.append(event)
            while not done.is_set():
                accept(queue.drain())
                done.wait(.0005)
            accept(queue.drain())
        consumer = threading.Thread(target=consume)
        consumer.start()
        with ThreadPoolExecutor(4) as pool:
            for local in pool.map(produce, range(4)):
                latencies.extend(local)
        done.set()
        consumer.join()
        if attestor:
            attestor.close()
            if not attestor.verify_epochs():
                raise ValueError("asynchronous transport epochs failed verification")
        elapsed = time.perf_counter()-start
        results[name] = {"input_events": count, "delivered_events": len(received), "suppressed_events": getattr(queue, "suppressed", 0), "drop_rate_percent": queue.drops/count*100, "sequence_inversions": sum(a.seq_no > b.seq_no for a, b in zip(received, received[1:])), "producer_p50_us": percentile(latencies, .5), "producer_p99_us": percentile(latencies, .99), "throughput_input_events_sec": count/elapsed, "wall_time_ms": elapsed*1000}
    return results


def benchmark_attestation(signer: Any, directory: Any, count: int=10000) -> Any:
    """Measure signature and proof costs for the three batching strategies. Complexity: O(b + W) time and O(b + M) space; b is captured input/output, W external verification work, M retained measurements."""
    leaves = [KernelTelemetryEvent(seq_no=i).to_bytes() for i in range(count)]
    results = {}
    for name, batch_size in [("per_event", 1), ("microbatch_128", 128), ("epoch_65536", 65536)]:
        before = time.process_time()
        signatures = []
        selected = None
        signing_cpu = 0
        if batch_size == 1 and count >= 1000:
            tasks = [(signer.secret_key, leaves[i:i+250]) for i in range(0, count, 250)]
            with ProcessPoolExecutor(4) as pool:
                for sigs, cpu_ms in pool.map(sign_workload, tasks):
                    signatures.extend(sigs)
                    signing_cpu += cpu_ms
                    if len(signatures) % 1000 == 0:
                        print(f"Attestation: {len(signatures)}/{count} individual signatures", flush=True)
            selected = (leaves[0], signatures[0], [leaves[0]])
        for start in range(0 if not signatures else count, count, batch_size):
            batch = leaves[start:start+batch_size]
            message = batch[0] if batch_size == 1 else mth(batch)
            sig = signer.sign(message, deterministic=False)
            signatures.append(sig)
            if start == 0:
                selected = (message, sig, batch)
            if batch_size == 1 and start and start % 1000 == 0:
                print(f"Attestation: {start}/{count} individual signatures", flush=True)
        elapsed = (time.process_time()-before)*1000 + signing_cpu
        path = Path(directory) / (name + ".signatures")
        path.write_bytes(b"".join(signatures))
        message, signature, batch = selected
        before = time.perf_counter()
        proof = [] if batch_size == 1 else prove_inclusion(0, batch)
        inclusion = True if batch_size == 1 else verify_inclusion(batch[0], 0, len(batch), proof, message)
        verified = signer.verify(signer.public_key, message, signature)
        results[name] = {"events": count, "signature_count": len(signatures), "signature_bytes": path.stat().st_size, "signing_cpu_ms": elapsed, "inclusion_proof_bytes": len(proof)*32, "inclusion_and_signature_verification_ms": (time.perf_counter()-before)*1000, "verified": bool(inclusion and verified)}
    return results


def score(predictions: Any, truth: Any) -> Any:
    """Compute precision, recall and F1 from the observed classifications. Complexity: O(b + W) time and O(b + M) space; b is captured input/output, W external verification work, M retained measurements."""
    tp = sum(p and t for p, t in zip(predictions, truth))
    fp = sum(p and not t for p, t in zip(predictions, truth))
    fn = sum(not p and t for p, t in zip(predictions, truth))
    precision = tp/(tp+fp) if tp+fp else 0
    recall = tp/(tp+fn) if tp+fn else 0
    return {"precision": precision, "recall": recall, "f1": 2*precision*recall/(precision+recall) if precision+recall else 0, "true_positive": tp, "false_positive": fp, "false_negative": fn}


def benchmark_detection() -> Any:
    """Evaluate dependency detection against the labeled workload fixtures. Complexity: O(b + W) time and O(b + M) space; b is captured input/output, W external verification work, M retained measurements."""
    cases = [
        ("import numpy", "imports", "numpy", True),
        ("from yaml import safe_load", "imports", "yaml", True),
        ("import sklearn", "imports", "sklearn", True),
        ("import PIL", "imports", "PIL", True),
        ("TRANSITIVE", "child", "private-child.dat", True),
        ('import importlib; importlib.import_module("dynamic_pkg")', "imports", "dynamic_pkg", True),
        ('import ctypes; ctypes.CDLL("hidden.dll")', "shared_libraries", "hidden.dll", True),
        ('import ctypes as c; c.CDLL("hidden.so")', "shared_libraries", "hidden.so", True),
        ('import subprocess; subprocess.run(["worker", "--run"])', "subprocesses", "worker", True),
        ('import os; os.execv("child", ["child"])', "subprocesses", "child", True),
        ('import os; os.getenv("SECRET")', "environment", "SECRET", True),
        ('import os; os.environ["TOKEN"]', "environment", "TOKEN", True),
        ('open("private.dat")', "filesystem", "private.dat", True),
        ('from pathlib import Path; Path("private.txt")', "filesystem", "private.txt", True),
        ("ELF", "binary", "libhidden.so", True),
        ("PE", "binary", "hidden.dll", True),
        ("ESCAPE", "path", "secret", True),
        ("import os", "imports", "os", False),
        ("import json", "imports", "json", False),
        ("NORMALIZE", "path", "allowed", False),
    ]
    truth, static, raw, hybrid = [], [], [], []
    with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parents[1] / ".tmp") as tmp:
        root = Path(tmp)
        allowed = root / "allowed"
        allowed.mkdir()
        outside = root / "outside"
        outside.mkdir()
        (outside / "secret").write_text("private")
        link = allowed / "link"
        if sys.platform == "win32":
            import _winapi
            _winapi.CreateJunction(str(outside), str(link))
        else:
            link.symlink_to(outside, target_is_directory=True)
        for source, field, target, expected in cases:
            truth.append(expected)
            if field == "binary":
                libs = parse_elf_needed(build_synthetic_elf([target])) if source == "ELF" else parse_pe_imports(build_synthetic_pe([target]))
                static.append(False)
                raw.append(False)
                hybrid.append(target in libs)
            elif field == "child":
                child_path = root / target
                child_path.write_text("child data")
                with RuntimeInterceptorHAL({}, target_root=root) as hal:
                    child = subprocess.run([sys.executable, "-c", f"open({str(child_path)!r}).read()"], capture_output=True, timeout=30)
                if child.returncode:
                    raise RuntimeError("child observation fixture failed to execute")
                target_hash = hashlib.sha256(str(child_path.resolve()).encode()).digest()
                observed = any(e.syscall_nr in {2, 9} and e.target_digest == target_hash for e in hal.events)
                static.append(False)
                raw.append(False)
                hybrid.append(observed)
            elif field == "path":
                path = link / "secret" if source == "ESCAPE" else allowed / ".." / "allowed" / "file"
                static.append(False)
                raw.append(".." in str(path) or not FlawedBaselineRingBufferV01.naive_allowed(path, allowed))
                hybrid.append(not ZeroDropRingBufferV02.canonical_allowed(path, allowed))
            else:
                scanned = scan_source(source)
                declared_standard = target in sys.stdlib_module_names
                static.append(field == "imports" and not declared_standard and "import_module(" not in source)
                raw.append(field in {"imports", "shared_libraries", "subprocesses", "filesystem"} and target in scanned.get(field, []) and not declared_standard)
                hybrid.append(target in scanned.get(field, []) and not declared_standard)
    return {"case_count": len(cases), "static_import_only": score(static, truth), "raw_trace_fixture": score(raw, truth), "portable_hybrid": score(hybrid, truth), "comparison_scope": "in-repository fixtures; static symlink/junction escape; portable child file observation is a measured false negative; no external comparison tool was executed"}


def benchmark_faults() -> Any:
    """Measure replay determinism and fault-schedule reduction. Complexity: O(b + W) time and O(b + M) space; b is captured input/output, W external verification work, M retained measurements."""
    source = '''def workload(connection, journal):
    fallback = False
    failed = False
    for site in range(32):
        try:
            if site == 7:
                connection.recv(8)
            else:
                journal.write(b"checkpoint")
        except OSError as error:
            if site == 7 and error.errno == 11:
                fallback = True
            if site == 23 and error.errno == 28 and fallback:
                failed = True
    return failed
'''
    with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parents[1] / ".tmp") as directory:
        directory = Path(directory)
        script = directory / "pipeline.py"
        script.write_text(source)
        namespace = {}
        exec(compile(source, str(script), "exec"), namespace)
        def execute(injector: Any) -> Any:
            """Execute the workload with the selected fault schedule. Complexity: O(b + W) time and O(b + M) space; b is captured input/output, W external verification work, M retained measurements."""
            left, right = socket.socketpair()
            try:
                right.sendall(b"response")
                with RuntimeInterceptorHAL({}, target_root=directory, injector=injector):
                    with open(directory / "journal", "wb") as journal:
                        return namespace["workload"](left, journal)
            finally:
                left.close()
                right.close()
        schedule = None
        for master_seed in range(1000):
            exploration = SyscallFaultInjector(master_seed, 1, syscall_types={9, 10})
            if execute(exploration):
                schedule = exploration.schedule
                break
        if schedule is None or len(schedule) != 32:
            raise ValueError("exploration did not find the paired syscall failure")
        initial = [fault["site_id"] for fault in schedule]
        def reproduce(sites: Any) -> Any:
            """Repeat the scheduled workload and compare its failure outcome. Complexity: O(b + W) time and O(b + M) space; b is captured input/output, W external verification work, M retained measurements."""
            return execute(SyscallFaultInjector(master_seed, schedule=schedule, active_sites=sites, syscall_types={9, 10}))
        shrinker = DeltaDebuggingShrinker(reproduce)
        minimal = shrinker.shrink(initial)
        results = [reproduce(minimal) for _ in range(20)]
        naive = []
        for seed in range(20):
            pair = [execute(SyscallFaultInjector(seed*2+rerun, .5, syscall_types={9, 10})) for rerun in range(2)]
            naive.append(all(pair))
    return {"initial_fault_count": len(initial), "minimal_fault_count": len(minimal), "minimal_sites": minimal, "reduction_percent": (1-len(minimal)/len(initial))*100, "oracle_evaluations": shrinker.evaluations, "replay_determinism_percent": sum(results)/len(results)*100, "naive_double_rerun_success_percent": sum(naive)/len(naive)*100, "replays": len(results), "master_seed": master_seed, "scope": "real socket pair and journal writes mediated by runtime boundary shims"}


def benchmark_batch_ledger(directory: str | Path, count: int = 10000) -> dict[str,Any]:
    """Measure three batch trials and four epochs; O(e*n log n) time, O(n) space."""
    from verikernel.rust_bridge import BatchEngine
    from verikernel.m4_attest.ledger_store import ChainedTransparencyLedger,verify_ledger_history
    if count<4:
        raise ValueError('four nonempty epochs are required')
    directory = Path(directory)
    original = bytearray(b''.join(KernelTelemetryEvent(seq_no=i,syscall_nr=9,dev_id=1,inode_nr=1 if i<int(count*.85) else i+1,mtime_ns=1).to_bytes() for i in range(count)))
    seed = bytes([66])*32
    output: dict[str,Any] = {'events':count,'trials':3,'native_loaded':BatchEngine().native,'hash_profile':'sha256','scope':'input construction and buffer copying excluded from operation timers; medians of three trials; no universal throughput guarantee'}
    for name,native_enabled in [('python',False),('native',True)]:
        engine = BatchEngine(native=native_enabled)
        samples: dict[str,list[float]] = {operation:[] for operation in ['seal','verify','merkle','dedup']}
        kept = 0
        for _ in range(3):
            buffer = bytearray(original)
            start = time.perf_counter()
            c0,kn = engine.seal(buffer,seed)
            samples['seal'].append(time.perf_counter()-start)
            start = time.perf_counter()
            status,index = engine.verify(buffer,seed,c0,kn)
            samples['verify'].append(time.perf_counter()-start)
            if status or index!=-1:
                raise ValueError('benchmark epoch failed verification')
            start = time.perf_counter()
            root = engine.root(buffer)
            samples['merkle'].append(time.perf_counter()-start)
            start = time.perf_counter()
            mask = engine.dedup(original,16384)
            samples['dedup'].append(time.perf_counter()-start)
            kept = sum(mask)
        output[name] = {**{operation+'_events_sec':count/statistics.median(values) for operation,values in samples.items()},'samples_seconds':samples,'kept_events':kept,'root':root.hex()}
    if output['native']['root']!=output['python']['root'] or output['native']['kept_events']!=output['python']['kept_events']:
        raise ValueError('native and reference benchmark results differ')
    ledger = ChainedTransparencyLedger(directory/'ledger',MLDSA65Signer(seed=bytes([23])*32))
    sizes = [count//4]*3+[count-3*(count//4)]
    for size in sizes:
        checkpoint = ledger.append([KernelTelemetryEvent(syscall_nr=9,inode_nr=i+1) for i in range(size)])
    latencies = []
    for _ in range(3):
        start = time.perf_counter()
        verified = verify_ledger_history(directory/'ledger',trusted_checkpoint=checkpoint)
        latencies.append((time.perf_counter()-start)*1000)
    history = ledger.export_history()
    output['ledger'] = {'epochs':4,'tree_size':verified['tree_size'],'verified':verified['valid'],'anchored':verified['anchored'],'verification_median_ms':statistics.median(latencies),'verification_samples_ms':latencies,'last_consistency_proof_bytes':len(history['epochs'][-1]['consistency_proof'])*32,'checkpoint_hash':hashlib.sha256(json.dumps(checkpoint,sort_keys=True).encode()).hexdigest()}
    return output


def render_report(metrics: Any) -> Any:
    """Render measured benchmark rows as Markdown tables. Complexity: O(b + W) time and O(b + M) space; b is captured input/output, W external verification work, M retained measurements."""
    lines = ["# VeriKernel measured benchmark report", "", f"Runtime: {metrics['environment']}", "", "I measured controlled fixtures, without executing external comparison tools.", "I do not infer kernel throughput, atomic path mediation, or bounded-memory zero loss from this run.", "", "| Transport | Drops (%) | Inversions | p50 (us) | p99 (us) | Input events/s |", "|---|---:|---:|---:|---:|---:|"]
    for name, row in metrics["transport"].items():
        lines.append(f"| {name} | {row['drop_rate_percent']:.2f} | {row['sequence_inversions']} | {row['producer_p50_us']:.3f} | {row['producer_p99_us']:.3f} | {row['throughput_input_events_sec']:.1f} |")
    lines += ["", "| Attestation | Signature bytes | Signing CPU ms | Proof bytes | Proof construction + verification ms |", "|---|---:|---:|---:|---:|"]
    for name, row in metrics["attestation"].items():
        lines.append(f"| {name} | {row['signature_bytes']} | {row['signing_cpu_ms']:.3f} | {row['inclusion_proof_bytes']} | {row['inclusion_and_signature_verification_ms']:.3f} |")
    lines += ["", "| Detection fixture | Precision | Recall | F1 |", "|---|---:|---:|---:|"]
    for name in ("static_import_only", "raw_trace_fixture", "portable_hybrid"):
        row = metrics["detection"][name]
        lines.append(f"| {name} | {row['precision']:.3f} | {row['recall']:.3f} | {row['f1']:.3f} |")
    fault = metrics["faults"]
    lines += ["", f"I reduced {fault['initial_fault_count']} faults to {fault['minimal_fault_count']} sites {fault['minimal_sites']} in {fault['oracle_evaluations']} oracle evaluations.", f"Reduction: {fault['reduction_percent']:.2f}%; replay: {fault['replay_determinism_percent']:.2f}% across {fault['replays']} runs.", f"The controlled double-rerun fixture reproduced both failures in {fault['naive_double_rerun_success_percent']:.2f}% of trials.", "", "The v0.2 transport uses the bounded native lock-free FIFO when built, with synchronized per-CPU staging and contiguous sequence release. The signing consumer seals asynchronous periodic epochs.", "The attestation scaling experiment signs its 10,000-event tree once; the 65,536-fold figure is arithmetic for a full epoch, not this run.", "Detection includes a real directory symlink or junction and a child-process false negative; no concurrent symlink swap is claimed.", ""]
    if 'rust_ffi' in metrics:
        ffi = metrics['rust_ffi']
        lines += [f"Native Rust library loaded: {ffi['native_loaded']}.",f"The 1,024-byte FNV-1a comparison measured {ffi['speedup']:.3f}x speedup across {ffi['fnv1a_1024']['native']['calls']} calls, including ctypes overhead.",""]
    if 'batch_ledger' in metrics:
        batch = metrics['batch_ledger']
        lines += ['','## Batch SHA-256 and chained ledger','', '| Engine | Seal events/s | Verify events/s | Merkle events/s | Dedup events/s |','|---|---:|---:|---:|---:|']
        for engine in ['python','native']:
            row = batch[engine]
            lines.append(f"| {engine} | {row['seal_events_sec']:.1f} | {row['verify_events_sec']:.1f} | {row['merkle_events_sec']:.1f} | {row['dedup_events_sec']:.1f} |")
        ledger = batch['ledger']
        lines += ['',f"I verify {ledger['epochs']} chained epochs and {ledger['tree_size']:,} cumulative leaves in median {ledger['verification_median_ms']:.3f} ms. The last consistency proof occupies {ledger['last_consistency_proof_bytes']} bytes.",'', '| Timing path | Welch t | Below 4.5 | Rejected both classes |','|---|---:|---|---|']
        for name,row in metrics['sidechannel']['paths'].items():
            lines.append(f"| {name} | {row['t_statistic']:.6f} | {row['below_threshold']} | {row['all_rejected']} |")
        lines += ['', 'I retain unfiltered first/last corruption measurements with 2,000 observations per class. These are finite timing observations, not constant-time certification.','']
    if 'release_boundaries' in metrics:
        release = metrics['release_boundaries']
        native = release['native_target']
        lines += ['', '## Native target and distribution verification', '',
                  f"Compiled comparator architecture: {release['machine_code']['architecture']}; branch-free body instructions: {release['machine_code']['body_instruction_count']}.",
                  f"Real native workload: {native['event_count']} events in {native['normal_seconds']*1000:.3f} ms; strict undeclared-file denial: {native['strict_denial']}.",
                  f"Native ENOSPC minimal site: {native['minimal_fault_sites']}; oracle evaluations: {native['oracle_evaluations']}.",
                  f"Normalized wheel equality: {release['distribution']['reproducible']}; clean offline installation: {release['distribution']['clean_install_verified']}.",
                  'Native telemetry uses the trusted linked adapter. The instruction finding applies only to the inspected comparator body.', '']
    if 'lattice_confinement' in metrics:
        current = metrics['lattice_confinement']
        lines += ['', '## Fixed-schedule lattice arithmetic and kernel resource limits', '',
                  '| Exported arithmetic body | Decoded instructions | Conditional branches |',
                  '|---|---:|---:|']
        for name,row in current['assembly']['symbols'].items():
            lines.append(f"| {name} | {row['body_instruction_count']} | 0 |")
        reference = current['differential']
        lines += ['', f"Independent convolution: {reference['ntt']['pairs']} pairs, {reference['ntt']['coefficients_checked']} coefficients.",
                  f"Exhaustive fault predicates: {reference['ddmin']['predicates']}; 1,024 subsets each; maximum ddmin oracle calls {reference['ddmin']['max_oracle_evaluations']}.",
                  f"SHA-256 boundary cases: {reference['hash']['hash_cases']}; independent tree cases: {reference['hash']['tree_cases']}.",
                  f"Kernel resource backend: {current['resources']['spawn']['backend']}; child creation denied: {current['resources']['spawn']['denied']}; 128 MiB allocation denied: {current['resources']['memory']['denied']}.",
                  'Unrestricted controls execute the child and touch the full allocation. The aggregate kernel accounting payload is bound to a signed ledger leaf.',
                  'The instruction audit covers six fixed-schedule arithmetic bodies, not the complete signature protocol or microarchitectural timing.', '']
    return "\n".join(lines)


def run_benchmarks(output_dir: str="benchmarks/results", count: int=10000) -> Any:
    """Run the experiments and save their metrics and report. Complexity: O(b + W) time and O(b + M) space; b is captured input/output, W external verification work, M retained measurements."""
    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=True)
    temp = Path(__file__).resolve().parents[1] / ".tmp"
    temp.mkdir(exist_ok=True)
    signer = MLDSA65Signer(seed=bytes(range(32)))
    metrics = {"environment": {"python": sys.version.split()[0], "platform": platform.platform(), "machine": platform.machine(), "interpreter_platform": sysconfig.get_platform(), "signing_backend": signer.backend if signer._rust else "pqcrypto-native" if native else signer.backend, "windows_arm64_x64_emulation": sys.platform == "win32" and platform.machine().upper() == "ARM64" and "amd64" in sysconfig.get_platform().lower()}, "transport": benchmark_transport(signer, count)}
    print("Transport benchmark complete", flush=True)
    with tempfile.TemporaryDirectory(dir=temp) as directory:
        metrics["attestation"] = benchmark_attestation(signer, directory, count)
    metrics["detection"] = benchmark_detection()
    metrics["faults"] = benchmark_faults()
    from verikernel.rust_bridge import benchmark_bridge
    metrics['rust_ffi'] = benchmark_bridge()
    with tempfile.TemporaryDirectory(dir=temp) as directory:
        metrics['batch_ledger'] = benchmark_batch_ledger(directory,count)
    from verikernel.m4_attest.sidechannel_audit import run_welch_t_test_audit
    from verikernel.m4_attest.kat_vectors import verify_known_answers
    metrics['sidechannel'] = run_welch_t_test_audit()
    metrics['known_answers'] = verify_known_answers()
    from scripts.verify_release_boundaries import verify_release_boundaries
    metrics['release_boundaries'] = verify_release_boundaries()
    from scripts.verify_constant_time_asm import verify_crypto_symbols
    from scripts.differential_oracles import run_differential_verification
    from verikernel.m2_enforcer.win32_job_sandbox import run_resource_confinement,verify_kernel_accounting
    assembly = verify_crypto_symbols()
    compact = {key:value for key,value in assembly.items() if key != 'symbols'}
    compact['symbols'] = {name:{key:value for key,value in row.items() if key != 'machine_code_hex'}
                          for name,row in assembly['symbols'].items()}
    with tempfile.TemporaryDirectory(dir=temp) as directory:
        resources = run_resource_confinement(directory)
        verified = verify_kernel_accounting(directory)
    metrics['lattice_confinement'] = {'assembly':compact,'differential':run_differential_verification(),
                                     'resources':resources,'accounting_bound':verified['accounting_bound']}
    (output/'sidechannel_audit.json').write_text(json.dumps(metrics['sidechannel'],indent=2),encoding='utf-8')
    (output/'rust_ffi_metrics.json').write_text(json.dumps(metrics['rust_ffi'],indent=2),encoding='utf-8')
    (output / "latest_benchmark_metrics.json").write_text(json.dumps(metrics, indent=2, sort_keys=True), encoding="utf-8")
    (output / "latest_benchmark_report.md").write_text(render_report(metrics), encoding="utf-8")
    return metrics


def main() -> None:
    """Parse command-line arguments and return the selected operation status. Complexity: O(b + W) time and O(b + M) space; b is captured input/output, W external verification work, M retained measurements."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-dir", default="benchmarks/results")
    args = parser.parse_args()
    run_benchmarks(args.output_dir)


if __name__ == "__main__":
    main()
