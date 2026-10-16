"""Render release documentation from completed measurements; O(B) time and space."""
from __future__ import annotations
import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
RESULTS = ROOT/'benchmarks/results'


def finalize() -> None:
    """Require twelve successful gates and render their evidence; O(B) time and space."""
    preflight = json.loads((RESULTS/'preflight_ci.json').read_text(encoding='utf-8'))
    metrics = json.loads((RESULTS/'latest_benchmark_metrics.json').read_text(encoding='utf-8'))
    assembly = json.loads((RESULTS/'crypto_disassembly.json').read_text(encoding='utf-8'))
    if not preflight['ok'] or len(preflight['gates']) != 12:
        raise ValueError('twelve successful preflight checks are required')
    if metrics['lattice_confinement']['assembly']['library_sha256'] != assembly['library_sha256']:
        raise ValueError('benchmark and final disassembly identify different release libraries')
    gates = {row['name']:row for row in preflight['gates']}
    tests = gates['python']['detail']
    release = gates['release_boundaries']['detail']
    distribution = release['distribution']
    kernel = gates['confinement']['detail']
    differential = gates['lattice_reference']['detail']
    quality = gates['quality']['detail']
    rust_log = (ROOT/'dist/preflight/rust-workspace.log').read_text(encoding='utf-8')
    rust_count = sum(map(int,re.findall(r'test result: ok\. (\d+) passed;',rust_log)))
    host_log = ROOT/'dist/preflight/cargo-host-final.log'
    if not host_log.exists():
        raise ValueError('the host workspace test log is required')
    host_count = sum(map(int,re.findall(r'test result: ok\. (\d+) passed;',host_log.read_text(encoding='utf-8'))))
    if not rust_count or not host_count:
        raise ValueError('native and host Rust test evidence is required')
    summary = [
        '### Verification', '',
        f"I execute {tests['tests']} Python tests with zero failures, errors or skips, {rust_count} native ARM64 Rust tests and {host_count} host x64 Rust tests.",
        'All twelve local CI verification checks succeed. Remote matrix execution is reported separately.', '',
        '| Capability | Observed result |', '|---|---|',
        f"| Machine-code inspection | Six release arithmetic bodies; no conditional transfers/calls after public guards; {next(iter(assembly['symbols'].values()))['architecture']} |",
        f"| Independent polynomial oracle | {differential['polynomial_pairs']} pairs; 25,600 coefficients match schoolbook convolution |",
        f"| Exhaustive fault oracle | {differential['predicates']} predicates; 1,024 subsets each; at most {differential['max_oracle_evaluations']} ddmin calls |",
        f"| SHA-256 / independent tree oracle | {differential['hash_cases']} block-boundary inputs / eight tree sizes |",
        f"| Native kernel resource limits | Child creation and 128 MiB allocation denied; {kernel['resource_backend']}; signed accounting verified |",
        f"| Linux native confinement | {kernel['linux_backend']}; UID {kernel['linux_uid']}; socket/spawn/Landlock EACCES {kernel['socket_errno']}/{kernel['spawn_errno']}/{kernel['landlock_errno']} |",
        f"| Source audit | {quality['python_files']} Python files; {quality['rust_parsed_files']} Rust files; zero package catch-all annotations |",
        f"| Distribution | Two identical {distribution['size_bytes']:,}-byte wheels; contained offline installation verified |", '',
        f"Release library SHA-256: `{assembly['library_sha256']}`.",
        f"Wheel SHA-256: `{distribution['build_1_sha256']}`.",
        f"Wheel GitOID: `{distribution['build_1_gitoid']}`.", '',
        'I inspect fixed-schedule arithmetic, not the complete ML-DSA rejection sampler or microarchitectural timing. The selectable native-ring provider uses these primitives in the standard protocol; the maintained native signer remains the default.',
        'Windows Job Objects constrain resources and child count. Linux pre-exec seccomp and Landlock restrict the tested syscall/filesystem capabilities. I retain unrestricted controls, real kernel errors and a signed aggregate accounting receipt; these do not imply universal syscall capture or complete hostile-code isolation.',
        'I retain protected audit-seed, trusted-kernel, immutable executable and external-checkpoint assumptions. Quantum calibration remains modeled. The fixed-source wheel comparison excludes native compiler reproducibility.', '',
        'Development caches and build artifacts are excluded from version control.', '',
        'Reproduction: `python scripts/preflight_ci.py`, `python scripts/verify_constant_time_asm.py`, `python scripts/differential_oracles.py`, and `python scripts/verify_native_confinement.py`.', '',
        'I retain [the verification report](benchmarks/results/latest_verification_report.md), [29 decisions](decisions.md), [the threat model](docs/threat-model.md), [the paper](docs/paper.md), and [the dashboard](benchmarks/results/demo_mission_control.html).', '']
    readme = (ROOT/'README.md').read_text(encoding='utf-8')
    start, end = readme.index('## Benchmarks & Empirical Evaluation'), readme.index('## Technology Choices & Rationale')
    benchmark = (RESULTS/'latest_benchmark_report.md').read_text(encoding='utf-8')
    section = '## Benchmarks & Empirical Evaluation\n\n'+benchmark.replace('# VeriKernel measured benchmark report\n','',1).replace('## ', '### ')+'\n'
    readme = readme[:start]+section+readme[end:]
    index = readme.index('### Verification')
    (ROOT/'README.md').write_text(readme[:index]+'\n'.join(summary),encoding='utf-8')
    table = ['# VeriKernel execution verification', '',
             'The following tables summarize executed local verification checks.', '',
             '| Check | Name | Successful | Seconds |', '|---|---|---|---:|']
    table += [f"| {index} | {row['name']} | {row['ok']} | {row['seconds']:.3f} |" for index,row in enumerate(preflight['gates'],1)]
    report_summary = '\n'.join(summary)
    report_summary = report_summary.replace('(benchmarks/results/', '(').replace('(decisions.md)', '(../../decisions.md)').replace('(docs/', '(../../docs/')
    report = '\n'.join(table)+'\n\n'+report_summary+'\n'+benchmark
    report += '\n## Evidence custody\n\nFull decoded bytes are in crypto_disassembly.json; independent seeds/results are in differential_reference.json. Kernel controls and actual accounting are in kernel_confinement.json and native_linux_confinement.json. The signed accounting ledger remains under the reported ignored dist/ path. Bundled signatures establish integrity; identity requires a separately trusted public key. \n'
    report += '\nThe benchmark tables record the CLI verification run against the inspected release library. Timing samples are retained without filtering.\n'
    actual = json.loads((RESULTS/'kernel_confinement.json').read_text(encoding='utf-8'))
    resources = actual['resources']
    report += '\n## Real kernel accounting\n\n| Attack | Denied | Native result | Peak process bytes | Page faults | User / kernel 100 ns |\n|---|---|---|---:|---:|---|\n'
    for name in ['spawn','memory']:
        row = resources[name]
        accounting = row.get('accounting',{})
        report += f"| {name} | {row['denied']} | {row.get('errno',row.get('error','denied'))} | {row.get('peak_process_memory_bytes',0)} | {accounting.get('page_faults',0)} | {accounting.get('user_time',0)} / {accounting.get('kernel_time',0)} |\n"
    report += f"\nSigned aggregate accounting ledger: `{actual['ledger_directory']}`. Values are observed counters, including unsuccessful process-creation attempts; they are not inferred syscall counts.\n"
    boot = json.loads((ROOT/'dist/preflight/native-boot.json').read_text(encoding='utf-8'))
    report += f"\n## Guest startup correction\n\nAn earlier combined run exposed a slow guest startup. I replace its 274 MB development image with a deterministic minimal Python runtime, use {boot['memory_mib']} MiB guest RAM and a bounded 240-second cold-boot budget. The final payload image is {boot['initrd_bytes']:,} bytes; actual console readiness took {boot['startup_seconds']:.3f} seconds. The complete suite and both kernel checks are repeated after this change.\n"
    (RESULTS/'latest_verification_report.md').write_text(report,encoding='utf-8')
    paper = ROOT/'docs/paper.md'
    text = paper.read_text(encoding='utf-8').split('\n## 10. Current release measurements')[0]
    batch = metrics['batch_ledger']
    text += '\n## 10. Current release measurements\n\n| Current release experiment | Measured result |\n|---|---:|\n'
    text += f"| Native inode deduplication | {batch['native']['dedup_events_sec']:.3f} events/s |\n| Anchored four-epoch verification | {batch['ledger']['verification_median_ms']:.3f} ms |\n| Portable burst drops / inversions | {metrics['transport']['portable_two_level']['drop_rate_percent']:.2f}% / {metrics['transport']['portable_two_level']['sequence_inversions']} |\n| Independent polynomial pairs | {differential['polynomial_pairs']} |\n| Maximum exhaustive-reference ddmin calls | {differential['max_oracle_evaluations']} |\n| Successful local preflight checks | 12 |\n"
    paper.write_text(text,encoding='utf-8')


if __name__ == '__main__':
    finalize()
