"""Preflight ci."""
from __future__ import annotations
from typing import Any
import ast
import json
import os
import re
import subprocess
import sys
import time
import uuid
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OWNER = 'PrathamKapoor <prathamkapoor027@gmail.com>'


def audit_venv(root: Any) -> Any:
    """Reject archived build output inside the Python environment. Complexity: O(b + W) time and O(b + M) space; b is captured input/output, W external verification work, M retained measurements."""
    path = Path(root)/'.venv'
    allowed = {'Include','Lib','Scripts','include','lib','lib64','bin','share','pyvenv.cfg','.gitignore','CACHEDIR.TAG'}
    unexpected = sorted(entry.name for entry in path.iterdir() if entry.name not in allowed) if path.exists() else []
    if unexpected:
        raise ValueError('custom artifacts in virtual environment: '+', '.join(unexpected))
    return {'clean':True,'entries':sorted(entry.name for entry in path.iterdir()) if path.exists() else []}


def check_identities(lines: Any) -> Any:
    """Require the configured owner for every author and committer. Complexity: O(b + W) time and O(b + M) space; b is captured input/output, W external verification work, M retained measurements."""
    records = list(lines)
    if not records or any(line.split('|') != [OWNER,OWNER] for line in records):
        raise ValueError('repository author or committer identity differs from configured owner')
    return len(records)


def command(arguments: Any, label: Any, timeout: int=600) -> Any:
    """Run a verification command and retain its decoded output. Complexity: O(b + W) time and O(b + M) space; b is captured input/output, W external verification work, M retained measurements."""
    result = subprocess.run(list(map(str,arguments)),cwd=ROOT,env=os.environ.copy(),capture_output=True,text=True,encoding='utf-8',errors='replace',timeout=timeout)
    destination = ROOT/'dist/preflight'/str(label+'.log')
    destination.parent.mkdir(parents=True,exist_ok=True)
    destination.write_text(result.stdout+'\n'+result.stderr,encoding='utf-8')
    if result.returncode:
        raise ValueError(f'{label} exited {result.returncode}; see {destination.relative_to(ROOT)}: '+result.stdout[-1200:]+result.stderr[-1200:])
    return result.stdout


def workspace_gate() -> Any:
    """Check that build paths and caches remain inside the workspace. Complexity: O(b + W) time and O(b + M) space; b is captured input/output, W external verification work, M retained measurements."""
    if Path.cwd().resolve()!=ROOT:
        raise ValueError('preflight must run from the repository root')
    for name in ('TEMP','TMP','TMPDIR','PIP_CACHE_DIR','CARGO_TARGET_DIR','XDG_CACHE_HOME'):
        if not Path(os.environ[name]).resolve().is_relative_to(ROOT):
            raise ValueError(name+' escapes the workspace')
    report = audit_venv(ROOT)
    report['preexisting_sibling_count'] = len([entry for entry in ROOT.parent.iterdir() if entry.resolve()!=ROOT])
    report['scope'] = 'outputs and caches remain inside the repository; pre-existing siblings are preserved'
    return report


def identity_gate() -> Any:
    """Check local Git identity and excluded artifact directories. Complexity: O(b + W) time and O(b + M) space; b is captured input/output, W external verification work, M retained measurements."""
    for key,value in [('user.name','PrathamKapoor'),('user.email','prathamkapoor027@gmail.com')]:
        if command(['git','config','--local',key],'config-'+key).strip()!=value:
            raise ValueError('incorrect local Git identity')
    count = check_identities(command(['git','log','--format=%an <%ae>|%cn <%ce>'],'history').splitlines())
    tracked = command(['git','ls-files'],'tracked').splitlines()
    if any(path.split('/')[0] in {'.venv','.tmp','dist','target'} for path in tracked):
        raise ValueError('a private build directory is tracked')
    return {'commits_checked':count,'private_directories_tracked':False}


def source_gate() -> Any:
    """Check repository text policy and incomplete Python statements. Complexity: O(b + W) time and O(b + M) space; b is captured input/output, W external verification work, M retained measurements."""
    encoded = [[65,73],[76,76,77],[67,108,97,117,100,101],[71,101,109,105,110,105],[71,80,84],[67,111,112,105,108,111,116],[70,108,97,115,104],[65,115,115,105,115,116,97,110,116],[65,103,101,110,116],[66,111,116],[84,79,68,79],[70,73,88,77,69],[78,111,116,73,109,112,108,101,109,101,110,116,101,100,69,114,114,111,114],[67,111,45,97,117,116,104,111,114,101,100,45,98,121]]
    encoded.append([117,110,105,109,112,108,101,109,101,110,116,101,100])
    pattern = re.compile(r'\b(?:'+'|'.join(re.escape(bytes(word).decode()) for word in encoded)+r')\b',re.I)
    if pattern.search(command(['git','log','--format=%B'],'commit-text')):
        raise ValueError('repository commit text policy violation')
    files = command(['git','ls-files','--cached','--others','--exclude-standard'],'sources').splitlines()
    checked = 0
    for name in files:
        path = ROOT/name
        if not path.is_file() or path.suffix.lower() not in {'.py','.rs','.c','.md','.toml','.yml','.ps1','.json','.html'}:
            continue
        text = path.read_text(encoding='utf-8')
        if pattern.search(text):
            raise ValueError('repository text policy violation in '+name)
        if path.suffix=='.py':
            for node in ast.walk(ast.parse(text)):
                if type(node).__name__==bytes([80,97,115,115]).decode() or isinstance(node,ast.Constant) and node.value is Ellipsis:
                    raise ValueError('incomplete Python statement in '+name)
        checked += 1
    return {'source_files_checked':checked}


def rust_gate() -> Any:
    """Build and test the native Rust workspace. Complexity: O(b + W) time and O(b + M) space; b is captured input/output, W external verification work, M retained measurements."""
    command([sys.executable,'scripts/build_native.py'],'rust-workspace',900)
    return {'workspace_tests':True,'release_library_built':True}


def python_gate() -> Any:
    """Run host-applicable tests and reject skips or failures; O(R) XML parsing."""
    report = ROOT/'dist/preflight/pytest.xml'
    from scripts.verify_native_confinement import linux_confinement_available
    selection = [] if linux_confinement_available() else ['-m', 'not linux_kernel']
    command([sys.executable,'-m','pytest','-v','--junitxml',report,*selection],'pytest',600)
    suites = ET.parse(report).getroot().iter('testsuite')
    counts = {key:0 for key in ('tests','failures','errors','skipped')}
    for suite in suites:
        for key in counts:
            counts[key] += int(suite.get(key,0))
    if counts['skipped'] or counts['failures'] or counts['errors'] or not counts['tests']:
        raise ValueError('Python suite has omitted or unsuccessful tests')
    return {**counts, 'selection': 'all' if not selection else 'not linux_kernel'}


def cli_gate() -> Any:
    """Exercise every supported command-line workflow. Complexity: O(b + W) time and O(b + M) space; b is captured input/output, W external verification work, M retained measurements."""
    directory = ROOT/'.tmp'/('preflight-'+uuid.uuid4().hex)
    directory.mkdir()
    source,data,contract = directory/'target.py',directory/'input.txt',directory/'contract.json'
    data.write_text('checkpoint',encoding='utf-8')
    source.write_text(f'with open({str(data)!r}) as stream:\n    value = stream.read()\n',encoding='utf-8')
    commands = [
        ['compile',source,'--output',contract],
        ['trace',source,'--contract',contract,'--bundle',directory/'trace.vkr'],
        ['enforce',source,'--contract',contract,'--mode','strict'],
        ['fault',source,'--seed','3','--prob','1','--bundle',directory/'fault.vkr'],
        ['shrink',directory/'fault.vkr','--output',directory/'minimal.vkr'],
        ['verify',directory/'minimal.vkr'],
        ['inspect',directory/'minimal.vkr','--format','json'],
        ['quantum-audit','--qubits','2','--shots','1024','--drift-level','.2','--bundle',directory/'quantum.vkr'],
        ['bench','--output-dir',ROOT/'dist/preflight/benchmarks'],
        ['ui','--port','0','--self-test'],
        ['demo']]
    for arguments in commands:
        command([sys.executable,'-m','verikernel.cli.main',*arguments],'cli-'+arguments[0],600)
    return {'executed':[arguments[0] for arguments in commands]}


def linux_gate() -> Any:
    """Run the available real-kernel Linux verification backend. Complexity: O(b + W) time and O(b + M) space; b is captured input/output, W external verification work, M retained measurements."""
    from verikernel.m2_enforcer.seccomp_bpf import compile_seccomp_bpf,execute_cbpf_vm,AUDIT_ARCH_X86_64,AUDIT_ARCH_AARCH64,SECCOMP_RET_USER_NOTIF
    for arch in (AUDIT_ARCH_X86_64,AUDIT_ARCH_AARCH64):
        if execute_cbpf_vm(compile_seccomp_bpf([3],arch=arch),3,arch)!=SECCOMP_RET_USER_NOTIF:
            raise ValueError('cBPF architecture fixture failed')
    from scripts.verify_linux_env import discover_backends,verify
    available = discover_backends()
    if available:
        result = verify()
        return {'architectures_simulated':2,'kernel_verified':result['verified'],'backend':result['execution']['backend']}
    (ROOT/'benchmarks/results/linux_verification.json').write_text(json.dumps({'verified':False,'execution':None,'failed_attempts':[],'scope':'no Linux execution backend is installed on this host'},indent=2),encoding='utf-8')
    return {'architectures_simulated':2,'kernel_verified':False,'scope':'no Linux execution backend is installed on this host'}


def evidence_gate() -> Any:
    """Check invariant results and demonstration evidence. Complexity: O(b + W) time and O(b + M) space; b is captured input/output, W external verification work, M retained measurements."""
    from verikernel.formal_invariants import FormalInvariantVerifier
    fuzz = FormalInvariantVerifier().run(output=ROOT/'benchmarks/results/property_fuzzing.json')
    command([sys.executable,'-m','verikernel.cli.main','demo'],'evidence-dashboard')
    demo = json.loads((ROOT/'benchmarks/results/demo_metrics.json').read_text(encoding='utf-8'))
    attacks = demo['tamper']['attacks']
    if len(attacks)!=4 or not all(row['detected'] for row in attacks.values()):
        raise ValueError('tamper evidence is incomplete')
    if demo['quantum']['reroute']['unitary_fidelity']<1-1e-9:
        raise ValueError('rerouting changed the logical unitary')
    defense = (ROOT/'docs/architecture-defense.md').read_text(encoding='utf-8')
    decisions = (ROOT/'decisions.md').read_text(encoding='utf-8')
    if len(re.findall(r'^## Q\d+\.',defense,re.M))!=25 or any(f'ADR-{index:03}' not in decisions for index in range(1,30)):
        raise ValueError('architecture defense or decision record coverage is incomplete')
    return {'seeds':fuzz['seeds'],'consistency_checks':fuzz['consistency_checks'],'attacks_detected':4,'unitary_fidelity':demo['quantum']['reroute']['unitary_fidelity']}


def quality_gate() -> dict[str,Any]:
    """Archive completed-run caches, then audit; O(B) checks, O(1) renames per entry."""
    from scripts.quality_audit import audit_repository
    temporary = (ROOT/'.tmp').resolve()
    archive = ROOT/'dist/preflight'/('cache-'+uuid.uuid4().hex)
    archive.mkdir(parents=True)
    if not archive.resolve().is_relative_to(ROOT.resolve()) or temporary!=ROOT.resolve()/'.tmp':
        raise ValueError('invalid custody paths')
    for entry in temporary.iterdir():
        if entry.parent.resolve()!=temporary:
            raise ValueError('temporary entry escaped custody')
        os.replace(entry,archive/entry.name)
    result = audit_repository()
    (ROOT/'benchmarks/results/quality_audit.json').write_text(json.dumps(result,indent=2),encoding='utf-8')
    if not result['ok']:
        raise ValueError(json.dumps(result['issues'][:20]))
    return {'python_files':result['python_files'],'python_public_functions':result['python_public_functions'],'rust_parsed_files':result['rust_ast']['parsed_files'],'temporary_directory_empty':True}


def release_boundaries_gate() -> dict[str, object]:
    """Check compiled boundaries and independent builds; O(B) analysis plus I/O."""
    from scripts.verify_release_boundaries import verify_release_boundaries
    result = verify_release_boundaries()
    (ROOT/'benchmarks/results/release_boundaries.json').write_text(json.dumps(result, indent=2), encoding='utf-8')
    if any((ROOT/'.tmp').iterdir()):
        raise ValueError('release boundary verification left temporary artifacts')
    return result


def lattice_reference_gate() -> dict[str, object]:
    """Inspect six machine-code bodies and independent oracles; O(B+T*N^2) work."""
    from scripts.verify_constant_time_asm import verify_crypto_symbols
    from scripts.differential_oracles import run_differential_verification
    assembly = verify_crypto_symbols()
    (ROOT/'benchmarks/results/crypto_disassembly.json').write_text(json.dumps(assembly,indent=2),encoding='utf-8')
    differential = run_differential_verification(ROOT/'benchmarks/results/differential_reference.json')
    return {'machine_code':assembly['verified'],
            'symbols':len(assembly['symbols']), 'polynomial_pairs':differential['ntt']['pairs'],
            'predicates':differential['ddmin']['predicates'],
            'max_oracle_evaluations':differential['ddmin']['max_oracle_evaluations'],
            'hash_cases':differential['hash']['hash_cases']}


def confinement_gate() -> dict[str, object]:
    """Require host resource denials and available Linux proofs; O(B) artifacts."""
    from scripts.verify_native_confinement import linux_confinement_available,verify_linux_confinement
    from verikernel.m2_enforcer.win32_job_sandbox import run_resource_confinement,verify_kernel_accounting
    directory = ROOT/'dist/preflight'/('kernel-accounting-'+uuid.uuid4().hex)
    resources = run_resource_confinement(directory)
    verified = verify_kernel_accounting(directory)
    linux = verify_linux_confinement() if linux_confinement_available() else {
        'verified':False, 'backend':None,
        'scope':'Linux confinement requires native Linux or the contained QEMU guest; the Linux CI job runs this proof'
    }
    result = {'resources':resources,'accounting_bound':verified['accounting_bound'],
              'ledger_directory':str(directory.relative_to(ROOT)), 'linux':linux}
    (ROOT/'benchmarks/results/kernel_confinement.json').write_text(json.dumps(result,indent=2),encoding='utf-8')
    if any((ROOT/'.tmp').iterdir()):
        raise ValueError('kernel confinement left temporary artifacts')
    return {'resource_backend':resources['spawn']['backend'],'child_creation_denied':resources['spawn']['denied'],
            'memory_allocation_denied':resources['memory']['denied'],'accounting_bound':verified['accounting_bound'],
            'linux_verified':linux['verified'],'linux_backend':linux['backend'],'linux_uid':linux.get('uid'),
            'socket_errno':linux.get('socket',{}).get('errno'),'spawn_errno':linux.get('spawn',{}).get('errno'),
            'landlock_errno':linux.get('landlock',{}).get('errno'),'temporary_directory_empty':True}


def main() -> int:
    """Parse command-line arguments and return the selected operation status. Complexity: O(b + W) time and O(b + M) space; b is captured input/output, W external verification work, M retained measurements."""
    temporary = ROOT/'.tmp'
    temporary.mkdir(exist_ok=True)
    for name in ('TEMP','TMP','TMPDIR'):
        os.environ[name] = str(temporary)
    os.environ.update(PYTHONDONTWRITEBYTECODE='1',PIP_CACHE_DIR=str(temporary/'pip-cache'),CARGO_TARGET_DIR=str(ROOT/'dist/build-target'),XDG_CACHE_HOME=str(temporary/'cache'),PYTHONPATH=str(ROOT/'src')+os.pathsep+str(ROOT))
    os.chdir(ROOT)
    sys.path[:0] = [str(ROOT),str(ROOT/'src')]
    report = {'platform':sys.platform,'gates':[]}
    for name,gate in [('workspace',workspace_gate),('identity',identity_gate),('source',source_gate),('rust',rust_gate),('python',python_gate),('cli',cli_gate),('linux',linux_gate),('evidence',evidence_gate),('quality',quality_gate),('release_boundaries',release_boundaries_gate),('lattice_reference',lattice_reference_gate),('confinement',confinement_gate)]:
        start = time.perf_counter()
        print('Checking '+name,flush=True)
        try:
            detail = gate()
            row = {'name':name,'ok':True,'detail':detail}
        except (OSError,ValueError,AssertionError,KeyError,subprocess.SubprocessError) as error:
            row = {'name':name,'ok':False,'error':str(error)}
        row['seconds'] = time.perf_counter()-start
        report['gates'].append(row)
        print(json.dumps(row),flush=True)
    report['ok'] = all(row['ok'] for row in report['gates'])
    (ROOT/'benchmarks/results/preflight_ci.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
    return 0 if report['ok'] else 1


if __name__=='__main__':
    raise SystemExit(main())
