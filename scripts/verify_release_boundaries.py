"""Exercise release boundaries using real artifacts; O(N) work plus subprocess I/O."""
from __future__ import annotations
import json
from pathlib import Path
import tempfile
from scripts.verify_constant_time_asm import verify_library
from scripts.build_reproducible_dist import verify_reproducible_build
from scripts.quality_audit import audit_python_source

ROOT = Path(__file__).resolve().parents[1]


def verify_native_target() -> dict[str, object]:
    """Run successful, denied and minimized native workloads; O(N) event space."""
    from verikernel.cli.main import verify_bundle
    from verikernel.m1_contract.compiler import compile_contract
    from verikernel.m2_enforcer.native_supervisor import NativeTargetSupervisor, target_binary
    from verikernel.m3_fault.ddmin import DeltaDebuggingShrinker
    from verikernel.m3_fault.replay import read_container
    binary = target_binary()
    contract = compile_contract(binary)
    with tempfile.TemporaryDirectory(dir=ROOT/'.tmp', prefix='native_release_') as name:
        directory = Path(name)
        contract['filesystem'] = [str(directory/'checkpoint.dat')]
        contract['environment'] = ['VK_NATIVE_TEST']
        normal_path = directory/'normal.vkr'
        normal = NativeTargetSupervisor(contract, mode='strict').run(binary, ['--work-dir', name, '--read-env', 'VK_NATIVE_TEST'], normal_path)
        if normal['returncode'] != 0 or not verify_bundle(normal_path)['valid']:
            raise ValueError('normal native execution did not verify')
        forbidden = directory/'forbidden.txt'
        forbidden.write_text('undeclared', encoding='utf-8')
        denied_path = directory/'denied.vkr'
        denied = NativeTargetSupervisor(contract, mode='strict').run(binary, ['--work-dir', name, '--simulate-undeclared-file', str(forbidden)], denied_path)
        metadata, _ = read_container(denied_path)
        if denied['returncode'] == 0 or str(forbidden) not in metadata['manifest']['patch']['add'].get('filesystem', []) or not verify_bundle(denied_path)['valid']:
            raise ValueError('native strict denial was not observed and sealed')
        runs = 0
        def oracle(sites: list[int]) -> bool:
            """Restore the checkpoint and execute selected boundary faults; O(N) work."""
            nonlocal runs
            runs += 1
            checkpoint = directory/'checkpoint.dat'
            if checkpoint.exists():
                checkpoint.unlink()
            receipt = directory/f'fault-{runs}.vkr'
            result = NativeTargetSupervisor(contract, mode='strict', fault_sites=set(sites), seed=42).run(binary, ['--work-dir', name], receipt)
            verify_bundle(receipt)
            return result['returncode'] != 0
        shrinker = DeltaDebuggingShrinker(oracle)
        minimal = shrinker.shrink(list(range(8)))
        if minimal != [2] or not oracle(minimal) or oracle([]):
            raise ValueError('native checkpoint fault did not minimize reproducibly')
        return {'verified':True, 'binary':str(binary), 'gitoid':normal['target_gitoid'],
                'shared_libraries':contract['shared_libraries'], 'event_count':normal['event_count'],
                'normal_seconds':normal['elapsed_seconds'], 'strict_denial':True,
                'minimal_fault_sites':minimal, 'oracle_evaluations':shrinker.evaluations,
                'fault_code':-28, 'scope':'cooperative compiled adapter; actual filesystem workload'}


def verify_release_boundaries() -> dict[str, object]:
    """Verify native code, typed boundaries and distribution; O(B) source analysis."""
    issues = [issue for source in (ROOT/'src/verikernel').rglob('*.py') for issue in audit_python_source(source)]
    if issues:
        raise ValueError('package boundary audit rejected: '+json.dumps(issues))
    result = {'zero_dynamic_package_annotations':True, 'machine_code':verify_library(),
              'native_target':verify_native_target(), 'distribution':verify_reproducible_build()}
    return result


if __name__ == '__main__':
    print(json.dumps(verify_release_boundaries(), indent=2))
