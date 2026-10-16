from pathlib import Path
import sys
from verikernel.cli.main import verify_bundle
from verikernel.m3_fault.replay import read_container


def test_real_native_headers_execution_and_sealed_io(tmp_path):
    from verikernel.m2_enforcer.native_supervisor import NativeTargetSupervisor, target_binary
    from verikernel.m1_contract.compiler import compile_contract
    binary = target_binary()
    contract = compile_contract(binary)
    assert contract['inputs'][binary.name].startswith('gitoid:blob:sha256:')
    assert any(name.lower() in {'kernel32.dll', 'ntdll.dll', 'libc.so.6', 'libgcc_s.so.1', 'libsystem.b.dylib'} for name in contract['shared_libraries'])
    checkpoint = tmp_path/'checkpoint.dat'
    contract['filesystem'] = [str(checkpoint.resolve())]
    contract['environment'] = ['VK_NATIVE_TEST']
    bundle = tmp_path/'native.vkr'
    result = NativeTargetSupervisor(contract).run(binary, ['--work-dir',str(tmp_path),'--read-env','VK_NATIVE_TEST'], bundle)
    assert result['returncode'] == 0
    assert checkpoint.read_bytes().startswith(b'VK-CHECKPOINT-V1')
    assert verify_bundle(bundle)['valid']
    metadata, events = read_container(bundle)
    assert {1,2,5,9,10} <= {e.syscall_nr for e in events}
    assert all(e.pid == result['pid'] and e.tid > 0 for e in events)
    assert metadata['manifest']['target_gitoid'] == contract['inputs'][binary.name]


def test_native_undeclared_access_and_checkpoint_fault_shrink(tmp_path):
    from verikernel.m2_enforcer.native_supervisor import NativeTargetSupervisor, target_binary
    from verikernel.m3_fault.ddmin import DeltaDebuggingShrinker
    binary = target_binary()
    checkpoint = tmp_path/'checkpoint.dat'
    contract = {'filesystem':[str(checkpoint)],'subprocesses':[str(binary)]}
    forbidden = tmp_path/'forbidden'
    forbidden.write_text('private')
    denied = NativeTargetSupervisor(contract, mode='strict').run(binary,['--work-dir',str(tmp_path),'--simulate-undeclared-file',str(forbidden)],tmp_path/'denied.vkr')
    assert denied['returncode'] != 0
    assert verify_bundle(tmp_path/'denied.vkr')['valid']
    metadata, _ = read_container(tmp_path/'denied.vkr')
    assert str(forbidden) in metadata['manifest']['patch']['add']['filesystem']
    calls = 0
    def oracle(sites):
        nonlocal calls
        calls += 1
        outcome = NativeTargetSupervisor(contract, fault_sites=set(sites), seed=42).run(binary,['--work-dir',str(tmp_path)],tmp_path/f'fault-{calls}.vkr')
        assert verify_bundle(tmp_path/f'fault-{calls}.vkr')['valid']
        return outcome['returncode'] != 0
    minimal = DeltaDebuggingShrinker(oracle).shrink(list(range(8)))
    assert minimal == [2]
    assert oracle(minimal)
    assert not oracle([])
    fault_records = [event for event in read_container(tmp_path/'fault-1.vkr')[1] if event.fault_injected]
    assert len(fault_records) == 1 and fault_records[0].fault_injected == -28
