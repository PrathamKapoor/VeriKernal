import json
from pathlib import Path
import sys
from verikernel.cli.main import verify_bundle
from verikernel.m3_fault.replay import read_container


def test_child_grandchild_ipc_and_signed_global_order(tmp_path):
    from verikernel.m2_enforcer.process_supervisor import MultiProcessSupervisor
    secret=tmp_path/'undeclared.txt'
    secret.write_text('private')
    grand=tmp_path/'grand.py'
    grand.write_text(f'with open({str(secret)!r}) as stream:\n    stream.read()\n')
    worker=tmp_path/'worker.py'
    worker.write_text(f'import subprocess,sys\nsubprocess.run([sys.executable,{str(grand)!r}],check=True)\n')
    parent=tmp_path/'parent.py'
    parent.write_text(f'import subprocess,sys\na=subprocess.Popen([sys.executable,{str(worker)!r}])\nb=subprocess.Popen([sys.executable,"-c","print(123)"])\na.wait(); b.wait()\n')
    bundle=tmp_path/'tree.vkr'
    result=MultiProcessSupervisor({},mode='audit').run(parent,bundle)
    assert result['returncode']==0
    assert verify_bundle(bundle)['valid']
    assert verify_bundle(bundle,prove_index=0)['inclusion']
    metadata,events=read_container(bundle)
    assert len({event.pid for event in events})>=4
    assert [e.seq_no for e in events]==list(range(len(events)))
    assert all(e.tid>0 for e in events)
    assert str(secret.resolve()) in metadata['manifest']['patch']['add']['filesystem']
    nodes=metadata['manifest']['process_tree']
    assert len(nodes)>=4 and all(node['complete'] for node in nodes)
    assert any(node['parent_pid'] in {n['pid'] for n in nodes} for node in nodes)


def test_child_strict_denial_and_seeded_faults(tmp_path):
    from verikernel.m2_enforcer.process_supervisor import MultiProcessSupervisor
    source=tmp_path/'target.py'
    target=tmp_path/'forbidden'
    source.write_text(f'with open({str(target)!r},"w") as stream:\n    stream.write("bad")\n')
    strict=MultiProcessSupervisor({},mode='strict').run(source,tmp_path/'strict.vkr')
    assert strict['returncode']!=0 and not target.exists()
    assert verify_bundle(tmp_path/'strict.vkr')['valid']
    source.write_text('import os\nprint(os.urandom(4))\n')
    first=MultiProcessSupervisor({},fault_seed=17,probability=1).run(source,tmp_path/'one.vkr')
    second=MultiProcessSupervisor({},fault_seed=17,probability=1).run(source,tmp_path/'two.vkr')
    a=read_container(tmp_path/'one.vkr')[0]['manifest']['process_tree'][0]['fault_schedule']
    b=read_container(tmp_path/'two.vkr')[0]['manifest']['process_tree'][0]['fault_schedule']
    assert a and a==b


def test_cli_process_tree_backend_and_terminal_inspection(tmp_path):
    import subprocess
    child=tmp_path/'child.py';child.write_text('print(42)\n')
    parent=tmp_path/'parent.py';parent.write_text(f'import subprocess,sys\nsubprocess.run([sys.executable,{str(child)!r}],check=True)\n')
    contract=tmp_path/'contract.json';contract.write_text('{}')
    bundle=tmp_path/'cli.vkr'
    result=subprocess.run([sys.executable,'-m','verikernel.cli.main','trace',str(parent),'--backend','multiprocess','--contract',str(contract),'--bundle',str(bundle)],capture_output=True,text=True)
    assert result.returncode==0,result.stderr
    assert verify_bundle(bundle)['valid']
    assert len(read_container(bundle)[0]['manifest']['process_tree'])==2
