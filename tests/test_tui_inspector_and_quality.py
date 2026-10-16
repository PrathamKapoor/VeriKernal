import json
import os
import subprocess
import sys
import pytest
from verikernel.cli.main import main


def test_terminal_inspector_wire_proof_diff_and_json(tmp_path):
    from verikernel.ui.tui_inspector import inspect_bundle,render_text
    path=tmp_path/'run.vkr'
    assert main(['quantum-audit','--bundle',str(path)])==0
    result=inspect_bundle(path)
    assert result['signature_status']=='VERIFIED' and result['ratchet_status']=='INTACT'
    assert result['event']['wire_bytes']==128
    assert len(result['event']['hex'])==256
    assert result['merkle']['verified']
    text=render_text(result)
    assert '128-BYTE WIRE' in text and '96..127' in text and 'ML-DSA-65' in text
    cli=subprocess.run([sys.executable,'-m','verikernel.cli.main','inspect',str(path),'--format','json'],capture_output=True,text=True,env=os.environ.copy())
    assert cli.returncode==0,cli.stderr
    assert json.loads(cli.stdout)['event']['fields']['syscall_nr']==8
    with pytest.raises(ValueError):
        inspect_bundle(path,event_seq=99)
    raw=bytearray(path.read_bytes());raw[-1]^=1;path.write_bytes(raw)
    with pytest.raises(ValueError):
        inspect_bundle(path)


def test_quality_python_ast_detects_missing_contracts(tmp_path):
    from scripts.quality_audit import audit_python_source
    source=tmp_path/'broken.py'
    source.write_text('def broken(value):\n    return value\n')
    issues=audit_python_source(source)
    kinds={issue['rule'] for issue in issues}
    assert {'module-docstring','function-docstring','parameter-annotation','return-annotation'}<=kinds


def test_repository_quality_annotations_and_rust_ast():
    from scripts.quality_audit import audit_repository
    result=audit_repository(require_empty_temp=False)
    assert result['ok'],result['issues']
    assert result['python_public_functions']>170
    assert result['rust_ast']['parsed_files']>5
