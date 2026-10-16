import pytest


def test_venv_audit_rejects_custom_artifacts(tmp_path):
    from scripts.preflight_ci import audit_venv
    environment = tmp_path/'.venv'
    environment.mkdir()
    (environment/'Lib').mkdir()
    assert audit_venv(tmp_path)['clean']
    (environment/'archived-build').mkdir()
    with pytest.raises(ValueError,match='virtual environment'):
        audit_venv(tmp_path)


def test_identity_audit_checks_both_author_and_committer():
    from scripts.preflight_ci import check_identities
    owner = 'PrathamKapoor <prathamkapoor027@gmail.com>'
    assert check_identities([owner+'|'+owner]) == 1
    with pytest.raises(ValueError):
        check_identities([owner+'|Other <other@example.org>'])


@pytest.mark.parametrize('linux_available,expected_tests', [(False, 1), (True, 2)])
def test_python_preflight_selects_tests_for_available_kernel(tmp_path, monkeypatch, linux_available, expected_tests):
    from types import SimpleNamespace
    from scripts import preflight_ci
    from scripts import verify_native_confinement
    monkeypatch.setattr(preflight_ci, 'ROOT', tmp_path)
    monkeypatch.setattr(verify_native_confinement, 'sys', SimpleNamespace(platform='linux' if linux_available else 'win32'))
    monkeypatch.setattr(verify_native_confinement, 'discover_backends', lambda: [])
    (tmp_path/'pytest.ini').write_text('[pytest]\nmarkers =\n    linux_kernel: requires a real Linux kernel\n')
    (tmp_path/'test_host.py').write_text(
        'import pytest\n\ndef test_portable():\n    assert True\n\n'
        '@pytest.mark.linux_kernel\ndef test_kernel():\n'
        f'    assert {linux_available!r}, "Linux kernel is unavailable"\n'
    )
    result = preflight_ci.python_gate()
    assert result['tests'] == expected_tests
    assert result['failures'] == result['errors'] == result['skipped'] == 0


def test_confinement_preflight_records_unavailable_linux_without_claiming_proof(tmp_path, monkeypatch):
    import json
    from types import SimpleNamespace
    from scripts import preflight_ci
    from scripts import verify_native_confinement
    monkeypatch.setattr(preflight_ci, 'ROOT', tmp_path)
    monkeypatch.setattr(verify_native_confinement, 'sys', SimpleNamespace(platform='win32'))
    monkeypatch.setattr(verify_native_confinement, 'discover_backends', lambda: [])
    (tmp_path/'.tmp').mkdir()
    (tmp_path/'benchmarks/results').mkdir(parents=True)
    result = preflight_ci.confinement_gate()
    assert result['child_creation_denied'] and result['memory_allocation_denied']
    assert result['accounting_bound']
    assert result['linux_verified'] is False
    assert result['linux_backend'] is None
    evidence = json.loads((tmp_path/'benchmarks/results/kernel_confinement.json').read_text())
    assert evidence['linux']['verified'] is False
    assert 'socket' not in evidence['linux']


def test_confinement_preflight_propagates_available_linux_proof_failure(tmp_path, monkeypatch):
    from types import SimpleNamespace
    from scripts import preflight_ci
    from scripts import verify_native_confinement
    monkeypatch.setattr(preflight_ci, 'ROOT', tmp_path)
    monkeypatch.setattr(verify_native_confinement, 'sys', SimpleNamespace(platform='linux'))
    def failed_proof():
        raise ValueError('Linux confinement proof failed')
    monkeypatch.setattr(verify_native_confinement, 'verify_linux_confinement', failed_proof)
    with pytest.raises(ValueError, match='Linux confinement proof failed'):
        preflight_ci.confinement_gate()
