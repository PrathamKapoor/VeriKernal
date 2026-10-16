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
