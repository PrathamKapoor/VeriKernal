import hashlib
import zipfile
from pathlib import Path


def test_two_builds_have_identical_hashes_and_install_cleanly():
    from scripts.build_reproducible_dist import verify_reproducible_build
    report = verify_reproducible_build(install=True)
    assert report['reproducible'] and report['clean_install_verified']
    assert report['build_1_sha256'] == report['build_2_sha256']
    assert report['build_1_gitoid'] == report['build_2_gitoid']
    artifact = Path(report['artifact'])
    assert hashlib.sha256(artifact.read_bytes()).hexdigest() == report['build_1_sha256']
    with zipfile.ZipFile(artifact) as wheel:
        names = wheel.namelist()
        assert names == sorted(names)
        assert 'verikernel/type_boundaries.py' in names
        assert wheel.read('verikernel-0.2.0.dist-info/METADATA').startswith(b'Metadata-Version: 2.4\n')
        assert any(name.endswith('verikernel-schema/src/lib.rs') for name in names)
        assert all((item.external_attr >> 16) & 0o777 == 0o644 for item in wheel.infolist())
        assert len({item.date_time for item in wheel.infolist()}) == 1
    assert not any(Path('.tmp').glob('repro_build_*'))


def test_source_content_changes_artifact_digest(tmp_path):
    from scripts.build_reproducible_dist import write_wheel
    first, second = tmp_path/'first.whl', tmp_path/'second.whl'
    write_wheel(first, {'example.py':b'x = 1\n'})
    write_wheel(second, {'example.py':b'x = 2\n'})
    assert hashlib.sha256(first.read_bytes()).digest() != hashlib.sha256(second.read_bytes()).digest()
