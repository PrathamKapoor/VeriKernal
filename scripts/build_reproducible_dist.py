"""Build and clean-install canonical wheels twice; O(B) time and source memory."""
from __future__ import annotations
import base64
import csv
import datetime
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import tomllib
import zipfile
from verikernel.omnibor import gitoid_sha256

ROOT = Path(__file__).resolve().parents[1]
SOURCE_DATE_EPOCH = 1760486400
DIST_INFO = 'verikernel-0.2.0.dist-info'
WHEEL_NAME = 'verikernel-0.2.0-py3-none-any.whl'


def distribution_entries() -> dict[str, bytes]:
    """Read source and metadata independently per build; O(B) time and space."""
    entries = {}
    for folder, prefix in [('src/verikernel', 'verikernel'), ('benchmarks', 'benchmarks'), ('examples', 'examples')]:
        directory = ROOT/folder
        for source in sorted(directory.rglob('*.py')):
            if '__pycache__' not in source.parts:
                entries[prefix+'/'+source.relative_to(directory).as_posix()] = source.read_bytes().replace(b'\r\n', b'\n')
    data_prefix = 'verikernel-0.2.0.data/data/share/verikernel/'
    for source in sorted((ROOT/'crates').rglob('*')):
        if source.is_file() and source.suffix in {'.rs', '.toml'}:
            entries[data_prefix+source.relative_to(ROOT).as_posix()] = source.read_bytes().replace(b'\r\n', b'\n')
    for name in ['Cargo.toml', 'Cargo.lock', 'pyproject.toml', 'LICENSE']:
        entries[data_prefix+name] = (ROOT/name).read_bytes().replace(b'\r\n', b'\n')
    project = tomllib.loads((ROOT/'pyproject.toml').read_text(encoding='utf-8'))['project']
    metadata = ['Metadata-Version: 2.4', 'Name: verikernel', 'Version: '+project['version'],
                'Summary: '+project['description'], 'Requires-Python: '+project['requires-python'],
                'License-Expression: MIT', 'Author-email: Pratham Kapoor <prathamkapoor027@gmail.com>']
    metadata.extend('Requires-Dist: '+item for item in project['dependencies'])
    entries[DIST_INFO+'/METADATA'] = ('\n'.join(metadata)+'\n\n').encode()
    entries[DIST_INFO+'/WHEEL'] = b'Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n'
    entries[DIST_INFO+'/entry_points.txt'] = b'[console_scripts]\nverikernel = verikernel.cli.main:main\n'
    entries[DIST_INFO+'/licenses/LICENSE'] = (ROOT/'LICENSE').read_bytes().replace(b'\r\n', b'\n')
    return entries


def write_wheel(path: Path, entries: dict[str, bytes]) -> None:
    """Write sorted normalized ZIP members and RECORD; O(B) time and space."""
    records = io.StringIO(newline='')
    writer = csv.writer(records, lineterminator='\n')
    for name, data in sorted(entries.items()):
        if name.startswith('/') or '..' in Path(name).parts or '\\' in name:
            raise ValueError('unsafe distribution entry')
        digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b'=').decode()
        writer.writerow([name, 'sha256='+digest, len(data)])
    writer.writerow([DIST_INFO+'/RECORD', '', ''])
    members = {**entries, DIST_INFO+'/RECORD':records.getvalue().encode()}
    stamp = datetime.datetime.fromtimestamp(SOURCE_DATE_EPOCH, datetime.timezone.utc).timetuple()[:6]
    path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(path, 'w', compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for name, data in sorted(members.items()):
            info = zipfile.ZipInfo(name, stamp)
            info.create_system = 3
            info.external_attr = 0o100644 << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, data, compresslevel=9)


def verify_reproducible_build(install: bool = True) -> dict[str, object]:
    """Compare independent builds and optionally install offline; O(B) time/space."""
    temporary = (ROOT/'.tmp').resolve()
    if temporary != ROOT.resolve()/'.tmp':
        raise ValueError('invalid build custody root')
    temporary.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='repro_build_', dir=temporary) as workspace:
        directory = Path(workspace)
        if not directory.resolve().is_relative_to(temporary):
            raise ValueError('build path escaped temporary custody')
        paths = [directory/('build_run_'+str(index))/WHEEL_NAME for index in (1, 2)]
        hashes, identities = [], []
        for path in paths:
            write_wheel(path, distribution_entries())
            data = path.read_bytes()
            hashes.append(hashlib.sha256(data).hexdigest())
            identities.append(gitoid_sha256(data))
        if hashes[0] != hashes[1] or identities[0] != identities[1]:
            raise ValueError('independent distribution builds differ')
        if install:
            installation = directory/'installation'
            environment = os.environ.copy()
            environment.update(SOURCE_DATE_EPOCH=str(SOURCE_DATE_EPOCH), PYTHONDONTWRITEBYTECODE='1', PIP_DISABLE_PIP_VERSION_CHECK='1')
            subprocess.run([sys.executable, '-m', 'pip', 'install', '--no-index', '--no-deps', '--no-compile', '--no-cache-dir', '--target', str(installation), str(paths[0])],
                           env=environment, check=True, capture_output=True, text=True, timeout=90)
            check = 'import sys; sys.path.insert(0, sys.argv[1]); import verikernel; from verikernel.schemas import EVENT_STRUCT; from verikernel.type_boundaries import WireEvent; import ctypes; assert EVENT_STRUCT.size == ctypes.sizeof(WireEvent) == 128; assert verikernel.__file__.startswith(sys.argv[1])'
            subprocess.run([sys.executable, '-I', '-B', '-c', check, str(installation)], env=environment, cwd=directory, check=True, capture_output=True, text=True, timeout=30)
        artifact = ROOT/'dist'/WHEEL_NAME
        artifact.parent.mkdir(exist_ok=True)
        shutil.copyfile(paths[0], artifact)
        return {'reproducible':True, 'clean_install_verified':install,
                'source_date_epoch':SOURCE_DATE_EPOCH, 'artifact':str(artifact),
                'build_1_sha256':hashes[0], 'build_2_sha256':hashes[1],
                'build_1_gitoid':identities[0], 'build_2_gitoid':identities[1],
                'size_bytes':artifact.stat().st_size, 'scope':'same source snapshot and Python ZIP toolchain; optional native libraries excluded'}


if __name__ == '__main__':
    print(json.dumps(verify_reproducible_build(), indent=2))
