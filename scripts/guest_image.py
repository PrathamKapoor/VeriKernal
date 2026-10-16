"""Build a minimal contained Python initramfs; O(B+N log N) input/order work."""
from __future__ import annotations
import gzip
import hashlib
import json
from pathlib import Path
import stat
import tarfile

ROOT = Path(__file__).resolve().parents[1]
INIT = b'''#!/bin/sh
mount -t proc proc /proc
mount -t sysfs sys /sys
mount -t devtmpfs dev /dev
export HOME=/work/.tmp TMPDIR=/work/.tmp
echo VERIKERNEL_LINUX_READY
cd /
printf '/ # '
while IFS= read -r vk_command; do
    /bin/sh -c "$vk_command"
    printf '/ # '
done
'''


def keep_path(name: str) -> bool:
    """Select runtime files without compiler/modules/workload state; O(L) path work."""
    parts = name.split('/')
    if name.startswith('/') or '..' in parts:
        raise ValueError('escaping guest archive path')
    if name in {'etc/passwd','etc/group','etc/ld-musl-aarch64.path'}:
        return True
    if name.startswith(('bin/','sbin/')):
        return True
    if name.startswith('usr/bin/python3') or name == 'usr/bin/strace':
        return True
    if name.startswith('usr/lib/python3.12/'):
        return 'site-packages' not in parts
    if name.startswith(('lib/','usr/lib/')) and len(parts) in {2,3}:
        runtime = ('ld-musl','libc.musl','libpython','libcrypto','libssl','libz.',
                   'libbz2','liblzma','libexpat','libffi','libgcc_s','libstdc++','libmpdec',
                   'libunwind','libelf','libzstd')
        return '.so' in parts[-1] and parts[-1].startswith(runtime)
    return False


def newc_entry(name: str, content: bytes, mode: int, inode: int, major: int = 0, minor: int = 0, mtime: int = 0) -> bytes:
    """Encode bounded newc metadata and device identifiers; O(B) time and space."""
    encoded = name.encode()+b'\0'
    fields = [inode,mode,0,0,1,mtime,len(content),0,0,major,minor,len(encoded),0]
    prefix = b'070701'+''.join(f'{value:08x}' for value in fields).encode()+encoded
    return prefix+b'\0'*((-len(prefix))%4)+content+b'\0'*((-len(content))%4)


def prepare_verification_initrd() -> Path:
    """Build/cache required bytes; O(B+N log N) time, O(R) retained runtime space."""
    source = ROOT/'dist/development/build-archive-v02/guest-root.tar.gz'
    if not source.is_file():
        raise OSError('contained Alpine Python root archive is required for the guest')
    with source.open('rb') as stream:
        digest = hashlib.file_digest(stream,'sha256').digest()
    identity = hashlib.sha256(digest+INIT+b'VK-MINIMAL-ROOT-V3').hexdigest()
    directory = ROOT/'dist/linux-confinement'
    directory.mkdir(parents=True,exist_ok=True)
    destination = directory/('python-root-'+identity[:20]+'.gz')
    manifest_path = destination.with_suffix('.json')
    if destination.exists() and manifest_path.exists():
        manifest = json.loads(manifest_path.read_text(encoding='utf-8'))
        if hashlib.sha256(destination.read_bytes()).hexdigest() == manifest['image_sha256']:
            return destination
        raise ValueError('cached verification image digest differs')
    entries: dict[str, tuple[bytes,int,int]] = {}
    with tarfile.open(source,'r|gz') as archive:
        for member in archive:
            name = member.name.removeprefix('./').rstrip('/')
            if not name or not keep_path(name):
                continue
            if member.isfile():
                stream = archive.extractfile(member)
                if stream is None:
                    raise ValueError('missing runtime file body')
                entries[name] = (stream.read(),stat.S_IFREG | member.mode,int(member.mtime))
            elif member.issym() or member.islnk():
                target = member.linkname if member.issym() else '/'+member.linkname.removeprefix('./')
                entries[name] = (target.encode(),stat.S_IFLNK | 0o777,int(member.mtime))
    for name in ['dev','proc','sys','work','work/.tmp','etc','bin','sbin','lib','usr','usr/bin','usr/lib']:
        entries[name] = (b'',stat.S_IFDIR | (0o777 if name == 'work/.tmp' else 0o755),0)
    for name in list(entries):
        for parent in Path(name).parents:
            normalized = parent.as_posix()
            if normalized != '.':
                entries.setdefault(normalized,(b'',stat.S_IFDIR | 0o755,0))
    entries['init'] = (INIT,stat.S_IFREG | 0o755,0)
    if not {'bin/busybox','bin/sh','usr/bin/python3','usr/bin/python3.12','lib/ld-musl-aarch64.so.1'} <= entries.keys():
        raise ValueError('guest runtime archive lacks the required interpreter or loader')
    payload = b''.join(newc_entry(name,entries[name][0],entries[name][1],index+1,mtime=entries[name][2])
                       for index,name in enumerate(sorted(entries,key=lambda value:(value.count('/'),value))))
    payload += newc_entry('dev/console',b'',stat.S_IFCHR | 0o600,len(entries)+1,5,1)
    payload += newc_entry('dev/null',b'',stat.S_IFCHR | 0o666,len(entries)+2,1,3)
    payload += newc_entry('TRAILER!!!',b'',0,len(entries)+3)
    destination.write_bytes(gzip.compress(payload,compresslevel=3,mtime=0))
    manifest = {'source_sha256':digest.hex(),'image_sha256':hashlib.sha256(destination.read_bytes()).hexdigest(),
                'image_bytes':destination.stat().st_size,'uncompressed_bytes':len(payload),'entries':sorted(entries)}
    manifest_path.write_text(json.dumps(manifest,indent=2),encoding='utf-8')
    return destination
