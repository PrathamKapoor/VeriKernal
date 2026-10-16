"""Verify compiled pre-exec confinement on Linux or a contained guest; O(B) artifacts."""
from __future__ import annotations
import gzip
import hashlib
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import time
from scripts.verify_linux_env import console, discover_backends

ROOT = Path(__file__).resolve().parents[1]


def cross_build_linux() -> Path:
    """Build only the two Linux executables with contained caches; O(B) build work."""
    environment = os.environ.copy()
    environment.update(CARGO_HOME=str(ROOT/'dist/development/cargo'),RUSTUP_HOME=str(ROOT/'dist/development/rustup'),
                       CARGO_TARGET_DIR=str(ROOT/'dist/build-target'),ZIG_GLOBAL_CACHE_DIR=str(ROOT/'dist/development/zig-cache'),ZIG_LOCAL_CACHE_DIR=str(ROOT/'dist/development/zig-local-cache'))
    linkers = list((ROOT/'dist/development/llvm').glob('*/bin/ld.lld.exe'))
    if not linkers:
        raise OSError('an ELF-capable contained LLD linker is required')
    environment['CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER'] = str(linkers[0])
    environment['RUSTFLAGS'] = '-C linker-flavor=ld.lld'
    command = ['cargo','build','--release','--target','aarch64-unknown-linux-musl','-p','verikernel-target-bin','-p','verikernel-sandbox-exec']
    result = subprocess.run(command,cwd=ROOT,env=environment,capture_output=True,text=True,encoding='utf-8',errors='replace',timeout=300)
    log = ROOT/'dist/preflight/native-linux-build.log'
    log.parent.mkdir(parents=True,exist_ok=True)
    log.write_text(result.stdout+result.stderr,encoding='utf-8')
    if result.returncode:
        raise ValueError('Linux executable build failed: '+result.stderr[-3000:])
    return ROOT/'dist/build-target/aarch64-unknown-linux-musl/release'


def cpio_member(name: str, content: bytes, mode: int, inode: int) -> bytes:
    """Encode one deterministic newc member; O(B) time and space."""
    encoded = name.encode()+b'\0'
    fields = [inode,mode,0,0,1,0,len(content),0,0,0,0,len(encoded),0]
    header = b'070701'+''.join(f'{value:08x}' for value in fields).encode()
    prefix = header+encoded
    return prefix+b'\0'*((-len(prefix))%4)+content+b'\0'*((-len(content))%4)


def guest_initrd(directory: Path, base: Path) -> Path:
    """Append deterministic native payload to the existing initramfs; O(B) streaming work."""
    entries = [('work',b'',0o40755),('work/native',b'',0o40755),('work/.tmp',b'',0o40777),
               ('work/probe.py',(ROOT/'scripts/native_kernel_probe.py').read_bytes(),0o100644)]
    for name in ['vk-target-bin','verikernel-sandbox-exec']:
        entries.append(('work/native/'+name,(directory/name).read_bytes(),0o100755))
    payload = b''.join(cpio_member(name,data,mode,index+1) for index,(name,data,mode) in enumerate(entries))
    payload += cpio_member('TRAILER!!!',b'',0,999)
    with base.open('rb') as source:
        digest = hashlib.file_digest(source,'sha256').digest()
    identity = hashlib.sha256(digest+payload).hexdigest()
    destination = ROOT/'dist/linux-confinement'/('initrd-'+identity[:20]+'.gz')
    if not destination.exists():
        destination.parent.mkdir(parents=True,exist_ok=True)
        with base.open('rb') as source, destination.open('wb') as output:
            shutil.copyfileobj(source,output)
            output.write(gzip.compress(payload,mtime=0))
    return destination


def qemu_native_probe(backend: dict[str, object]) -> str:
    """Boot and execute real compiled ELF files without instrumentation; O(B) artifacts."""
    directory = cross_build_linux()
    images = Path(backend['images'])
    from scripts.guest_image import prepare_verification_initrd
    initrd = guest_initrd(directory,prepare_verification_initrd())
    with socket.socket() as reservation:
        reservation.bind(('127.0.0.1',0))
        port = reservation.getsockname()[1]
    command = backend['command']+['-M','virt','-cpu','cortex-a72','-m','1024','-smp','2','-kernel',str(images/'ubuntu-vmlinuz'),
              '-initrd',str(initrd),'-append','console=ttyAMA0 rdinit=/init lsm=landlock,yama,bpf quiet','-display','none','-nic','none',
              '-serial',f'tcp:127.0.0.1:{port},server,nowait','-monitor','none','-no-reboot']
    logs = ROOT/'dist/preflight'
    logs.mkdir(parents=True,exist_ok=True)
    transcript = ROOT/'.tmp/console-last.log'
    if transcript.exists():
        os.replace(transcript,logs/'native-previous-console.log')
    boot = {'memory_mib':1024,'initrd_bytes':initrd.stat().st_size,'booted':False}
    started = time.monotonic()
    with (logs/'native-guest.log').open('wb') as log:
        process = subprocess.Popen(command,stdout=log,stderr=log)
        try:
            deadline = time.monotonic()+240
            while True:
                try:
                    console(port,timeout=3)
                    break
                except (OSError,TimeoutError):
                    if process.poll() is not None or time.monotonic() > deadline:
                        raise OSError('native guest did not boot')
                    time.sleep(1)
            boot.update(booted=True,startup_seconds=time.monotonic()-started)
            setup = []
            for instruction in ['mkdir -p /proc /sys /work/.tmp','mount -t proc proc /proc','chmod 777 /work/.tmp','ls -ld /proc /proc/self/exe']:
                setup.append(console(port,instruction))
            (logs/'native-setup.log').write_text('\n'.join(setup),encoding='utf-8')
            text = console(port,'PYTHONDONTWRITEBYTECODE=1 TMPDIR=/work/.tmp /usr/bin/python3 /work/probe.py /work/native --drop-user',timeout=180)
            (logs/'native-console.log').write_text(text,encoding='utf-8')
            return text
        finally:
            boot['elapsed_seconds'] = time.monotonic()-started
            (logs/'native-boot.json').write_text(json.dumps(boot,indent=2),encoding='utf-8')
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
            transcript = ROOT/'.tmp/console-last.log'
            if transcript.exists():
                os.replace(transcript,logs/'native-console-last.log')


def verify_linux_confinement() -> dict[str, object]:
    """Require measured Linux kernel denials; O(B) bounded artifacts and output."""
    if sys.platform == 'linux':
        from verikernel.m2_enforcer.native_supervisor import target_binary
        command = [sys.executable,str(ROOT/'scripts/native_kernel_probe.py'),str(target_binary().parent)]
        result = subprocess.run(command,capture_output=True,text=True,timeout=90,check=True)
        text, backend = result.stdout,'native-linux'
    else:
        backend = next((item for item in discover_backends() if item['kind'] == 'qemu'),None)
        if backend is None:
            raise OSError('a real Linux runtime is required for the compiled confinement proof')
        text = qemu_native_probe(backend)
        backend = 'qemu-linux'
    lines = [line[len('VK_NATIVE_RESULT='):] for line in text.replace('\r','').splitlines() if line.startswith('VK_NATIVE_RESULT=')]
    if not lines:
        raise ValueError('compiled Linux guest emitted no valid result: '+text[-3000:])
    report = json.loads(lines[-1])
    if not report['verified'] or report['socket']['errno'] != 13 or report['spawn']['errno'] != 13 or report['landlock']['errno'] != 13:
        raise ValueError('native kernel denial evidence is invalid')
    report['backend'] = backend
    (ROOT/'benchmarks/results/native_linux_confinement.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
    return report


if __name__ == '__main__':
    print(json.dumps(verify_linux_confinement(),indent=2))
