"""Verify linux env."""
from __future__ import annotations
from typing import Any
import argparse
import base64
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import time
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def is_console_ready(output: Any) -> Any:
    """Recognize the guest console readiness marker. Complexity: O(b + W) time and O(b + M) space; b is captured input/output, W external verification work, M retained measurements."""
    return re.sub(rb'\x1b\[[0-9;?]*[A-Za-z]',b'',output).endswith(b'/ # ')


def guest_transfer_commands(data: Any, target: Any) -> Any:
    """Encode source transfer commands for the bounded serial channel. Complexity: O(b + W) time and O(b + M) space; b is captured input/output, W external verification work, M retained measurements."""
    if not re.fullmatch(r'/work/[A-Za-z0-9_./-]+',target) or '..' in target.split('/'):
        raise ValueError('unsupported guest transfer path')
    encoded = base64.b64encode(data).decode()
    return [': > '+target+'.b64'] + ["printf '%s' '"+encoded[index:index+512]+"' >> "+target+'.b64' for index in range(0,len(encoded),512)] + ['base64 -d '+target+'.b64 > '+target]


def discover_backends() -> Any:
    """Discover available Linux execution backends without installing tools. Complexity: O(b + W) time and O(b + M) space; b is captured input/output, W external verification work, M retained measurements."""
    result = []
    if sys.platform == 'linux':
        result.append({'kind':'native','command':[sys.executable]})
    if shutil.which('wsl'):
        check = subprocess.run(['wsl','--list','--quiet'],capture_output=True,timeout=15)
        if check.returncode == 0 and check.stdout.replace(b'\x00',b'').strip():
            result.append({'kind':'wsl','command':['wsl','--exec','python3']})
    if shutil.which('docker'):
        check = subprocess.run(['docker','info','--format','{{.OSType}}'],capture_output=True,timeout=15)
        if check.returncode == 0 and b'linux' in check.stdout:
            result.append({'kind':'docker','command':['docker']})
    executable = ROOT / 'dist/development/qemu/qemu-system-aarch64.exe'
    images = ROOT / 'dist/development/linux-vm'
    if executable.exists() and (images/'ubuntu-combined-initrd.gz').exists():
        result.append({'kind':'qemu','command':[str(executable)],'images':str(images)})
    return result


def console(port: Any, command: str='', timeout: int=60) -> Any:
    """Exchange a command and its completion marker with the guest console. Complexity: O(b + W) time and O(b + M) space; b is captured input/output, W external verification work, M retained measurements."""
    with socket.create_connection(('127.0.0.1',port),timeout=10) as connection:
        connection.settimeout(.2)
        token = uuid.uuid4().hex if command else ''
        framed = command+"; printf '\\n%s%s\\n' 'VK_DONE_' '"+token+"'" if command else ''
        data = (framed+'\r').encode()
        for offset in range(0,len(data),6):
            connection.sendall(data[offset:offset+6])
            time.sleep(.02)
        deadline = time.monotonic()+timeout
        output = b''
        while time.monotonic() < deadline:
            try:
                chunk = connection.recv(16384)
                if not chunk:
                    break
                output += chunk
                (ROOT/'.tmp/console-last.log').write_bytes(output)
                complete = re.search(rb'(?:^|[\r\n])VK_DONE_'+token.encode()+rb'[\r\n]',output) if command else is_console_ready(output)
                if complete:
                    return output.decode(errors='replace')
            except socket.timeout:
                time.sleep(.02)
        raise TimeoutError('guest console did not return its readiness marker')


def qemu_probe(backend: Any) -> Any:
    """Boot the contained Linux guest and execute the kernel probe. Complexity: O(b + W) time and O(b + M) space; b is captured input/output, W external verification work, M retained measurements."""
    with socket.socket() as reservation:
        reservation.bind(('127.0.0.1',0))
        port = reservation.getsockname()[1]
    images = Path(backend['images'])
    from scripts.guest_image import prepare_verification_initrd
    initrd = prepare_verification_initrd()
    command = backend['command'] + ['-M','virt','-cpu','cortex-a72','-m','1024','-smp','2','-kernel',str(images/'ubuntu-vmlinuz'),'-initrd',str(initrd),'-append','console=ttyAMA0 rdinit=/init lsm=landlock,yama,bpf quiet','-display','none','-serial',f'tcp:127.0.0.1:{port},server,nowait','-monitor','none','-no-reboot']
    with (ROOT/'.tmp/linux-guest.log').open('wb') as log:
        process = subprocess.Popen(command,stdout=log,stderr=log)
        try:
            deadline = time.monotonic()+240
            while True:
                try:
                    console(port,timeout=3)
                    break
                except (OSError,TimeoutError):
                    if process.poll() is not None or time.monotonic()>deadline:
                        raise OSError('Linux guest boot failed')
                    time.sleep(1)
            console(port,'mkdir -p /proc /sys /work/.tmp /work/src/verikernel/m2_enforcer /work/scripts')
            console(port,'mount -t proc proc /proc')
            for source, target in [('src/verikernel/m2_enforcer/seccomp_bpf.py','/work/src/verikernel/m2_enforcer/seccomp_bpf.py'),('scripts/kernel_seccomp_probe.py','/work/scripts/kernel_seccomp_probe.py')]:
                for transfer in guest_transfer_commands((ROOT/source).read_bytes(),target):
                    console(port,transfer,timeout=15)
            response = console(port,'PYTHONDONTWRITEBYTECODE=1 TMPDIR=/work/.tmp /usr/bin/python3 /work/scripts/kernel_seccomp_probe.py',timeout=180)
            (ROOT/'.tmp/linux-console.log').write_text(response,encoding='utf-8')
            return response
        finally:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()


def verify(output: Any=None) -> dict[str, Any]:
    """Validate the captured evidence and return the verification result. Complexity: O(b + W) time and O(b + M) space; b is captured input/output, W external verification work, M retained measurements."""
    (ROOT/'.tmp').mkdir(exist_ok=True)
    attempts, verified = [], None
    for backend in discover_backends():
        try:
            kind = backend['kind']
            if kind == 'qemu':
                text = qemu_probe(backend)
            else:
                command = backend['command']
                if kind == 'native':
                    command += [str(ROOT/'scripts/kernel_seccomp_probe.py')]
                elif kind == 'wsl':
                    mapped = subprocess.check_output(['wsl','--exec','wslpath','-a',str(ROOT)],text=True).strip()
                    command += [mapped+'/scripts/kernel_seccomp_probe.py']
                else:
                    command += ['run','--rm','--network','none','--mount',f'type=bind,source={ROOT},target=/repo','-w','/repo','-e','PYTHONDONTWRITEBYTECODE=1','-e','TMPDIR=/repo/.tmp','python:3.12-bookworm','python','scripts/kernel_seccomp_probe.py']
                completed = subprocess.run(command,capture_output=True,text=True,timeout=180,check=True)
                text = completed.stdout
            lines = [line for line in text.replace('\r','').splitlines() if line.startswith('VK_RESULT=')]
            if not lines:
                raise ValueError('guest emitted no result: '+text[-2000:])
            line = lines[-1]
            verified = json.loads(line[len('VK_RESULT='):])
            from verikernel.m2_enforcer.linux_hal import verify_kernel_stream
            from verikernel.schemas import KernelTelemetryEvent
            if not verify_kernel_stream([KernelTelemetryEvent.from_bytes(bytes.fromhex(event)) for event in verified['events']],[bytes.fromhex(verified['audit_seed'])],[bytes.fromhex(verified['terminal'])]):
                raise ValueError('kernel telemetry authentication failed')
            verified['backend'] = kind
            break
        except (OSError,ValueError,TimeoutError,StopIteration,subprocess.SubprocessError) as error:
            attempts.append({'backend':backend['kind'],'error':str(error)})
    report = {'verified':verified is not None,'execution':verified,'failed_attempts':attempts}
    destination = Path(output or ROOT/'benchmarks/results/linux_verification.json')
    destination.parent.mkdir(parents=True,exist_ok=True)
    destination.write_text(json.dumps(report,indent=2),encoding='utf-8')
    if verified is None:
        raise OSError('no executable Linux runtime verified; see '+str(destination))
    return report


if __name__ == '__main__':
    sys.path.insert(0,str(ROOT/'src'))
    parser = argparse.ArgumentParser()
    parser.add_argument('--output')
    arguments = parser.parse_args()
    print(json.dumps(verify(arguments.output),indent=2))
