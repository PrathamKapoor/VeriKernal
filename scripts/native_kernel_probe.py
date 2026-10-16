"""Execute uninstrumented compiled controls and attacks; O(B) bounded output space."""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import tempfile


def run_probe(directory: str) -> dict[str, object]:
    """Compare real unrestricted and restricted syscalls; O(B) retained output."""
    binary = Path(directory)/'vk-target-bin'
    launcher = Path(directory)/'verikernel-sandbox-exec'
    def execute(arguments: list[str], expected: int) -> dict[str, object]:
        """Run one bounded target and parse its actual result; O(B) output work/space."""
        print('VK_NATIVE_STAGE='+arguments[-1],flush=True)
        result = subprocess.run(arguments,capture_output=True,text=True,timeout=20)
        if result.returncode != expected:
            raise ValueError('unexpected target exit: '+str(result.returncode)+' '+result.stdout+' '+result.stderr)
        rows = [json.loads(line) for line in result.stdout.splitlines() if line.startswith('{')]
        if not rows:
            raise ValueError('target emitted no measurement')
        return {**rows[-1],'returncode':result.returncode}
    with tempfile.TemporaryDirectory(dir=os.environ['TMPDIR'],prefix='native_probe_') as name:
        temporary = Path(name)
        marker = temporary/'child.marker'
        secret = temporary/'outside-allowed-root'
        secret.write_text('kernel-policy-control',encoding='utf-8')
        socket_control = execute([str(binary),'--uncooperative-banned-syscall'],0)
        spawn_control = execute([str(binary),'--uncooperative-spawn','--marker',str(marker)],0)
        if not marker.is_file():
            raise ValueError('unrestricted child did not create its marker')
        marker.unlink()
        read_control = execute([str(binary),'--uncooperative-read',str(secret)],0)
        prefix = [str(launcher),'--memory-bytes','0']
        socket_denial = execute([*prefix,'--',str(binary),'--uncooperative-banned-syscall'],77)
        spawn_denial = execute([*prefix,'--',str(binary),'--uncooperative-spawn','--marker',str(marker)],77)
        roots = [directory]
        for candidate in ['/lib','/lib64','/usr/lib','/etc/ld.so.cache']:
            if Path(candidate).exists():
                roots.append(candidate)
        read_prefix = prefix[:]
        for root in roots:
            read_prefix += ['--read-root',root]
        read_denial = execute([*read_prefix,'--',str(binary),'--uncooperative-read',str(secret)],77)
        if marker.exists() or socket_denial.get('errno') != 13 or spawn_denial.get('errno') != 13 or read_denial.get('errno') != 13:
            raise ValueError('kernel did not produce the required EACCES denials')
        return {'verified':True,'kernel':platform.release(),'machine':platform.machine(),'uid':os.getuid(),
                'socket':socket_denial,'spawn':spawn_denial,'landlock':read_denial,
                'controls':{'socket_succeeded':not socket_control['denied'],'spawn_succeeded':not spawn_control['denied'],'read_succeeded':not read_control['denied']},
                'target_sha256':hashlib.sha256(binary.read_bytes()).hexdigest(),
                'launcher_sha256':hashlib.sha256(launcher.read_bytes()).hexdigest()}


if __name__ == '__main__':
    print('VK_NATIVE_STAGE=runtime-ready',flush=True)
    if '--drop-user' in sys.argv and os.geteuid() == 0:
        os.setgroups([])
        os.setgid(65534)
        os.setuid(65534)
    print('VK_NATIVE_RESULT='+json.dumps(run_probe(sys.argv[1]),sort_keys=True))
