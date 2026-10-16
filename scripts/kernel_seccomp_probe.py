"""Kernel seccomp probe."""
from __future__ import annotations
from typing import Any
import ctypes
import hashlib
import json
import os
import platform
import struct
import sys
import time
import signal
from pathlib import Path


def probe() -> Any:
    """Execute the kernel capability checks and collect their results. Complexity: O(b + W) time and O(b + M) space; b is captured input/output, W external verification work, M retained measurements."""
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
    from verikernel.m2_enforcer.seccomp_bpf import compile_seccomp_bpf
    machine = platform.machine()
    arch, random_nr, clock_nr = (0xc00000b7,278,113) if machine == 'aarch64' else (0xc000003e,318,228) if machine == 'x86_64' else (0,0,0)
    if not arch:
        raise OSError('unsupported kernel architecture')
    program = compile_seccomp_bpf([clock_nr], {random_nr:13}, arch)
    class Filter(ctypes.Structure):
        """Filter. Complexity: O(b + W) time and O(b + M) space; b is captured input/output, W external verification work, M retained measurements."""
        _fields_ = [('code',ctypes.c_ushort),('jt',ctypes.c_ubyte),('jf',ctypes.c_ubyte),('k',ctypes.c_uint)]
    class Program(ctypes.Structure):
        """Program. Complexity: O(b + W) time and O(b + M) space; b is captured input/output, W external verification work, M retained measurements."""
        _fields_ = [('len',ctypes.c_ushort),('filter',ctypes.POINTER(Filter))]
    filters = (Filter*(len(program)//8)).from_buffer_copy(program)
    policy = Program(len(filters),filters)
    libc = ctypes.CDLL(None,use_errno=True)
    reader, writer = os.pipe()
    child = os.fork()
    if child == 0:
        os.close(reader)
        try:
            if os.geteuid() == 0:
                os.setgroups([])
                os.setgid(65534)
                os.setuid(65534)
            if libc.prctl(38,1,0,0,0) or libc.prctl(22,2,ctypes.byref(policy),0,0):
                raise OSError(ctypes.get_errno(),'seccomp installation failed')
            key = bytes(range(32))
            commitment = hashlib.blake2b(b'VK-RATCHET-COMMIT-V1'+key,digest_size=32).hexdigest()
            events, observations = [], []
            for index, (nr, operation, expected) in enumerate([(random_nr,7,13),(clock_nr,6,38)]):
                buffer = ctypes.create_string_buffer(32)
                ctypes.set_errno(0)
                returned = libc.syscall(nr,ctypes.byref(buffer),1,0)
                error = ctypes.get_errno()
                if returned != -1 or error != expected:
                    raise AssertionError('kernel verdict differs from compiled policy')
                payload = struct.pack('<QQIIIIQQQQ32s', index,time.monotonic_ns(),os.getpid(),os.getpid(),operation,(-error)&0xffffffff,0,0,0,0,hashlib.sha256(str(nr).encode()).digest())
                tag = hashlib.blake2b(b'VK-RATCHET-TAG-V1'+key+payload,digest_size=32).digest()
                key = hashlib.blake2b(b'VK-RATCHET-STEP-V1'+key+tag,digest_size=32).digest()
                events.append((payload+tag).hex())
                observations.append({'syscall':nr,'errno':error,'result':returned})
            result = {'verified':True,'kernel':platform.release(),'machine':machine,'uid':os.getuid(),'program_hex':program.hex(),'events':events,'observations':observations,'audit_seed':bytes(range(32)).hex(),'commitment':commitment,'terminal':key.hex(),'hash_algorithm':'blake2b-256'}
            os.write(writer,json.dumps(result).encode())
            os._exit(0)
        except BaseException as error:
            os.write(writer,json.dumps({'verified':False,'error':str(error)}).encode())
            os._exit(1)
    os.close(writer)
    chunks = []
    while True:
        chunk = os.read(reader,8192)
        if not chunk:
            break
        chunks.append(chunk)
    os.close(reader)
    _, status = os.waitpid(child,0)
    result = json.loads(b''.join(chunks))
    if status or not result.get('verified'):
        raise OSError(str(result))
    wrong_arch = 0xc000003e if arch == 0xc00000b7 else 0xc00000b7
    rejected = compile_seccomp_bpf([],arch=wrong_arch)
    wrong_filters = (Filter*(len(rejected)//8)).from_buffer_copy(rejected)
    wrong_policy = Program(len(wrong_filters),wrong_filters)
    guard_child = os.fork()
    if guard_child == 0:
        if os.geteuid() == 0:
            os.setgroups([])
            os.setgid(65534)
            os.setuid(65534)
        if libc.prctl(38,1,0,0,0) or libc.prctl(22,2,ctypes.byref(wrong_policy),0,0):
            os._exit(2)
        os._exit(0)
    _, guard_status = os.waitpid(guard_child,0)
    if not os.WIFSIGNALED(guard_status) or os.WTERMSIG(guard_status) != signal.SIGSYS:
        raise AssertionError('kernel architecture guard did not kill the mismatched child')
    result['architecture_mismatch_signal'] = os.WTERMSIG(guard_status)
    print('VK_RESULT='+json.dumps(result),flush=True)
    return result


if __name__ == '__main__':
    probe()
