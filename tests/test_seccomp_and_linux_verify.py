import struct
import pytest


def test_architecture_guard_errno_and_notification_dispatch():
    from verikernel.m2_enforcer.seccomp_bpf import compile_seccomp_bpf, execute_cbpf_vm
    for arch in [0xc000003e, 0xc00000b7]:
        program = compile_seccomp_bpf([0, 257], {3: 13}, arch)
        assert program[:8] == bytes.fromhex('2000000004000000')
        for syscall, verdict in [(0,0x7fc00000),(257,0x7fc00000),(3,0x5000d),(4,0x7fff0000)]:
            assert execute_cbpf_vm(program, syscall, arch) == verdict
        assert execute_cbpf_vm(program, 0, 0x40000003) == 0x80000000
    assert execute_cbpf_vm(compile_seccomp_bpf([]), 0x40000001) == 0x80000000


def test_verifier_rejects_unreachable_bad_jumps_and_malformed_programs():
    from verikernel.m2_enforcer.seccomp_bpf import execute_cbpf_vm, compile_seccomp_bpf
    for program in [b'', b'x', struct.pack('<HBBI',0x15,255,0,1), struct.pack('<HBBI',0x20,0,0,64), struct.pack('<HBBI',0xffff,0,0,0)]:
        with pytest.raises(ValueError):
            execute_cbpf_vm(program, 1)
    with pytest.raises(ValueError):
        compile_seccomp_bpf([1], {1: 13})
    with pytest.raises(ValueError):
        compile_seccomp_bpf(list(range(3000)))


def test_linux_runtime_discovery_is_bounded_and_reports_capabilities():
    from scripts.verify_linux_env import discover_backends
    found = discover_backends()
    assert isinstance(found, list)
    assert all(item['kind'] in {'native','wsl','docker','qemu'} for item in found)


def test_guest_transport_survives_terminal_limits_and_cursor_queries():
    import base64
    from scripts.verify_linux_env import guest_transfer_commands, is_console_ready
    original = bytes(range(256))*30
    commands = guest_transfer_commands(original,'/work/scripts/check.py')
    encoded = ''.join(command.split("'")[3] for command in commands if command.startswith('printf'))
    assert base64.b64decode(encoded) == original
    assert max(map(len,commands)) < 1024
    assert is_console_ready(b'/ # \x1b[6n')
    assert not is_console_ready(b'kernel starting')
def test_console_ignores_stale_prompt_until_command_completion(monkeypatch):
    import re
    import scripts.verify_linux_env as harness
    class Connection:
        def __init__(self):
            self.sent = bytearray()
            self.reads = 0
        def __enter__(self):
            return self
        def __exit__(self, *args):
            return False
        def settimeout(self, value):
            self.timeout = value
        def sendall(self, data):
            self.sent.extend(data)
        def recv(self, size):
            self.reads += 1
            if self.reads == 1:
                return b'/ # '
            token = re.search(rb"'VK_DONE_' '([0-9a-f]{32})'",bytes(self.sent))
            assert token is not None
            return b'executed-result\nVK_DONE_'+token[1]+b'\n/ # '
    connection = Connection()
    monkeypatch.setattr(harness.socket,'create_connection',lambda *args,**kwargs:connection)
    monkeypatch.setattr(harness.time,'sleep',lambda value:None)
    assert 'executed-result' in harness.console(42,'echo executed-result',timeout=2)
    assert connection.reads == 2
