import os
import pytest


def test_lru_refreshes_mtime_and_eviction():
    from verikernel.m2_enforcer.deduplicator import InodeDeduplicator
    cache = InodeDeduplicator(2)
    assert not cache.seen(2, 1, 2, 3)
    assert cache.seen(2, 1, 2, 3)
    assert not cache.seen(2, 1, 2, 4)
    assert not cache.seen(2, 1, 3, 1)
    assert not cache.seen(2, 1, 2, 3)


def test_strict_blocks_undeclared_files_and_inactive_hook_is_inert(tmp_path):
    from verikernel.m2_enforcer.hal import RuntimeInterceptorHAL
    path = tmp_path / "secret"
    path.write_text("secret")
    with RuntimeInterceptorHAL({"filesystem": []}, mode="strict", target_root=tmp_path) as hal:
        with pytest.raises(PermissionError):
            open(path).read()
    assert path.read_text() == "secret"
    assert hal.violations[0]["kind"] == "GHOST_FILESYSTEM"


def test_trace_emits_ghost_diff_and_deduplicates(tmp_path):
    from verikernel.m2_enforcer.hal import RuntimeInterceptorHAL
    path = tmp_path / "file"
    path.write_text("abc")
    with RuntimeInterceptorHAL({}, target_root=tmp_path) as hal:
        for _ in range(5):
            with open(path) as stream:
                assert stream.read() == "abc"
    assert len(hal.events) == 2
    assert {event.syscall_nr for event in hal.events} == {2, 9}
    assert hal.ghost_patch()["add"]["filesystem"] == [str(path.resolve())]


def test_canonical_policy_rejects_parent_escape(tmp_path):
    from verikernel.m2_enforcer.diff_engine import ContractEnforcer
    policy = ContractEnforcer({"filesystem": [str(tmp_path / "allowed")]})
    assert policy.violation(2, str(tmp_path / "allowed" / ".." / "secret"))["kind"] == "GHOST_FILESYSTEM"


def test_transparent_file_shim_injects_partial_reads(tmp_path):
    from verikernel.m2_enforcer.hal import RuntimeInterceptorHAL
    from verikernel.m3_fault.injector import SyscallFaultInjector
    path = tmp_path / "data"
    path.write_bytes(b"abcdefgh")
    schedule = [{"site_id": 0, "syscall_nr": 9, "stack_hash": 14695981039346656037, "ordinal": 0, "code": 1, "kind": "SHORT_READ"}]
    injector = SyscallFaultInjector(schedule=schedule, syscall_types={9})
    with RuntimeInterceptorHAL({}, target_root=tmp_path, injector=injector):
        with open(path, "rb") as stream:
            assert stream.read(8) == b"abcd"


def test_thread_file_audits_are_observed(tmp_path):
    from concurrent.futures import ThreadPoolExecutor
    from verikernel.m2_enforcer.hal import RuntimeInterceptorHAL
    path = tmp_path / "thread-data"
    path.write_bytes(b"x")
    def read():
        with open(path, "rb") as stream:
            return stream.read()
    with RuntimeInterceptorHAL({}, target_root=tmp_path) as hal:
        with ThreadPoolExecutor(1) as pool:
            assert pool.submit(read).result() == b"x"
    assert any(event.syscall_nr == 9 for event in hal.events)


def test_subprocess_pipes_remain_usable(tmp_path):
    import subprocess
    import sys
    from verikernel.m2_enforcer.hal import RuntimeInterceptorHAL
    with RuntimeInterceptorHAL({}, target_root=tmp_path) as hal:
        result = subprocess.run([sys.executable, "-c", "print(7)"], capture_output=True, text=True, timeout=30)
    assert result.returncode == 0 and result.stdout.strip() == "7"
    assert any(event.syscall_nr == 1 for event in hal.events)


def test_socket_partial_read_and_random_boundary(tmp_path):
    import socket
    from verikernel.m2_enforcer.hal import RuntimeInterceptorHAL
    from verikernel.m3_fault.injector import SyscallFaultInjector
    schedule = [{"site_id": 0, "syscall_nr": 9, "stack_hash": 14695981039346656037, "ordinal": 0, "code": 1, "kind": "SHORT_READ"}]
    left, right = socket.socketpair()
    try:
        right.sendall(b"abcdefgh")
        with RuntimeInterceptorHAL({}, target_root=tmp_path, injector=SyscallFaultInjector(schedule=schedule, syscall_types={9})) as hal:
            assert left.recv(8) == b"abcd"
            assert len(os.urandom(12)) == 12
        assert any(event.syscall_nr == 7 for event in hal.events)
    finally:
        left.close()
        right.close()
