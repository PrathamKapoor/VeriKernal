import pytest


def test_splitmix_and_schedule_identity():
    from verikernel.m3_fault.injector import splitmix64, SyscallFaultInjector
    assert splitmix64(0) == 0xE220A8397B1DCDAF
    a, b = SyscallFaultInjector(42, 1), SyscallFaultInjector(42, 1)
    for op in [2, 9, 10] * 10:
        assert a.select(op, 123) == b.select(op, 123)
    replay = SyscallFaultInjector(42, 0, schedule=a.schedule, active_sites={7, 23})
    faults = [replay.select(op, 123) for op in [2, 9, 10] * 10]
    assert [i for i, f in enumerate(faults) if f] == [7, 23]
    with pytest.raises(ValueError):
        SyscallFaultInjector(1, -1)


def test_ddmin_two_causes_and_empty_failure():
    from verikernel.m3_fault.ddmin import DeltaDebuggingShrinker
    shrinker = DeltaDebuggingShrinker(lambda s: 7 in s and 23 in s)
    assert shrinker.shrink(range(32)) == [7, 23]
    assert shrinker.evaluations < 40
    assert DeltaDebuggingShrinker(lambda s: True).shrink(range(4)) == []
    with pytest.raises(ValueError):
        DeltaDebuggingShrinker(lambda s: False).shrink([1])


def test_bundle_roundtrip_and_corrupt_container(tmp_path):
    from verikernel.m3_fault.replay import write_container, read_container
    from verikernel.schemas import KernelTelemetryEvent
    path = tmp_path / "run.vkr"
    write_container(path, {"test": 7}, [KernelTelemetryEvent(seq_no=2)])
    metadata, events = read_container(path)
    assert metadata == {"test": 7} and events[0].seq_no == 2
    path.write_bytes(path.read_bytes()[:-1])
    with pytest.raises(ValueError):
        read_container(path)
