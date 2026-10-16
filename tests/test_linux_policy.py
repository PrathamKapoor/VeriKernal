import pytest


def test_policy_export_resolves_declared_paths_without_granting_parent(tmp_path):
    from verikernel.m2_enforcer.linux_hal import export_policy
    file = tmp_path / "declared"
    file.write_text("data")
    policy = export_policy({"filesystem": [str(file)]}, runtime_paths=[], machine="aarch64")
    assert policy["read_write"] == [str(file.resolve())]
    assert str(tmp_path) not in policy["read_write"]
    assert policy["architecture"] == 0xC00000B7
    assert 56 in policy["notify_syscalls"]
    with pytest.raises(ValueError):
        export_policy({}, machine="unknown")


def test_per_cpu_kernel_ratchets_reject_missing_or_changed_events():
    import hashlib
    from verikernel.schemas import KernelTelemetryEvent
    from verikernel.m2_enforcer.linux_hal import verify_kernel_stream
    seeds = [bytes(32), bytes([1])*32]
    states = list(seeds)
    events = []
    for index, cpu in enumerate([0, 1, 0, 1]):
        event = KernelTelemetryEvent(seq_no=index)
        event.ratchet_tag = hashlib.blake2b(b"VK-RATCHET-TAG-V1"+states[cpu]+event.to_bytes()[:96], digest_size=32).digest()
        states[cpu] = hashlib.blake2b(b"VK-RATCHET-STEP-V1"+states[cpu]+event.ratchet_tag, digest_size=32).digest()
        events.append(event)
    assert verify_kernel_stream(events, seeds, states)
    assert not verify_kernel_stream(events[:-1], seeds, states)
    events[1].pid = 7
    assert not verify_kernel_stream(events, seeds, states)


def test_native_stream_seals_events_and_rejects_truncation():
    import io
    import json
    from verikernel.m2_enforcer.linux_hal import consume_native_stream
    from verikernel.m4_attest.ratchet import ForwardSecureRatchet, HASH_ALGORITHM
    from verikernel.schemas import KernelTelemetryEvent
    seed = bytes(range(32))
    ratchet = ForwardSecureRatchet(seed)
    records = [{"kind": "header", "hash_algorithm": HASH_ALGORITHM, "audit_seed": seed.hex(), "commitment": ratchet.commitment.hex()}]
    for index in range(3):
        event = KernelTelemetryEvent(seq_no=index, syscall_nr=2)
        ratchet.tag(event)
        records.append({"kind": "event", "bytes": event.to_bytes().hex(), "target": "declared"})
    records.append({"kind": "terminal", "status": 0, "terminal": ratchet.terminal.hex(), "event_count": 3})
    stream = "\n".join(json.dumps(record) for record in records)
    result, service = consume_native_stream(io.StringIO(stream))
    assert result["status"] == 0 and service.verify_epochs()
    assert len(service.events) == 3
    with pytest.raises(ValueError, match="terminal"):
        consume_native_stream(io.StringIO("\n".join(json.dumps(record) for record in records[:-1])))
    records[1]["bytes"] = bytes(128).hex()
    with pytest.raises(ValueError, match="authentication"):
        consume_native_stream(io.StringIO("\n".join(json.dumps(record) for record in records)))
