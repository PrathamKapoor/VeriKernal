from concurrent.futures import ThreadPoolExecutor
from verikernel.schemas import KernelTelemetryEvent


def test_v02_threaded_delivery_deduplication_and_order():
    from verikernel.m5_ringbuf.zero_drop_v02 import ZeroDropRingBufferV02
    queue = ZeroDropRingBufferV02()
    def worker(cpu):
        for i in range(100):
            queue.push(KernelTelemetryEvent(seq_no=i*4+cpu, syscall_nr=2, inode_nr=i*4+cpu+1, dev_id=1), cpu)
    with ThreadPoolExecutor(4) as pool:
        list(pool.map(worker, range(4)))
    events = queue.drain()
    assert [e.seq_no for e in events] == list(range(400))
    assert queue.drops == 0
    assert queue.push(KernelTelemetryEvent(seq_no=400, syscall_nr=2, inode_nr=1, dev_id=1)) is False


def test_baseline_overflows_and_cross_cpu_reorders():
    from verikernel.m5_ringbuf.baseline_v01 import FlawedBaselineRingBufferV01
    queue = FlawedBaselineRingBufferV01(capacity=8)
    for i in range(100):
        queue.push(KernelTelemetryEvent(seq_no=i), i % 4)
    events = queue.drain()
    assert queue.drops == 68
    assert any(a.seq_no > b.seq_no for a, b in zip(events, events[1:]))


def test_native_fifo_reports_backpressure_and_preserves_wire_bytes():
    from verikernel.m5_ringbuf.native import NativeEventQueue
    with NativeEventQueue(capacity=2) as queue:
        assert queue.try_push(KernelTelemetryEvent(seq_no=1, fault_injected=-11))
        assert queue.try_push(KernelTelemetryEvent(seq_no=2))
        assert not queue.try_push(KernelTelemetryEvent(seq_no=3))
        first = queue.try_pop()
        assert first.seq_no == 1 and first.fault_injected == -11
        assert queue.try_pop().seq_no == 2
        assert queue.try_pop() is None


def test_streaming_drain_waits_for_publications_and_advances_over_dedup():
    from verikernel.m5_ringbuf.zero_drop_v02 import ZeroDropRingBufferV02
    queue = ZeroDropRingBufferV02(cpus=2, l1_capacity=1)
    queue.push(KernelTelemetryEvent(seq_no=1, syscall_nr=2, inode_nr=2), 1)
    assert queue.drain() == []
    queue.push(KernelTelemetryEvent(seq_no=0, syscall_nr=2, inode_nr=1), 0)
    assert [event.seq_no for event in queue.drain()] == [0, 1]
    assert not queue.push(KernelTelemetryEvent(seq_no=2, syscall_nr=2, inode_nr=1), 0)
    queue.push(KernelTelemetryEvent(seq_no=3, syscall_nr=2, inode_nr=3), 1)
    assert [event.seq_no for event in queue.drain()] == [3]
