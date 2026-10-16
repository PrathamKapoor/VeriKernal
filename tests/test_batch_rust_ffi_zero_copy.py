import hashlib
import random
from collections import OrderedDict
import pytest
from verikernel.schemas import KernelTelemetryEvent


@pytest.mark.parametrize('count',[0,1,2,3,7,16,63,128,1000])
def test_batch_profile_matches_independent_sha256(count):
    from verikernel.rust_bridge import BatchEngine
    engine = BatchEngine()
    assert engine.native
    rng = random.Random(count)
    events = [KernelTelemetryEvent(seq_no=i,syscall_nr=2,inode_nr=rng.randrange(5),dev_id=1,mtime_ns=9) for i in range(count)]
    original = bytearray(b''.join(e.to_bytes() for e in events))
    seed = bytes([66])*32
    for native in [True,False]:
        bridge = BatchEngine(native=native)
        buffer = bytearray(original)
        assert bridge.sha256(buffer)==hashlib.sha256(buffer).digest()
        c0,kn = bridge.seal(buffer,seed)
        state = seed
        for index in range(count):
            prefix = bytes(original[index*128:index*128+96])
            tag = hashlib.sha256(b'VK-RATCHET-TAG-V1'+state+prefix).digest()
            assert buffer[index*128+96:index*128+128]==tag
            state = hashlib.sha256(b'VK-RATCHET-STEP-V1'+state+tag).digest()
        assert kn==state and c0==hashlib.sha256(b'VK-RATCHET-COMMIT-V1'+seed).digest()
        assert bridge.verify(buffer,seed,c0,kn)==(0,-1)
        def root(leaves):
            if not leaves:
                return hashlib.sha256(b'').digest()
            if len(leaves)==1:
                return hashlib.sha256(b'\0'+leaves[0]).digest()
            k=1<<((len(leaves)-1).bit_length()-1)
            return hashlib.sha256(b'\1'+root(leaves[:k])+root(leaves[k:])).digest()
        assert bridge.root(buffer)==root([bytes(buffer[i:i+128]) for i in range(0,len(buffer),128)])
        cache,mask = OrderedDict(),bytearray()
        for event in events:
            key=(event.syscall_nr,event.dev_id,event.inode_nr,event.mtime_ns)
            seen=key in cache
            if seen:
                cache.move_to_end(key)
            else:
                cache[key]=True
                if len(cache)>3:
                    cache.popitem(last=False)
            mask.append(0 if seen else 1)
        assert bridge.dedup(original,3)==mask
        if count:
            buffer[64]^=1
            assert bridge.verify(buffer,seed,c0,kn)==(-1,0)
            buffer[64]^=1
            assert bridge.verify(buffer[:-128],seed,c0,kn)==(-2,count-1)


def test_batch_rejects_misaligned_and_invalid_keys():
    from verikernel.rust_bridge import BatchEngine
    with pytest.raises(ValueError):
        BatchEngine().seal(bytearray(127),bytes(32))
    with pytest.raises(ValueError):
        BatchEngine().seal(bytearray(128),bytes(31))


def test_batch_benchmark_measures_native_work_and_ledger(tmp_path):
    from benchmarks.run_benchmarks import benchmark_batch_ledger
    result=benchmark_batch_ledger(tmp_path,128)
    assert result['native_loaded']
    assert result['native']['kept_events']==result['python']['kept_events']
    assert result['ledger']['epochs']==4 and result['ledger']['tree_size']==128
    assert result['ledger']['verified'] and result['ledger']['anchored']
    assert result['native']['dedup_events_sec']>0


def test_batch_falls_back_for_older_scalar_abi(monkeypatch):
    import verikernel.rust_bridge as bridge
    from types import SimpleNamespace
    monkeypatch.setattr(bridge._bridge,'library',SimpleNamespace())
    engine=bridge.BatchEngine()
    assert not engine.native
    assert engine.sha256(bytearray(b'abc'))==hashlib.sha256(b'abc').digest()
