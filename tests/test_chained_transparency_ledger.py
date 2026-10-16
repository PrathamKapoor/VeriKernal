import copy
import hashlib
import pytest
from verikernel.schemas import KernelTelemetryEvent
from verikernel.m4_attest.pqc_signer import MLDSA65Signer
from verikernel.m4_attest.dsse_envelope import seal
from verikernel.m4_attest.merkle_tiles import mth,sha256_digest


def test_chained_epochs_consistency_rewrite_and_pinned_rollback(tmp_path):
    from verikernel.m4_attest.ledger_store import ChainedTransparencyLedger,verify_ledger_history
    signer=MLDSA65Signer(seed=bytes([19])*32)
    ledger=ChainedTransparencyLedger(tmp_path/'ledger',signer)
    for size in [3,5,2]:
        ledger.append([KernelTelemetryEvent(syscall_nr=2,inode_nr=i+1) for i in range(size)])
    history=ledger.export_history()
    anchor=history['epochs'][-1]['sth']
    assert verify_ledger_history(tmp_path/'ledger',trusted_checkpoint=anchor)['tree_size']==10
    assert verify_ledger_history(history)['epochs']==3
    rolled=copy.deepcopy(history)
    rolled['epochs'].pop()
    with pytest.raises(ValueError,match='rollback'):
        verify_ledger_history(rolled,trusted_checkpoint=anchor)
    rewritten=copy.deepcopy(history)
    epoch=rewritten['epochs'][0]
    raw=bytearray.fromhex(epoch['leaves'][0]); raw[64]^=1
    epoch['leaves'][0]=raw.hex()
    epoch['sth']['merkle_root']=mth([bytes.fromhex(v) for v in epoch['leaves']],sha256_digest).hex()
    epoch['envelope']=seal(epoch['sth'],signer)
    with pytest.raises(ValueError):
        verify_ledger_history(rewritten)
    from verikernel.rust_bridge import BatchEngine
    packed=bytearray(b''.join(bytes.fromhex(v) for v in epoch['leaves']))
    c0,kn=BatchEngine().seal(packed,bytes.fromhex(epoch['audit_seed']))
    epoch['leaves']=[packed[i:i+128].hex() for i in range(0,len(packed),128)]
    epoch['sth'].update(merkle_root=BatchEngine().root(packed).hex(),epoch_root=BatchEngine().root(packed).hex(),epoch_ratchet_c0=c0.hex(),epoch_ratchet_kn=kn.hex())
    epoch['envelope']=seal(epoch['sth'],signer)
    with pytest.raises(ValueError,match='cross-epoch'):
        verify_ledger_history(rewritten)
    changed=copy.deepcopy(history)
    changed['epochs'][1]['consistency_proof'][0]='00'*32
    with pytest.raises(ValueError,match='consistency'):
        verify_ledger_history(changed)


def test_ledger_reopen_rejects_wrong_signer_and_bad_head(tmp_path):
    from verikernel.m4_attest.ledger_store import ChainedTransparencyLedger,verify_ledger_history
    signer=MLDSA65Signer(seed=bytes([8])*32)
    ledger=ChainedTransparencyLedger(tmp_path/'ledger',signer)
    ledger.append([KernelTelemetryEvent()])
    reopened=ChainedTransparencyLedger(tmp_path/'ledger',signer)
    reopened.append([KernelTelemetryEvent()])
    assert verify_ledger_history(tmp_path/'ledger')['tree_size']==2
    with pytest.raises(ValueError):
        ChainedTransparencyLedger(tmp_path/'ledger',MLDSA65Signer())
