"""Immutable epoch records and externally anchored SHA-256 ledgers; O(n) storage."""
from __future__ import annotations
import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets
import tempfile
from verikernel.schemas import KernelTelemetryEvent
from verikernel.rust_bridge import BatchEngine
from .dsse_envelope import seal,verify,statement_payload
from .pqc_signer import MLDSA65Signer
from .merkle_tiles import mth,prove_consistency,verify_consistency,sha256_digest,publish_immutable


def canonical(value: object) -> bytes:
    """Canonical JSON serialization; O(n) time and space in serialized length."""
    return json.dumps(value,sort_keys=True,separators=(',',':')).encode()


def sth_hash(sth: dict[str,object]) -> str:
    """Domain-separated checkpoint identity; O(n) time, O(n) JSON workspace."""
    return hashlib.sha256(b'VK-CHAINED-STH-V1'+canonical(sth)).hexdigest()


def load_history(directory: str | Path) -> dict[str,object]:
    """Read committed records and private audit seeds; O(n) time and space."""
    directory = Path(directory)
    head = json.loads((directory/'HEAD.json').read_text(encoding='utf-8'))
    records = []
    for index in range(head['epoch_count']):
        path = directory/f'epoch-{index:08d}'
        record = json.loads(path.with_suffix('.json').read_text(encoding='utf-8'))
        packed = path.with_suffix('.bin').read_bytes()
        if len(packed)%128:
            raise ValueError('partial ledger event')
        record.update(leaves=[packed[i:i+128].hex() for i in range(0,len(packed),128)],audit_seed=path.with_suffix('.key').read_bytes().hex())
        records.append(record)
    if records and not hmac.compare_digest(sth_hash(records[-1]['sth']),head['sth_hash']):
        raise ValueError('ledger HEAD differs from committed checkpoint')
    return {'public_key':head['public_key'],'epochs':records}


def verify_ledger_history(ledger_dir_or_dict: str | Path | dict[str,object],
                          trusted_checkpoint: dict[str,object] | None = None,
                          trusted_public_key: bytes | None = None) -> dict[str,object]:
    """Check signatures, all leaves and links; O(t*n) time, O(n) space for t epochs.

    Complete-tail rollback needs an independently retained checkpoint. Bundled
    keys establish integrity only; identity requires trusted_public_key.
    """
    history = load_history(ledger_dir_or_dict) if isinstance(ledger_dir_or_dict,(str,Path)) else ledger_dir_or_dict
    key = bytes.fromhex(history['public_key'])
    if trusted_public_key is not None and not hmac.compare_digest(key,trusted_public_key):
        raise ValueError('ledger signer is not the trusted key')
    leaves: list[bytes] = []
    previous: dict[str,object] | None = None
    root = sha256_digest(b'')
    found_anchor = trusted_checkpoint is None
    for index,epoch in enumerate(history['epochs']):
        sth = epoch['sth']
        if not verify(epoch['envelope'],key) or statement_payload(epoch['envelope'])!=sth:
            raise ValueError('invalid signed ledger checkpoint')
        if sth['epoch_index']!=index or sth['hash_algorithm']!='sha256':
            raise ValueError('ledger epoch order or hash profile mismatch')
        expected_link = sth_hash(previous) if previous else None
        if sth['prev_sth_hash']!=expected_link or sth['previous_epoch_root']!=(previous['epoch_root'] if previous else None) or sth['previous_ratchet_terminal']!=(previous['epoch_ratchet_kn'] if previous else None):
            raise ValueError('cross-epoch checkpoint chain mismatch')
        new = [bytes.fromhex(leaf) for leaf in epoch['leaves']]
        old_size = len(leaves)
        leaves.extend(new)
        if sth['tree_size']!=len(leaves) or sth['epoch_size']!=len(new):
            raise ValueError('ledger cumulative size mismatch')
        current_root = mth(leaves,sha256_digest)
        if not hmac.compare_digest(current_root,bytes.fromhex(sth['merkle_root'])):
            raise ValueError('ledger cumulative root mismatch')
        if not verify_consistency(old_size,len(leaves),root,current_root,[bytes.fromhex(item) for item in epoch['consistency_proof']],sha256_digest):
            raise ValueError('cross-epoch consistency proof rejected')
        if not hmac.compare_digest(mth(new,sha256_digest),bytes.fromhex(sth['epoch_root'])):
            raise ValueError('epoch root mismatch')
        status,failed = BatchEngine().verify(bytearray(b''.join(new)),bytes.fromhex(epoch['audit_seed']),bytes.fromhex(sth['epoch_ratchet_c0']),bytes.fromhex(sth['epoch_ratchet_kn']))
        if status:
            raise ValueError(f'epoch ratchet rejected at {failed}')
        if trusted_checkpoint is not None and sth['epoch_index']==trusted_checkpoint['epoch_index']:
            found_anchor = hmac.compare_digest(sth_hash(sth),sth_hash(trusted_checkpoint))
        previous,root = sth,current_root
    if not found_anchor:
        raise ValueError('ledger rollback or retained checkpoint mismatch')
    return {'valid':True,'epochs':len(history['epochs']),'tree_size':len(leaves),'merkle_root':root.hex(),'trust':'pinned-key' if trusted_public_key else 'self-contained-integrity','anchored':trusted_checkpoint is not None}


class ChainedTransparencyLedger:
    """Append signed immutable epochs; O(t*n) audit time and O(n) retained storage."""
    def __init__(self, directory: str | Path, signer: MLDSA65Signer | None = None) -> None:
        """Initialize the owned state and validate configuration limits. Complexity: O(n + W) time and O(n + M) space; n is traversed data, W delegated work, M retained delegated state."""
        self.directory = Path(directory)
        self.directory.mkdir(parents=True,exist_ok=True)
        self.signer = signer
        if (self.directory/'HEAD.json').exists():
            verify_ledger_history(self.directory)
            key = bytes.fromhex(load_history(self.directory)['public_key'])
            if signer is not None and not hmac.compare_digest(key,signer.public_key):
                raise ValueError('append signer differs from ledger signer')
        else:
            self.signer = signer or MLDSA65Signer()
            self._head({'epoch_count':0,'public_key':self.signer.public_key.hex(),'sth_hash':None})

    def _head(self, value: dict[str,object]) -> None:
        """Return the latest checkpoint in the transparency ledger. Complexity: O(n + W) time and O(n + M) space; n is traversed data, W delegated work, M retained delegated state."""
        with tempfile.NamedTemporaryFile(dir=self.directory,delete=False) as stream:
            temporary = Path(stream.name)
            stream.write(canonical(value)); stream.flush(); os.fsync(stream.fileno())
        try:
            os.replace(temporary,self.directory/'HEAD.json')
        finally:
            temporary.unlink(missing_ok=True)

    def export_history(self) -> dict[str,object]:
        """Export sensitive offline audit material; O(n) time and space."""
        return load_history(self.directory)

    def append(self, events: list[KernelTelemetryEvent]) -> dict[str,object]:
        """Seal and publish one epoch; O(n) cumulative hash time, O(n) memory."""
        if self.signer is None or not events:
            raise ValueError('append needs a signer and a nonempty epoch')
        lock = self.directory/'.append.lock'
        lock.open('x').close()
        try:
            history = self.export_history()
            verify_ledger_history(history)
            index = len(history['epochs'])
            previous = history['epochs'][-1]['sth'] if index else None
            old = [bytes.fromhex(leaf) for epoch in history['epochs'] for leaf in epoch['leaves']]
            copied = [KernelTelemetryEvent.from_bytes(event.to_bytes()) for event in events]
            for local,event in enumerate(copied):
                event.seq_no = local
            packed = bytearray(b''.join(event.to_bytes() for event in copied))
            seed = secrets.token_bytes(32)
            c0,kn = BatchEngine().seal(packed,seed)
            leaves = [bytes(packed[i:i+128]) for i in range(0,len(packed),128)]
            cumulative = old+leaves
            sth = {'epoch_index':index,'epoch_size':len(leaves),'tree_size':len(cumulative),'merkle_root':mth(cumulative,sha256_digest).hex(),'epoch_root':BatchEngine().root(packed).hex(),'prev_sth_hash':sth_hash(previous) if previous else None,'previous_epoch_root':previous['epoch_root'] if previous else None,'previous_ratchet_terminal':previous['epoch_ratchet_kn'] if previous else None,'epoch_ratchet_c0':c0.hex(),'epoch_ratchet_kn':kn.hex(),'hash_algorithm':'sha256'}
            record = {'sth':sth,'envelope':seal(sth,self.signer),'consistency_proof':[item.hex() for item in prove_consistency(len(old),cumulative,sha256_digest)]}
            base = self.directory/f'epoch-{index:08d}'
            publish_immutable(base.with_suffix('.bin'),bytes(packed))
            with base.with_suffix('.key').open('xb') as stream:
                stream.write(seed)
            os.chmod(base.with_suffix('.key'),0o600)
            publish_immutable(base.with_suffix('.json'),canonical(record))
            self._head({'epoch_count':index+1,'public_key':self.signer.public_key.hex(),'sth_hash':sth_hash(sth)})
            return sth
        finally:
            lock.unlink(missing_ok=True)
