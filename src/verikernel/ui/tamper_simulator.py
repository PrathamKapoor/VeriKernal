"""Tamper simulator."""
from __future__ import annotations
import base64
import copy
from pathlib import Path
from verikernel.schemas import KernelTelemetryEvent
from verikernel.m4_attest.ratchet import ForwardSecureRatchet,ratchet_error
from verikernel.m4_attest.merkle_tiles import mth,prove_inclusion,leaf_hash,node_hash,largest_power_of_two_less_than
from verikernel.m4_attest.pqc_signer import MLDSA65Signer
from verikernel.m4_attest.dsse_envelope import seal,verify


def branch_hashes(index: int,leaves: object) -> object:
    """Return the sibling hashes for a selected Merkle audit path. Complexity: O(n + W) time and O(n + M) space; n is traversed data, W delegated work, M retained delegated state."""
    if not 0<=index<len(leaves):
        return []
    if len(leaves)==1:
        return [leaf_hash(leaves[0])]
    split = largest_power_of_two_less_than(len(leaves))
    if index<split:
        path = branch_hashes(index,leaves[:split])
        return path+[node_hash(path[-1],mth(leaves[split:]))]
    path = branch_hashes(index-split,leaves[split:])
    return path+[node_hash(mth(leaves[:split]),path[-1])]


def run_adversarial_tamper_suite(bundle_or_events: object) -> object:
    """Measure rejection of payload, truncation, ordering and signature attacks. Complexity: O(n + W) time and O(n + M) space; n is traversed data, W delegated work, M retained delegated state."""
    if isinstance(bundle_or_events,(str,Path)):
        from verikernel.cli.main import verify_bundle
        from verikernel.m3_fault.replay import read_container
        verify_bundle(bundle_or_events)
        metadata,events = read_container(bundle_or_events)
        seed = Path(str(bundle_or_events)+'.audit.key').read_bytes()
        commitment = bytes.fromhex(metadata['manifest']['ratchet_commitment'])
        terminal = bytes.fromhex(metadata['manifest']['ratchet_terminal'])
        envelope,public = metadata['envelope'],bytes.fromhex(metadata['public_key'])
        source = 'verified execution bundle'
    else:
        events = [KernelTelemetryEvent.from_bytes(event.to_bytes()) for event in bundle_or_events]
        seed = bytes(range(32))
        ratchet = ForwardSecureRatchet(seed)
        for index,event in enumerate(events):
            event.seq_no = index
            ratchet.tag(event)
        commitment,terminal = ratchet.commitment,ratchet.terminal
        signer = MLDSA65Signer()
        envelope = seal({'_type':'https://in-toto.io/Statement/v1','predicate':{'root':mth([e.to_bytes() for e in events]).hex(),'count':len(events)}},signer)
        public = signer.public_key
        source = 'new demonstration epoch from supplied event payloads'
    if len(events)<3:
        raise ValueError('the four-attack demonstration requires at least three events')
    baseline = [event.to_bytes() for event in events]
    root = mth(baseline)
    attacks = {}
    def record(name: object,changed: object,index: int,before: object,after: object) -> None:
        """Retain an observed event for the current execution receipt. Complexity: O(n + W) time and O(n + M) space; n is traversed data, W delegated work, M retained delegated state."""
        error = ratchet_error(changed,seed,commitment,terminal)
        leaves = [event.to_bytes() for event in changed]
        attacks[name] = {'detected':error is not None,'first_corrupted_index':error['index'] if error else None,'seq_no':error['seq_no'] if error else None,'rejection':error,'before_hex':before.hex(),'after_hex':after.hex(),'original_root':root.hex(),'altered_root':mth(leaves).hex(),'merkle_branch':{'leaf_hash':leaf_hash(baseline[index]).hex(),'siblings':[node.hex() for node in prove_inclusion(index,baseline)]}}
        attacks[name]['merkle_branch'].update(before_path=[node.hex() for node in branch_hashes(index,baseline)],after_path=[node.hex() for node in branch_hashes(index,leaves)])
    mutated = [KernelTelemetryEvent.from_bytes(raw) for raw in baseline]
    raw = bytearray(baseline[0])
    raw[64] ^= 1
    mutated[0] = KernelTelemetryEvent.from_bytes(raw)
    record('payload_bit_flip',mutated,0,baseline[0],bytes(raw))
    record('mid_epoch_tail_truncation',events[:-1],len(events)-1,baseline[-1],b'')
    swapped = list(events)
    swapped[0],swapped[1] = swapped[1],swapped[0]
    record('cross_cpu_sequence_swap',swapped,0,baseline[0]+baseline[1],baseline[1]+baseline[0])
    forged = copy.deepcopy(envelope)
    signature = bytearray(base64.b64decode(forged['signatures'][0]['sig']))
    original = bytes(signature)
    signature[48:51] = (int.from_bytes(signature[48:51],'little') & ~0xfffff).to_bytes(3,'little')
    forged['signatures'][0]['sig'] = base64.b64encode(signature).decode()
    rejected = not verify(forged,public)
    coefficient = 524288-(int.from_bytes(signature[48:51],'little')&0xfffff)
    attacks['pqc_signature_lattice_forge'] = {'detected':rejected,'first_corrupted_index':None,'seq_no':None,'before_hex':original.hex(),'after_hex':bytes(signature).hex(),'rejection':{'stage':'FIPS 204 response infinity-norm check','polynomial':0,'coefficient_index':0,'coefficient':coefficient,'exclusive_bound':524288-196,'ring':'Z_8380417[X]/(X^256+1)','provider_signature_accepted':not rejected},'original_root':root.hex(),'altered_root':root.hex(),'merkle_branch':{'siblings':[]}}
    return {'source':source,'event_count':len(events),'root':root.hex(),'attacks':attacks,'cpu_scope':'the wire format identifies threads rather than CPU numbers; order integrity is checked independently of CPU attribution'}
