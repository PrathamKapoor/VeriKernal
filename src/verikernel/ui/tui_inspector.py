"""Verified terminal wire and Merkle inspection; O(t*n) verification, O(n) memory."""
from __future__ import annotations
from collections import Counter
from dataclasses import asdict
import difflib
import hashlib
import json
from pathlib import Path
from verikernel.omnibor import gitoid_sha256
from verikernel.schemas import Operation
from verikernel.m3_fault.replay import read_container
from verikernel.m4_attest.ratchet import digest
from verikernel.m4_attest.merkle_tiles import sha256_digest,prove_inclusion,verify_inclusion,largest_power_of_two_less_than

WIRE_FIELDS = [('seq_no',0,8),('timestamp_ns',8,16),('pid',16,20),('tid',20,24),('syscall_nr',24,28),('fault_injected',28,32),('dev_id',32,40),('inode_nr',40,48),('mtime_ns',48,56),('call_stack_hash',56,64),('target_digest',64,96),('ratchet_tag',96,128)]


def inspect_bundle(path: str | Path, event_seq: int = 0) -> dict[str,object]:
    """Verify before rendering; O(t*n) hash work, O(n) retained events."""
    from verikernel.cli.main import verify_bundle
    verification = verify_bundle(path)
    metadata,events = read_container(path)
    manifest = metadata['manifest']
    selected = next((event for event in events if event.seq_no==event_seq),None)
    if selected is None and (events or event_seq!=0):
        raise ValueError('event sequence is not present')
    counts = Counter(event.pid for event in events)
    nodes = manifest.get('process_tree') or [{'pid':pid,'parent_pid':None,'role':'observed process','complete':None} for pid in counts]
    process_tree = []
    for node in nodes:
        own = [event for event in events if event.pid==node['pid']]
        operations = Counter(Operation(event.syscall_nr).name.removeprefix('SYS_') if event.syscall_nr in Operation._value2member_map_ else str(event.syscall_nr) for event in own)
        process_tree.append({**node,'tids':sorted({event.tid for event in own}),'syscalls':dict(operations),'event_count':len(own)})
    leaves = [event.to_bytes() for event in events]
    hash_fn = sha256_digest if manifest['hash_algorithm']=='sha256' else digest
    root = bytes.fromhex(manifest['merkle_root'])
    merkle: dict[str,object] = {'root':root.hex(),'verified':True,'steps':[]}
    event_view = None
    if selected is not None:
        index = events.index(selected)
        proof = prove_inclusion(index,leaves,hash_fn)
        steps: list[dict[str,object]] = []
        def walk(m: int, n: int, branch: list[bytes]) -> bytes:
            """Traverse the current subtree and accumulate its result. Complexity: O(n + W) time and O(n + M) space; n is traversed data, W delegated work, M retained delegated state."""
            if n==1:
                return hash_fn(b'\0'+selected.to_bytes())
            split = largest_power_of_two_less_than(n)
            child = walk(m if m<split else m-split,split if m<split else n-split,branch[:-1])
            sibling = branch[-1]
            computed = hash_fn(b'\1'+(child+sibling if m<split else sibling+child))
            steps.append({'sibling_side':'right' if m<split else 'left','sibling':sibling.hex(),'child':child.hex(),'node':computed.hex()})
            return computed
        computed = walk(index,len(events),proof)
        merkle.update(leaf_hash=hash_fn(b'\0'+selected.to_bytes()).hex(),steps=steps,computed_root=computed.hex(),verified=verify_inclusion(selected.to_bytes(),index,len(events),proof,root,hash_fn))
        decoded = {name:value.hex() if isinstance(value,bytes) else value for name,value in asdict(selected).items()}
        event_view = {'wire_bytes':128,'hex':selected.to_bytes().hex(),'fields':decoded,'offsets':[{'field':name,'start':start,'end_inclusive':end-1} for name,start,end in WIRE_FIELDS]}
    original = manifest.get('contract',{})
    observed = dict(original)
    for field,values in manifest.get('patch',{}).get('add',{}).items():
        observed[field] = sorted(set(original.get(field,[]))|set(values))
    ghost = ''.join(difflib.unified_diff(json.dumps(original,sort_keys=True,indent=2).splitlines(True),json.dumps(observed,sort_keys=True,indent=2).splitlines(True),fromfile='contract.vk.json',tofile='runtime_observed'))
    faults = [{'seq_no':event.seq_no,'pid':event.pid,'tid':event.tid,'operation':event.syscall_nr,'code':event.fault_injected} for event in events if event.fault_injected]
    return {'bundle_gitoid':gitoid_sha256(Path(path).read_bytes()),'public_key_fingerprint':hashlib.sha256(bytes.fromhex(metadata['public_key'])).hexdigest(),'signature_algorithm':'ML-DSA-65','signature_status':'VERIFIED','ratchet_status':'INTACT','trust':verification['trust'],'epochs':len(manifest.get('epochs',[{}])),'event_count':len(events),'process_tree':process_tree,'timeline':[{'timestamp_ns':event.timestamp_ns,'seq_no':event.seq_no,'pid':event.pid,'tid':event.tid,'syscall_nr':event.syscall_nr} for event in events],'event':event_view,'merkle':merkle,'ghost_diff':ghost,'faults':faults,'ddmin':{'active_sites':manifest.get('active_sites',[]),'oracle_evaluations':manifest.get('oracle_evaluations'),'schedule':manifest.get('schedule',[])}}


def render_text(data: dict[str,object], show_merkle: bool = True, show_diff: bool = True,
                show_ddmin: bool = True) -> str:
    """Render UTF-8-safe ASCII tables and trees; O(n) time and output space."""
    lines = ['VERIKERNEL BUNDLE INSPECTOR',f"Bundle {data['bundle_gitoid']}",f"ML-DSA-65 {data['signature_status']} | ratchet {data['ratchet_status']}",f"Key SHA-256 {data['public_key_fingerprint']}",f"Trust {data['trust']} | epochs {data['epochs']} | events {data['event_count']}",'','PROCESS PID/TID TREE']
    by_parent: dict[object,list[dict[str,object]]] = {}
    known = {node['pid'] for node in data['process_tree']}
    for node in data['process_tree']:
        by_parent.setdefault(node['parent_pid'] if node['parent_pid'] in known else None,[]).append(node)
    def tree(parent: int | None, prefix: str, visited: set[int]) -> None:
        """Render the process hierarchy and its syscall counts. Complexity: O(n + W) time and O(n + M) space; n is traversed data, W delegated work, M retained delegated state."""
        for node in by_parent.get(parent,[]):
            if node['pid'] in visited:
                continue
            visited.add(node['pid'])
            lines.append(f"{prefix}+-- PID {node['pid']} TID {node['tids']} {node['role']} {node['syscalls']}")
            tree(node['pid'],prefix+'|   ',visited)
    tree(None,'',set())
    lines += ['','128-BYTE WIRE DISSECTOR']
    event = data['event']
    if event:
        for field in event['offsets']:
            lines.append(f"{field['start']:02}..{field['end_inclusive']:03} {field['field']:<20} {event['fields'][field['field']]}")
        raw = bytes.fromhex(event['hex'])
        lines += [f'{offset:04x}  '+raw[offset:offset+16].hex(' ') for offset in range(0,128,16)]
    else:
        lines.append('No telemetry records')
    if show_merkle:
        lines += ['','RFC 9162 MERKLE AUDIT PATH',f"Leaf {data['merkle'].get('leaf_hash','empty tree')}"]
        for step in data['merkle']['steps']:
            lines += [f"+-- sibling {step['sibling_side']} {step['sibling']}",f"    NodeHash {step['node']}"]
        lines.append('Signed MerkleTreeHead '+data['merkle']['root'])
    if show_diff:
        lines += ['','GHOST DEPENDENCY UNIFIED DIFF',data['ghost_diff'] or 'No observed additions']
    if show_ddmin:
        lines += ['','FAULT INJECTION MAP',json.dumps(data['faults'],indent=2),'DDMIN SCHEDULE',json.dumps(data['ddmin'],indent=2)]
    lines += ['','PID/TID EXECUTION TIMELINE']
    lines += [f"{row['timestamp_ns']} seq={row['seq_no']} pid={row['pid']} tid={row['tid']} op={row['syscall_nr']}" for row in data['timeline']]
    return '\n'.join(lines)+'\n'
