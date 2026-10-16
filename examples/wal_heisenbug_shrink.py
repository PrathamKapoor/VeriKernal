"""Case2 wal heisenbug shrink."""
from __future__ import annotations
from typing import Any
import argparse
import json
import socket
import secrets
import os
from pathlib import Path
from verikernel.m2_enforcer.hal import RuntimeInterceptorHAL
from verikernel.m3_fault.injector import SyscallFaultInjector
from verikernel.m3_fault.ddmin import DeltaDebuggingShrinker
from verikernel.m4_attest.ratchet import ForwardSecureRatchet
from verikernel.omnibor import file_gitoid

SOURCE = '''def transaction(connection, journal):
    remote_ack, fallback, journal_errno = False, False, None
    for site in range(32):
        try:
            if site == 7:
                remote_ack = connection.recv(8) == b"COMMIT:1"
            elif site == 23:
                journal.write(b"COMMIT:1\\n")
            else:
                journal.write(("CHECKPOINT:" + str(site) + "\\n").encode())
        except OSError as error:
            if site == 7 and error.errno == 11:
                fallback = True
            if site == 23:
                journal_errno = error.errno
    acknowledged = remote_ack or fallback
    return {"acknowledged": acknowledged, "remote_ack": remote_ack, "fallback": fallback, "journal_errno": journal_errno}
'''


def run(output_dir: Any) -> Any:
    """Run the wal heisenbug shrink workflow and collect its results. Complexity: O(n + W) time and O(n + M) space; n is traversed data, W delegated work, M retained delegated state."""
    directory = Path(output_dir).resolve()
    directory.mkdir(parents=True,exist_ok=True)
    script = directory/'wal_pipeline.py'
    script.write_text(SOURCE,encoding='utf-8')
    namespace = {}
    exec(compile(SOURCE,str(script),'exec'),namespace)
    def execute(injector: Any) -> Any:
        """Execute the workload with the selected fault schedule. Complexity: O(n + W) time and O(n + M) space; n is traversed data, W delegated work, M retained delegated state."""
        left,right = socket.socketpair()
        ratchet = ForwardSecureRatchet(bytes(range(32)))
        try:
            right.sendall(b'COMMIT:1')
            left.settimeout(3)
            with RuntimeInterceptorHAL({},target_root=directory,injector=injector,ratchet=ratchet) as trace:
                with open(directory/'journal.wal','wb') as journal:
                    outcome = namespace['transaction'](left,journal)
                    journal.flush()
                    os.fsync(journal.fileno())
            durable = b'COMMIT:1\n' in (directory/'journal.wal').read_bytes().splitlines(keepends=True)
            corrupted = outcome['acknowledged'] and not outcome['remote_ack'] and not durable and outcome['fallback'] and outcome['journal_errno']==28
            return corrupted,trace,ratchet,outcome
        finally:
            left.close()
            right.close()
    schedule = None
    for seed in range(1000):
        injector = SyscallFaultInjector(seed,1,syscall_types={9,10})
        corrupted,trace,ratchet,outcome = execute(injector)
        if corrupted:
            schedule = injector.schedule
            break
    if schedule is None or len(schedule)!=32:
        raise ValueError('exploration did not discover a 32-site WAL counterexample')
    def replay(sites: Any) -> Any:
        """Replay the candidate schedule against a restored workload. Complexity: O(n + W) time and O(n + M) space; n is traversed data, W delegated work, M retained delegated state."""
        return execute(SyscallFaultInjector(seed,schedule=schedule,active_sites=sites,syscall_types={9,10}))
    oracle_trace = []
    def oracle(sites: Any) -> Any:
        """Test whether the selected fault subset reproduces the failure. Complexity: O(n + W) time and O(n + M) space; n is traversed data, W delegated work, M retained delegated state."""
        failed = replay(sites)[0]
        parent = next((index for index in range(len(oracle_trace)-1,-1,-1) if oracle_trace[index]['failed']),None)
        oracle_trace.append({'sites':list(sites),'failed':failed,'parent':parent})
        return failed
    shrinker = DeltaDebuggingShrinker(oracle)
    minimal = shrinker.shrink(item['site_id'] for item in schedule)
    reproduced = sum(replay(minimal)[0] for index in range(20))
    corrupted,trace,ratchet,outcome = replay(minimal)
    from verikernel.cli.main import pack_receipt
    bundle = directory/('minimal-'+secrets.token_hex(8)+'.vkr')
    manifest = {'case':'wal-corruption','source_gitoid':file_gitoid(script),'source':SOURCE,'seed':seed,'schedule':schedule,'active_sites':minimal,'outcome':outcome,'oracle_evaluations':shrinker.evaluations,'replay_scope':'case-study transaction oracle; not whole-process instruction replay'}
    pack_receipt(bundle,manifest,trace.events,bytes(range(32)),ratchet)
    result = {'case':'wal-heisenbug','initial_fault_count':len(schedule),'minimal_sites':minimal,'master_seed':seed,'replay_runs':20,'reproductions':reproduced,'acknowledged_without_durability':corrupted,'oracle_evaluations':shrinker.evaluations,'oracle_trace':oracle_trace,'recorded_events':len(trace.events),'bundle':str(bundle)}
    (directory/'result.json').write_text(json.dumps(result,indent=2),encoding='utf-8')
    return result


if __name__=='__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--output-dir',default='dist/case2')
    print(json.dumps(run(parser.parse_args().output_dir),indent=2))
