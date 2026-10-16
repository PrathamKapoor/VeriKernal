"""Main."""
from __future__ import annotations
import argparse
import base64
import hashlib
import json
import os
import secrets
import sys
from pathlib import Path
from verikernel.m1_contract.compiler import compile_contract, canonical_json
from verikernel.omnibor import gitoid_sha256
from verikernel.m2_enforcer.hal import RuntimeInterceptorHAL
from verikernel.m3_fault.injector import SyscallFaultInjector
from verikernel.m3_fault.ddmin import DeltaDebuggingShrinker
from verikernel.m3_fault.replay import write_container, read_container
from verikernel.m4_attest.ratchet import ForwardSecureRatchet, ratchet_error, HASH_ALGORITHM
from verikernel.m4_attest.merkle_tiles import mth, prove_inclusion, verify_inclusion, write_tiles
from verikernel.m4_attest.pqc_signer import MLDSA65Signer
from verikernel.m4_attest.dsse_envelope import seal, verify as verify_dsse, statement_payload
from verikernel.m4_attest.epoch_service import EpochAttestor
from verikernel.m5_ringbuf.zero_drop_v02 import ZeroDropRingBufferV02
from verikernel.m6_quantum.circuit_contract import CircuitContract
from verikernel.m6_quantum.drift_firewall import audit_uncertainty
from verikernel.schemas import KernelTelemetryEvent
from verikernel.type_boundaries import validate_bundle_dict


def emit(value: object) -> None:
    """Write a JSON result to standard output. Complexity: O(n + W) time and O(n + M) space; n is traversed data, W delegated work, M retained delegated state."""
    print(json.dumps(value, sort_keys=True))


def run_workload(script: object, contract: object=None, mode: str="audit", injector: object=None) -> object:
    """Execute a workload under the selected interception backend. Complexity: O(n + W) time and O(n + M) space; n is traversed data, W delegated work, M retained delegated state."""
    script = Path(script).resolve(strict=True)
    source = script.read_bytes()
    code = compile(source, str(script), "exec")
    seed = secrets.token_bytes(32)
    attestor = EpochAttestor(seed=seed)
    ratchet = attestor.ratchet
    hal = RuntimeInterceptorHAL(contract, mode, script.parent, injector, None, None, attestor=attestor)
    error = None
    old_argv, old_path = sys.argv, sys.path[:]
    sys.argv = [str(script)]
    sys.path.insert(0, str(script.parent))
    try:
        with hal:
            exec(code, {"__name__": "__main__", "__file__": str(script), "vk_hal": hal})
    except SystemExit as exc:
        if exc.code not in {None, 0}:
            error = {"type": "SystemExit", "code": exc.code}
    except Exception as exc:
        error = {"type": type(exc).__name__, "errno": getattr(exc, "errno", None), "message": str(exc)}
    finally:
        sys.argv, sys.path[:] = old_argv, old_path
        attestor.close()
    events = attestor.events
    return {"script": str(script), "source_gitoid": gitoid_sha256(source), "backend": hal.backend, "capabilities": hal.capabilities, "contract": contract or {}, "mode": mode, "error": error, "patch": hal.ghost_patch(), "schedule": injector.schedule if injector else [], "seed": injector.seed if injector else None, "epochs": attestor.epochs, "epoch_public_key": attestor.public_key.hex()}, events, seed, ratchet


def pack_receipt(path: object, manifest: object, events: object, seed: object, ratchet: object) -> object:
    """Seal captured events and execution metadata into a replay bundle. Complexity: O(n + W) time and O(n + M) space; n is traversed data, W delegated work, M retained delegated state."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    if any(candidate.exists() for candidate in [path,Path(str(path)+'.audit.key'),Path(str(path)+'.pubkey'),Path(str(path)+'.tiles')]):
        raise FileExistsError('receipt artifacts already exist; choose an unused output path')
    tiles = Path(str(path)+'.tiles')
    tiles.mkdir()
    leaves = [e.to_bytes() for e in events]
    from verikernel.m4_attest.merkle_tiles import sha256_digest
    from verikernel.m4_attest.ratchet import digest
    profile = getattr(ratchet,'hash_algorithm',HASH_ALGORITHM)
    hash_fn = sha256_digest if profile=='sha256' else digest
    manifest = {**manifest, "schema": "verikernel-execution-v2", "hash_algorithm": profile, "event_count": len(events), "merkle_root": mth(leaves,hash_fn).hex(), "ratchet_commitment": ratchet.commitment.hex(), "ratchet_terminal": ratchet.terminal.hex()}
    signer = MLDSA65Signer()
    statement = {"_type": "https://in-toto.io/Statement/v1", "subject": [{"name": path.name + ".events", "digest": {"sha256": hashlib.sha256(b"".join(leaves)).hexdigest()}}], "predicateType": "https://verikernel.dev/execution/v2", "predicate": manifest}
    envelope = seal(statement, signer)
    audit_path = Path(str(path) + ".audit.key")
    with audit_path.open('xb') as stream:
        stream.write(seed)
    os.chmod(audit_path, 0o600)
    with Path(str(path)+'.pubkey').open('xb') as stream:
        stream.write(signer.public_key)
    write_tiles(leaves, tiles,hash_fn)
    write_container(path, {"manifest": manifest, "public_key": signer.public_key.hex(), "envelope": envelope}, events,exclusive=True)
    return manifest


def verify_bundle(path: str | Path, trusted_key: str | Path | None=None, prove_index: int | None=None) -> dict[str,object]:
    """Check a bundle against its signature, Merkle root and ratchet state. Complexity: O(n + W) time and O(n + M) space; n is traversed data, W delegated work, M retained delegated state."""
    metadata, events = read_container(path)
    metadata = validate_bundle_dict(metadata)
    manifest = metadata["manifest"]
    pk = bytes.fromhex(metadata["public_key"])
    if trusted_key is not None and pk != Path(trusted_key).read_bytes():
        raise ValueError("bundle signer differs from trusted public key")
    if not verify_dsse(metadata["envelope"], pk):
        raise ValueError("invalid epoch signature")
    statement = statement_payload(metadata["envelope"])
    if statement.get("_type") != "https://in-toto.io/Statement/v1" or statement.get("predicate") != manifest:
        raise ValueError("unsigned or mismatched manifest")
    if manifest["hash_algorithm"] not in {HASH_ALGORITHM,'sha256'}:
        raise ValueError("bundle hash algorithm unavailable")
    from verikernel.m4_attest.merkle_tiles import sha256_digest
    from verikernel.m4_attest.ratchet import digest
    hash_fn = sha256_digest if manifest['hash_algorithm']=='sha256' else digest
    leaves = [e.to_bytes() for e in events]
    if manifest["event_count"] != len(events) or manifest["merkle_root"] != mth(leaves,hash_fn).hex():
        raise ValueError("event count or Merkle root mismatch")
    audit_path = Path(str(path) + ".audit.key")
    if manifest['hash_algorithm']=='sha256':
        from verikernel.rust_bridge import BatchEngine
        status,index = BatchEngine().verify(bytearray(b''.join(leaves)),audit_path.read_bytes(),bytes.fromhex(manifest['ratchet_commitment']),bytes.fromhex(manifest['ratchet_terminal']))
        error = {'index':index,'reason':'SHA-256 batch chain rejected'} if status else None
    else:
        error = ratchet_error(events, audit_path.read_bytes(), bytes.fromhex(manifest["ratchet_commitment"]), bytes.fromhex(manifest["ratchet_terminal"]))
    if error:
        raise ValueError(json.dumps(error))
    if "epochs" in manifest:
        from verikernel.m4_attest.merkle_tiles import verify_consistency
        previous_count, previous_root, previous_envelope = 0, mth([]), None
        epoch_key = bytes.fromhex(manifest["epoch_public_key"])
        for index, epoch in enumerate(manifest["epochs"]):
            if not verify_dsse(epoch["envelope"], epoch_key) or statement_payload(epoch["envelope"]) != epoch["statement"]:
                raise ValueError("invalid periodic epoch signature")
            predicate = epoch["statement"]["predicate"]
            count = predicate["event_count"]
            if predicate["epoch_index"] != index or predicate["previous_count"] != previous_count or not previous_count <= count <= len(events):
                raise ValueError("invalid periodic epoch count")
            root = mth(leaves[:count])
            previous_digest = hashlib.sha256(canonical_json(previous_envelope)).hexdigest() if previous_envelope else None
            if predicate["merkle_root"] != root.hex() or predicate["previous_envelope_sha256"] != previous_digest:
                raise ValueError("periodic epoch chain mismatch")
            if predicate["hash_algorithm"] != HASH_ALGORITHM or ratchet_error(events[:count], audit_path.read_bytes(), bytes.fromhex(predicate["ratchet_commitment"]), bytes.fromhex(predicate["ratchet_terminal"])):
                raise ValueError("periodic ratchet mismatch")
            if not verify_consistency(previous_count, count, previous_root, root, [bytes.fromhex(p) for p in predicate["consistency_proof"]]):
                raise ValueError("invalid periodic consistency proof")
            previous_count, previous_root, previous_envelope = count, root, epoch["envelope"]
        if not manifest["epochs"] or previous_count != len(events):
            raise ValueError("incomplete periodic epoch chain")
    result = {"valid": True, "event_count": len(events), "trust": "pinned-key" if trusted_key else "self-contained-integrity"}
    if prove_index is not None:
        proof = prove_inclusion(prove_index, leaves,hash_fn)
        result["inclusion"] = verify_inclusion(leaves[prove_index], prove_index, len(leaves), proof, bytes.fromhex(manifest["merkle_root"]),hash_fn)
        result["proof"] = [h.hex() for h in proof]
    return result


def shrink_bundle(source: object, output: object) -> object:
    """Rerun a failing schedule and write its reduced counterexample. Complexity: O(n + W) time and O(n + M) space; n is traversed data, W delegated work, M retained delegated state."""
    verify_bundle(source)
    metadata, _ = read_container(source)
    manifest = metadata["manifest"]
    if not manifest.get("error") or not manifest.get("script"):
        raise ValueError("bundle has no reproducible workload failure")
    script = manifest["script"]
    if gitoid_sha256(Path(script).read_bytes()) != manifest["source_gitoid"]:
        raise ValueError("workload bytes differ from recorded source")
    schedule = manifest["schedule"]
    def fails(sites: object) -> object:
        """Replay a candidate fault subset and test the recorded failure condition. Complexity: O(n + W) time and O(n + M) space; n is traversed data, W delegated work, M retained delegated state."""
        injector = SyscallFaultInjector(manifest["seed"], schedule=schedule, active_sites=sites)
        observed, _, _, _ = run_workload(script, manifest["contract"], manifest["mode"], injector)
        error = observed["error"]
        expected = manifest["error"]
        return bool(error and error["type"] == expected["type"] and error.get("errno") == expected.get("errno"))
    shrinker = DeltaDebuggingShrinker(fails)
    sites = shrinker.shrink(item["site_id"] for item in schedule)
    injector = SyscallFaultInjector(manifest["seed"], schedule=schedule, active_sites=sites)
    observed, events, seed, ratchet = run_workload(script, manifest["contract"], manifest["mode"], injector)
    observed["active_sites"] = sites
    observed["parent_bundle_sha256"] = hashlib.sha256(Path(source).read_bytes()).hexdigest()
    observed["oracle_evaluations"] = shrinker.evaluations
    pack_receipt(output, observed, events, seed, ratchet)
    return {"initial_faults": len(schedule), "minimal_sites": sites, "oracle_evaluations": shrinker.evaluations}


def parser() -> object:
    """Define command-line arguments and their defaults. Complexity: O(n + W) time and O(n + M) space; n is traversed data, W delegated work, M retained delegated state."""
    p = argparse.ArgumentParser(prog="verikernel")
    sub = p.add_subparsers(dest="command", required=True)
    compile_p = sub.add_parser("compile")
    compile_p.add_argument("repo_path")
    compile_p.add_argument("--output", required=True)
    for name in ("trace", "enforce", "fault"):
        cmd = sub.add_parser(name)
        cmd.add_argument("script")
        if name != "fault":
            cmd.add_argument("--backend", choices=["portable", "linux", "multiprocess"], default="portable")
        else:
            cmd.add_argument('--backend',choices=['portable','multiprocess'],default='portable')
        if name != "fault":
            cmd.add_argument("--contract", required=True)
        if name != "enforce":
            cmd.add_argument("--bundle", required=True)
        if name == "enforce":
            cmd.add_argument("--mode", choices=["audit", "strict"], default="audit")
        if name == "fault":
            cmd.add_argument("--seed", type=int, required=True)
            cmd.add_argument("--prob", type=float, default=.05)
    shrink = sub.add_parser("shrink")
    shrink.add_argument("bundle")
    shrink.add_argument("--output", required=True)
    verify_p = sub.add_parser("verify")
    verify_p.add_argument("bundle")
    verify_p.add_argument("--prove-index", type=int)
    verify_p.add_argument("--trusted-key")
    quantum = sub.add_parser("quantum-audit")
    quantum.add_argument("--qubits", type=int, default=2)
    quantum.add_argument("--shots", type=int, default=1024)
    quantum.add_argument("--drift-level", type=float, default=0)
    quantum.add_argument("--bundle", required=True)
    bench = sub.add_parser("bench")
    bench.add_argument("--output-dir", default="benchmarks/results")
    demo = sub.add_parser('demo')
    demo.add_argument('--output',default='benchmarks/results/demo_mission_control.html')
    ui = sub.add_parser('ui')
    ui.add_argument('--port',type=int,default=8765)
    ui.add_argument('--self-test',action='store_true')
    inspector = sub.add_parser('inspect')
    inspector.add_argument('bundle')
    inspector.add_argument('--event-seq',type=int,default=0)
    inspector.add_argument('--format',choices=['text','json'],default='text')
    inspector.add_argument('--show-merkle',action='store_true')
    inspector.add_argument('--show-diff',action='store_true')
    inspector.add_argument('--show-ddmin',action='store_true')
    return p


def main(argv: object=None) -> int:
    """Parse command-line arguments and return the selected operation status. Complexity: O(n + W) time and O(n + M) space; n is traversed data, W delegated work, M retained delegated state."""
    args = parser().parse_args(argv)
    try:
        if args.command == "compile":
            result = compile_contract(args.repo_path, args.output)
            emit({"contract_gitoid": result["contract_gitoid"], "ghost_imports": result["ghost_imports"]})
        elif args.command in {"trace", "enforce", "fault"}:
            contract = json.loads(Path(args.contract).read_text()) if args.command != "fault" else {}
            mode = args.mode if args.command == "enforce" else "audit"
            if args.backend=='multiprocess':
                from verikernel.m2_enforcer.process_supervisor import MultiProcessSupervisor
                output = args.bundle if args.command!='enforce' else Path(__file__).resolve().parents[3]/'.tmp'/('enforce-'+secrets.token_hex(12)+'.vkr')
                observed = MultiProcessSupervisor(contract,mode,args.seed if args.command=='fault' else 0,args.prob if args.command=='fault' else 0).run(args.script,output)
                metadata,_ = read_container(output)
                emit({**observed,'patch':metadata['manifest']['patch'],'error':None if observed['returncode']==0 else {'returncode':observed['returncode']}})
                return 1 if args.command=='enforce' and observed['returncode'] else 0
            injector = SyscallFaultInjector(args.seed, args.prob) if args.command == "fault" else None
            if args.backend == "linux":
                from verikernel.m2_enforcer.linux_hal import run_native
                manifest, events, seed, ratchet = run_native(args.script, contract, mode=mode)
            else:
                manifest, events, seed, ratchet = run_workload(args.script, contract, mode, injector)
            if args.command != "enforce":
                pack_receipt(args.bundle, manifest, events, seed, ratchet)
                Path(args.bundle).with_name("contract_patch.vk.json").write_bytes(canonical_json(manifest["patch"]))
            emit({"event_count": len(events), "error": manifest["error"], "patch": manifest["patch"]})
            if args.command == "enforce" and manifest["error"]:
                return 1
        elif args.command == "verify":
            emit(verify_bundle(args.bundle, args.trusted_key, args.prove_index))
        elif args.command == "shrink":
            emit(shrink_bundle(args.bundle, args.output))
        elif args.command == "quantum-audit":
            if not 0 <= args.drift_level <= .5:
                raise ValueError("drift level must lie in [0,.5]")
            circuit = CircuitContract(args.qubits, [("H", 0)])
            receipt = audit_uncertainty([.5, .5], args.shots, [.5, .5], [.5+args.drift_level, .5-args.drift_level])
            receipt.update({"circuit_gitoid": circuit.identity, "qubits": args.qubits, "transpiler_seed": circuit.seed, "layout": circuit.layout, "evidence": "synthetic-calibration"})
            seed = secrets.token_bytes(32)
            ratchet = ForwardSecureRatchet(seed)
            event = KernelTelemetryEvent(syscall_nr=8, target_digest=hashlib.sha256(canonical_json(receipt)).digest())
            ratchet.tag(event)
            pack_receipt(args.bundle, {"receipt": receipt}, [event], seed, ratchet)
            emit(receipt)
        elif args.command == "bench":
            from benchmarks.run_benchmarks import run_benchmarks
            emit(run_benchmarks(args.output_dir))
        elif args.command == 'demo':
            from verikernel.ui.dashboard_generator import generate_dashboard
            path,data = generate_dashboard(args.output)
            Path('benchmarks/results/demo_metrics.json').write_text(json.dumps(data,indent=2),encoding='utf-8')
            emit({'dashboard':str(path),'attacks_detected':sum(attack['detected'] for attack in data['tamper']['attacks'].values()),'unitary_fidelity':data['quantum']['reroute']['unitary_fidelity']})
        elif args.command == 'ui':
            from verikernel.ui.server import serve
            emit(serve(args.port,args.self_test))
        elif args.command == 'inspect':
            from verikernel.ui.tui_inspector import inspect_bundle,render_text
            inspection = inspect_bundle(args.bundle,args.event_seq)
            if args.format=='json':
                emit(inspection)
            else:
                all_sections = not (args.show_merkle or args.show_diff or args.show_ddmin)
                print(render_text(inspection,args.show_merkle or all_sections,args.show_diff or all_sections,args.show_ddmin or all_sections),end='')
        return 0
    except (ValueError, OSError, KeyError, TypeError) as exc:
        emit({"valid": False, "error": str(exc)})
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
