import json
import os
import subprocess
import sys
from pathlib import Path


def run_cli(*args):
    return subprocess.run([sys.executable, "-m", "verikernel.cli.main", *map(str, args)], capture_output=True, text=True, env=os.environ.copy(), timeout=120)


def test_compile_trace_verify_and_tampered_bundle(tmp_path):
    source = tmp_path / "target.py"
    data = tmp_path / "data"
    data.write_text("abc")
    source.write_text(f'with open({str(data)!r}) as f:\n    print(f.read())\n')
    contract, bundle = tmp_path / "contract.vk.json", tmp_path / "run.vkr"
    assert run_cli("compile", source, "--output", contract).returncode == 0
    trace = run_cli("trace", source, "--contract", contract, "--bundle", bundle)
    assert trace.returncode == 0, trace.stderr
    result = run_cli("verify", bundle, "--prove-index", 0)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["valid"] is True
    public_key = Path(str(bundle) + ".pubkey")
    assert run_cli("verify", bundle, "--trusted-key", public_key).returncode == 0
    wrong_key = tmp_path / "wrong.pubkey"
    wrong_key.write_bytes(bytes(1952))
    assert run_cli("verify", bundle, "--trusted-key", wrong_key).returncode != 0
    altered = bytearray(bundle.read_bytes())
    altered[-1] ^= 1
    bundle.write_bytes(altered)
    assert run_cli("verify", bundle).returncode != 0


def test_strict_fault_shrink_and_quantum_receipts(tmp_path):
    source = tmp_path / "target.py"
    data = tmp_path / "data"
    data.write_text("abc")
    source.write_text(f'with open({str(data)!r}) as f:\n    print(f.read())\n')
    empty = tmp_path / "contract.json"
    empty.write_text('{"filesystem":[]}')
    assert run_cli("enforce", source, "--contract", empty, "--mode", "strict").returncode == 1
    bundle, shrunk = tmp_path / "fault.vkr", tmp_path / "shrunk.vkr"
    assert run_cli("fault", source, "--seed", 3, "--prob", 1, "--bundle", bundle).returncode == 0
    result = run_cli("shrink", bundle, "--output", shrunk)
    assert result.returncode == 0, result.stderr
    assert run_cli("verify", shrunk).returncode == 0
    quantum = tmp_path / "quantum.vkr"
    assert run_cli("quantum-audit", "--qubits", 2, "--shots", 1024, "--drift-level", .2, "--bundle", quantum).returncode == 0
    assert run_cli("verify", quantum).returncode == 0


def test_bundle_manifest_is_signed_even_after_checksum_recomputed(tmp_path):
    from verikernel.m3_fault.replay import read_container, write_container
    bundle = tmp_path / "quantum.vkr"
    assert run_cli("quantum-audit", "--bundle", bundle).returncode == 0
    metadata, events = read_container(bundle)
    metadata["manifest"]["receipt"]["shots"] = 1
    write_container(bundle, metadata, events)
    assert run_cli("verify", bundle).returncode != 0


def test_benchmark_fault_pipeline_measures_two_causes():
    from benchmarks.run_benchmarks import benchmark_faults, benchmark_detection
    result = benchmark_faults()
    assert result["minimal_sites"] == [7, 23]
    assert result["replay_determinism_percent"] == 100
    detection = benchmark_detection()
    assert detection["case_count"] == 20
    assert detection["portable_hybrid"]["recall"] > detection["static_import_only"]["recall"]
