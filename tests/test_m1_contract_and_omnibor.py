import hashlib
import struct
import pytest


def test_event_signed_fault_and_wire_roundtrip():
    from verikernel.schemas import KernelTelemetryEvent, EVENT_STRUCT
    event = KernelTelemetryEvent(seq_no=42, fault_injected=-11)
    raw = event.to_bytes()
    assert len(raw) == EVENT_STRUCT.size == 128
    assert raw[28:32] == b"\xf5\xff\xff\xff"
    assert KernelTelemetryEvent.from_bytes(raw) == event
    with pytest.raises(ValueError):
        KernelTelemetryEvent.from_bytes(raw[:-1])


def test_gitoid_uses_git_blob_framing():
    from verikernel.omnibor import gitoid_sha256, input_manifest
    expected = "gitoid:blob:sha256:" + hashlib.sha256(b"blob 3\0abc").hexdigest()
    assert gitoid_sha256(b"abc") == expected
    manifest, identity = input_manifest([expected, expected])
    assert manifest == ("gitoid:blob:sha256\nblob " + expected.rsplit(":", 1)[1] + "\n").encode()
    assert identity == gitoid_sha256(manifest)


@pytest.mark.parametrize("kind,names", [("elf", ["libc.so.6", "libm.so.6"]), ("pe", ["KERNEL32.dll", "WS2_32.dll"])])
def test_binary_imports_roundtrip_and_truncation(kind, names):
    from verikernel.m1_contract.binary_inspector import build_synthetic_elf, build_synthetic_pe, parse_elf_needed, parse_pe_imports
    build, parse = (build_synthetic_elf, parse_elf_needed) if kind == "elf" else (build_synthetic_pe, parse_pe_imports)
    binary = build(names)
    assert parse(binary) == names
    with pytest.raises(ValueError):
        parse(binary[:40])


def test_contract_scans_aliases_literals_and_deterministic_identity(tmp_path):
    from verikernel.m1_contract.compiler import compile_contract
    (tmp_path / "pyproject.toml").write_text('[project]\ndependencies=["pyyaml>=6"]\n')
    (tmp_path / "sample.py").write_text('import yaml\nimport os\nimport ctypes as ct\nfrom importlib import import_module as im\nim("numpy")\nct.CDLL("ghost.dll")\nos.getenv("TOKEN")\nopen("input.txt")\n')
    first = compile_contract(tmp_path)
    assert first["ghost_imports"] == ["numpy"]
    assert first["shared_libraries"] == ["ghost.dll"]
    assert first["environment"] == ["TOKEN"]
    assert first["contract_gitoid"] == compile_contract(tmp_path)["contract_gitoid"]
    assert str((tmp_path / "input.txt").resolve()) in first["filesystem"]
