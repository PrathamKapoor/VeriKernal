"""Compiler."""
from __future__ import annotations
import json
import re
import sys
import tomllib
from pathlib import Path
from verikernel.omnibor import gitoid_sha256, input_manifest
from verikernel.type_boundaries import ContractDict, validate_contract_dict
from .ast_scanner import scan_path
from .binary_inspector import parse_elf_needed, parse_pe_imports

ALIASES = {"scikit-learn": "sklearn", "pyyaml": "yaml", "pillow": "PIL", "beautifulsoup4": "bs4", "opencv-python": "cv2", "pyjwt": "jwt"}


def canonical_json(value: object) -> bytes:
    """canonical json. Complexity: O(b + f log f) time and O(b + f) space for source bytes b and indexed artifacts f."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def compile_contract(repo_path: str | Path, output: str | Path | None=None) -> ContractDict:
    """compile contract. Complexity: O(b + f log f) time and O(b + f) space for source bytes b and indexed artifacts f."""
    target = Path(repo_path).resolve(strict=True)
    root = target if target.is_dir() else target.parent
    scanned = scan_path(target) if target.is_dir() or target.suffix == '.py' else {key:[] for key in ('imports', 'subprocesses', 'shared_libraries', 'environment', 'filesystem')}
    if target.is_file() and target.suffix != '.py':
        scanned['subprocesses'] = [str(target)]
    config_path = root / "pyproject.toml"
    config = tomllib.loads(config_path.read_text(encoding="utf-8")) if config_path.exists() else {}
    dependencies = config.get("project", {}).get("dependencies", [])
    declared = set()
    for dep in dependencies:
        name = re.split(r"[\s\[<>=!~;@]", dep, maxsplit=1)[0].lower().replace("_", "-")
        declared.add(ALIASES.get(name, name.replace("-", "_")))
    files = [target] if target.is_file() else sorted(p for p in root.rglob("*") if p.is_file() and not any(x in {".git", ".venv", ".tmp", "__pycache__", ".pytest_cache", "target"} for x in p.relative_to(root).parts) and p.suffix in {".py", ".toml", ".so", ".dll", ".exe", ".pyd"})
    identities = {}
    libraries = set(scanned["shared_libraries"])
    for file in files:
        data = file.read_bytes()
        identities[str(file.relative_to(root))] = gitoid_sha256(data)
        if data[:4] == b"\x7fELF":
            libraries.update(parse_elf_needed(data))
        elif data[:2] == b"MZ":
            libraries.update(parse_pe_imports(data))
    _, manifest_id = input_manifest(identities.values())
    local = {p.stem for p in root.glob("*.py")} | {p.name for p in root.iterdir() if p.is_dir() and (p / "__init__.py").exists()}
    contract = {"schema": "verikernel-contract-v1", "root": str(root), **scanned, "shared_libraries": sorted(libraries), "filesystem": sorted(str((root / p).resolve()) for p in scanned["filesystem"]), "declared_imports": sorted(declared), "ghost_imports": sorted(set(scanned["imports"]) - declared - sys.stdlib_module_names - local), "inputs": identities, "input_manifest_gitoid": manifest_id, "network": []}
    contract["contract_gitoid"] = gitoid_sha256(canonical_json(contract))
    if output:
        Path(output).write_bytes(canonical_json(contract))
    return validate_contract_dict(contract)
