"""Ast scanner."""
from __future__ import annotations
import ast
import shlex
from pathlib import Path


def scan_source(source: object, filename: str="<source>") -> object:
    """scan source. Complexity: O(b + f log f) time and O(b + f) space for source bytes b and indexed artifacts f."""
    tree = ast.parse(source, filename=filename)
    result = {k: set() for k in ("imports", "subprocesses", "shared_libraries", "environment", "filesystem")}
    aliases = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for item in node.names:
                result["imports"].add(item.name.split(".")[0])
                aliases[item.asname or item.name.split(".")[0]] = item.name if item.asname else item.name.split(".")[0]
        if isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            result["imports"].add(node.module.split(".")[0])
            for item in node.names:
                aliases[item.asname or item.name] = node.module + "." + item.name

    def name(node: object) -> object:
        """name. Complexity: O(b + f log f) time and O(b + f) space for source bytes b and indexed artifacts f."""
        if isinstance(node, ast.Name):
            return aliases.get(node.id, node.id)
        if isinstance(node, ast.Attribute):
            return name(node.value) + "." + node.attr
        return ""

    def literal(node: object) -> object:
        """literal. Complexity: O(b + f log f) time and O(b + f) space for source bytes b and indexed artifacts f."""
        return node.value if isinstance(node, ast.Constant) and isinstance(node.value, str) else None

    for node in ast.walk(tree):
        if isinstance(node, ast.Subscript) and name(node.value) == "os.environ":
            key = literal(node.slice)
            if key is not None:
                result["environment"].add(key)
        if not isinstance(node, ast.Call) or not node.args:
            continue
        func = name(node.func)
        value = literal(node.args[0])
        if func == "importlib.import_module" and value:
            result["imports"].add(value.split(".")[0])
        if (func.startswith("subprocess.") or func == "os.system" or func.startswith("os.exec")):
            arg = node.args[0]
            command = literal(arg.elts[0]) if isinstance(arg, (ast.List, ast.Tuple)) and arg.elts else value
            if command:
                result["subprocesses"].add(shlex.split(command, posix=False)[0].strip('"'))
        if func.rsplit(".", 1)[-1] in {"CDLL", "WinDLL", "LoadLibrary", "dlopen"} and value:
            result["shared_libraries"].add(value)
        if func in {"os.getenv", "os.environ.get", "os.environ.setdefault"} and value:
            result["environment"].add(value)
        if func in {"open", "io.open", "pathlib.Path", "Path"} and value:
            result["filesystem"].add(value)
    return {k: sorted(v) for k, v in result.items()}


def scan_path(path: object) -> object:
    """scan path. Complexity: O(b + f log f) time and O(b + f) space for source bytes b and indexed artifacts f."""
    path = Path(path)
    files = [path] if path.is_file() else sorted(p for p in path.rglob("*.py") if not any(s in {".venv", ".git", ".tmp"} for s in p.relative_to(path).parts))
    merged = {k: set() for k in ("imports", "subprocesses", "shared_libraries", "environment", "filesystem")}
    for file in files:
        data = scan_source(file.read_text(encoding="utf-8-sig"), str(file))
        for key, values in data.items():
            merged[key].update(values)
    return {k: sorted(v) for k, v in merged.items()}
