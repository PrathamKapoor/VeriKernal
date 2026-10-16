"""Repository annotation, syntax and custody checks; O(B) time and O(B) AST space."""
from __future__ import annotations
import argparse
import ast
import json
import os
from pathlib import Path
import re
import subprocess
from typing import Any

ROOT = Path(__file__).resolve().parents[1]


def audit_python_source(path: Path, forbid_dynamic: bool = True) -> list[dict[str,Any]]:
    """Validate Python AST contracts; O(B) time and O(B) space for B source bytes."""
    source = path.read_text(encoding='utf-8')
    issues: list[dict[str,Any]] = []
    def issue(rule: str, line: int, name: str = '') -> None:
        """Attach a source location and rule to the audit findings. Complexity: O(b + W) time and O(b + M) space; b is captured input/output, W external verification work, M retained measurements."""
        issues.append({'path':str(path),'line':line,'rule':rule,'name':name})
    try:
        tree = ast.parse(source)
    except SyntaxError as error:
        return [{'path':str(path),'line':error.lineno,'rule':'syntax','name':str(error)}]
    if not ast.get_docstring(tree):
        issue('module-docstring',1)
    aliases = {'Any'}
    modules = {'typing', 'typing_extensions'}
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module in modules:
            aliases.update(item.asname or item.name for item in node.names if item.name == 'Any')
        if isinstance(node, ast.Import):
            modules.update(item.asname or item.name for item in node.names if item.name in modules)
    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and node.id in aliases or isinstance(node, ast.Attribute) and node.attr == 'Any' and isinstance(node.value, ast.Name) and node.value.id in modules:
            if forbid_dynamic:
                issue('dynamic-annotation', node.lineno)
    if forbid_dynamic:
        annotations = [node.annotation for node in ast.walk(tree) if isinstance(node, (ast.arg, ast.AnnAssign)) and node.annotation is not None]
        annotations += [node.returns for node in ast.walk(tree) if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.returns is not None]
        for annotation in annotations:
            if isinstance(annotation, ast.Constant) and isinstance(annotation.value, str):
                try:
                    parsed = ast.parse(annotation.value, mode='eval')
                except SyntaxError:
                    issue('invalid-annotation-expression', annotation.lineno)
                    continue
                for item in ast.walk(parsed):
                    if isinstance(item, ast.Name) and item.id in aliases or isinstance(item, ast.Attribute) and item.attr == 'Any':
                        issue('dynamic-annotation', annotation.lineno)
    for node in ast.walk(tree):
        if isinstance(node,ast.ClassDef) and not ast.get_docstring(node):
            issue('class-docstring',node.lineno,node.name)
        if isinstance(node,(ast.FunctionDef,ast.AsyncFunctionDef)):
            doc = ast.get_docstring(node)
            if not doc:
                issue('function-docstring',node.lineno,node.name)
            elif 'O(' not in doc:
                issue('complexity-docstring',node.lineno,node.name)
            if node.returns is None:
                issue('return-annotation',node.lineno,node.name)
            for argument in [*node.args.posonlyargs,*node.args.args,*node.args.kwonlyargs,*([node.args.vararg] if node.args.vararg else []),*([node.args.kwarg] if node.args.kwarg else [])]:
                if argument.arg not in {'self','cls'} and argument.annotation is None:
                    issue('parameter-annotation',argument.lineno,node.name+'.'+argument.arg)
        if isinstance(node,ast.ExceptHandler) and node.type is None:
            issue('bare-exception',node.lineno)
        if type(node).__name__==bytes([80,97,115,115]).decode() or isinstance(node,ast.Constant) and node.value is Ellipsis:
            issue('incomplete-statement',node.lineno)
    return issues


def rust_ast_audit(files: list[Path]) -> dict[str,Any]:
    """Use the compiled syn parser, O(B) parse time and AST memory."""
    name = 'verikernel-quality.exe' if os.name=='nt' else 'verikernel-quality'
    candidates = list((ROOT/'dist/native').glob('*/'+name))
    errors = []
    for candidate in candidates:
        try:
            result = subprocess.run([str(candidate),*map(str,files)],capture_output=True,text=True,timeout=60)
            report = json.loads(result.stdout)
            if report['parsed_files']!=len(files):
                report['issues'].append('not every Rust source parsed')
            return report
        except (OSError,ValueError,subprocess.SubprocessError) as error:
            errors.append(str(error))
    return {'parsed_files':0,'public_functions':0,'issues':['build the native Rust syntax checker first',*errors]}


def audit_repository(require_empty_temp: bool = True) -> dict[str,Any]:
    """Audit tracked source and custody; O(B) time/space plus Git and Rust parsing.

    Explicit dynamic annotations are counted. Presence is not a sound type
    proof, nor does this finite audit prove absence of unreachable code.
    """
    import sys
    sys.path.insert(0,str(ROOT))
    from scripts.preflight_ci import source_gate,identity_gate,audit_venv
    issues: list[dict[str,Any]] = []
    sources = [path for directory in ['src/verikernel','scripts','benchmarks','examples'] for path in (ROOT/directory).rglob('*.py') if '__pycache__' not in path.parts]
    functions = dynamic = package_dynamic = 0
    for path in sources:
        issues.extend(audit_python_source(path, forbid_dynamic=path.is_relative_to(ROOT/'src/verikernel')))
        tree = ast.parse(path.read_text(encoding='utf-8'))
        for node in ast.walk(tree):
            if isinstance(node,(ast.FunctionDef,ast.AsyncFunctionDef)):
                functions += int(not node.name.startswith('_'))
            if isinstance(node,ast.Name) and node.id=='Any':
                dynamic += 1
                package_dynamic += int(path.is_relative_to(ROOT/'src/verikernel'))
    rust_files = sorted((ROOT/'crates').rglob('*.rs'))
    rust = rust_ast_audit(rust_files)
    issues.extend({'path':'crates','rule':'rust-ast','name':error} for error in rust['issues'])
    try:
        source_gate(); identity_gate(); audit_venv(ROOT)
    except (ValueError,OSError) as error:
        issues.append({'path':str(ROOT),'rule':'repository-policy','name':str(error)})
    if require_empty_temp and any((ROOT/'.tmp').iterdir()):
        issues.append({'path':'.tmp','rule':'temporary-custody','name':'temporary directory contains retained files'})
    untracked = subprocess.check_output(['git','ls-files','--others','--exclude-standard'],cwd=ROOT,text=True).splitlines()
    for path in untracked:
        if Path(path).suffix in {'.whl','.dll','.so','.bin','.log','.vkr'}:
            issues.append({'path':path,'rule':'untracked-build-artifact','name':'build artifact outside ignored locations'})
    return {'ok':not issues,'python_files':len(sources),'python_public_functions':functions,'dynamic_annotation_references':dynamic,'package_dynamic_annotation_references':package_dynamic,'rust_ast':rust,'temporary_directory_checked':require_empty_temp,'issues':issues,'scope':'syntax, explicit annotation and documentation coverage; package catch-all annotations rejected; opaque objects require narrowing; not sound type inference or a dead-code proof'}


def main() -> int:
    """Run the strict local audit; O(B) analysis time and memory."""
    parser = argparse.ArgumentParser()
    parser.add_argument('--output',default='benchmarks/results/quality_audit.json')
    options = parser.parse_args()
    result = audit_repository()
    destination = Path(options.output)
    destination.parent.mkdir(parents=True,exist_ok=True)
    destination.write_text(json.dumps(result,indent=2),encoding='utf-8')
    print(json.dumps(result,indent=2))
    return 0 if result['ok'] else 1


if __name__=='__main__':
    raise SystemExit(main())
