"""Inspect decoded comparator instructions; O(B) time/space for binary bytes.

This certifies a branch-free instruction body in this artifact. It does not
certify the operating system, other primitives, or microarchitectural timing.
"""
from __future__ import annotations
import hashlib
import json
from pathlib import Path
import re
import shutil
import struct
import subprocess
from verikernel.m5_ringbuf.native import library_path

ROOT = Path(__file__).resolve().parents[1]
Instruction = tuple[str, str, str, str]
SYMBOL = 'vk_constant_time_compare_32'


def pe_export(data: bytes, symbol: str) -> tuple[int, int, str]:
    """Resolve a PE export to its file offset and RVA; O(S + E) time, O(S) space."""
    pe = struct.unpack_from('<I', data, 60)[0]
    if data[pe:pe+4] != b'PE\0\0':
        raise ValueError('invalid PE signature')
    machine, sections = struct.unpack_from('<HH', data, pe+4)
    optional_size = struct.unpack_from('<H', data, pe+20)[0]
    optional = pe+24
    magic = struct.unpack_from('<H', data, optional)[0]
    directory = optional+(112 if magic == 0x20b else 96)
    export_rva = struct.unpack_from('<I', data, directory)[0]
    table = []
    for index in range(sections):
        section = optional+optional_size+40*index
        size, rva, raw_size, offset = struct.unpack_from('<IIII', data, section+8)
        table.append((rva, max(size, raw_size), offset))
    def offset(rva: int) -> int:
        """Map a bounded RVA; O(S) time and O(1) space."""
        for start, size, raw in table:
            if start <= rva < start+size:
                result = raw+rva-start
                if result < len(data):
                    return result
        raise ValueError('export RVA outside image')
    exports = offset(export_rva)
    names = struct.unpack_from('<I', data, exports+24)[0]
    functions, name_table, ordinals = struct.unpack_from('<III', data, exports+28)
    for index in range(names):
        name = offset(struct.unpack_from('<I', data, offset(name_table)+4*index)[0])
        end = data.index(b'\0', name)
        if data[name:end].decode('ascii') == symbol:
            ordinal = struct.unpack_from('<H', data, offset(ordinals)+2*index)[0]
            rva = struct.unpack_from('<I', data, offset(functions)+4*ordinal)[0]
            return offset(rva), rva, {0xaa64:'aarch64', 0x8664:'x86_64'}.get(machine, hex(machine))
    raise ValueError('comparison export is missing')


def inspect_body(instructions: list[Instruction]) -> dict[str, object]:
    """Reject conditional control flow and calls in a decoded body; O(I) time/space."""
    branches = []
    for address, raw, mnemonic, operands in instructions:
        conditional = (mnemonic.startswith('j') and mnemonic not in {'jmp', 'jmpq'}) or mnemonic.startswith(('cbz', 'cbnz', 'tbz', 'tbnz', 'b.')) or mnemonic.startswith('loop')
        call = mnemonic in {'call', 'callq', 'bl', 'blr'}
        if conditional or call or mnemonic in {'jmp', 'jmpq', 'br', 'b'}:
            branches.append({'address':address, 'instruction':mnemonic+' '+operands})
    if branches:
        raise ValueError('control flow inside comparison body: '+json.dumps(branches))
    return {'conditional_branches_in_body':[], 'body_instruction_count':len(instructions)}


def elf_symbol(data: bytes, symbol: str) -> tuple[int, int, str]:
    """Resolve an ELF64 little-endian dynamic or static symbol; O(B) time/space."""
    if data[:6] != b'\x7fELF\x02\x01':
        raise ValueError('only little-endian ELF64 is supported')
    machine = struct.unpack_from('<H', data, 18)[0]
    section_offset = struct.unpack_from('<Q', data, 40)[0]
    entry_size, count = struct.unpack_from('<HH', data, 58)
    sections = [struct.unpack_from('<IIQQQQIIQQ', data, section_offset+index*entry_size) for index in range(count)]
    for section in sections:
        if section[1] not in {2, 11} or section[9] < 24:
            continue
        names_section = sections[section[6]]
        names = data[names_section[4]:names_section[4]+names_section[5]]
        for index in range(section[5]//section[9]):
            name, info, other, owner, address, size = struct.unpack_from('<IBBHQQ', data, section[4]+index*section[9])
            if name < len(names) and names[name:names.index(b'\0', name)].decode('ascii') == symbol and owner < count:
                code = sections[owner]
                offset = code[4]+address-code[3]
                if not 0 <= offset < len(data) or size == 0 or offset+size > len(data):
                    raise ValueError('invalid ELF symbol bounds')
                return offset, address, {183:'aarch64', 62:'x86_64'}.get(machine, hex(machine))
    raise ValueError('comparison ELF symbol is missing')


def decode_symbol(path: Path, candidates: list[str], symbol: str = SYMBOL) -> str:
    """Select a compatible decoder with bounded fallback; O(D * B) work/space."""
    errors = []
    for decoder in dict.fromkeys(candidates):
        try:
            version = subprocess.run([decoder, '--version'], capture_output=True, text=True, timeout=10)
            llvm = 'llvm' in (version.stdout+version.stderr).lower()
            option = '--disassemble-symbols=' if llvm else '--disassemble='
            result = subprocess.run([decoder, '-d', option+symbol, str(path)], capture_output=True, text=True, timeout=30)
            if result.returncode == 0 and symbol in result.stdout and re.search(r'^\s*[0-9a-f]+:', result.stdout, re.M):
                return result.stdout
            errors.append(Path(decoder).name+': '+result.stderr[:200])
        except (OSError, subprocess.SubprocessError) as error:
            errors.append(str(error))
    raise RuntimeError('no compatible instruction decoder: '+'; '.join(errors))


CRYPTO_SYMBOLS = (SYMBOL, 'vk_montgomery_reduce_ct', 'vk_caddq_ct', 'vk_ntt_256_ct', 'vk_inv_ntt_256_ct', 'vk_poly_chknorm_ct')


def audit_control_flow(instructions: list[Instruction], architecture: str) -> dict[str, object]:
    """Reject every conditional branch/call after data loads; O(I) time and space.

    All fixed transforms are expanded at compile time, so no loop exemption is
    necessary. Public pointer/bound guards occur before the first input load.
    """
    for address, raw, mnemonic, operands in instructions:
        conditional = mnemonic.startswith(('cbz', 'cbnz', 'tbz', 'tbnz', 'b.','loop')) or mnemonic.startswith('j') and mnemonic not in {'jmp','jmpq'}
        if conditional or mnemonic in {'bl', 'blr', 'call', 'callq', 'br', 'jmp', 'jmpq'}:
            raise ValueError('control transfer in expanded arithmetic body: '+address+' '+mnemonic)
    return {'secret_dependent_branches':[], 'body_instruction_count':len(instructions),
            'property':'no conditional transfers or calls in expanded arithmetic body'}


def verify_crypto_symbols(path: Path | None = None) -> dict[str, object]:
    """Inspect six actual exported fixed-schedule bodies; O(B) time and space."""
    path = path or Path(str(library_path()._name))
    data = path.read_bytes()
    candidates = [shutil.which('llvm-objdump')]
    candidates += [str(p) for p in (ROOT/'dist/development/llvm').glob('*/bin/llvm-objdump.exe')]
    candidates += [shutil.which('objdump')]
    decoders = [p for p in candidates if p and Path(p).is_file()]
    symbols = {}
    for symbol in CRYPTO_SYMBOLS:
        if data[:2] == b'MZ':
            offset, address, architecture = pe_export(data, symbol)
        else:
            offset, address, architecture = elf_symbol(data, symbol)
        decoded = decode_symbol(path, decoders, symbol)
        instructions = []
        for line in decoded.splitlines():
            match = re.match(r'\s*([0-9a-f]+):\s+((?:[0-9a-f]{2}\s+)+|[0-9a-f]{8}\s+)([a-z][a-z0-9.]*)\s*(.*)', line)
            if match:
                instructions.append((match[1], ''.join(match[2].split()), match[3], match[4]))
        if not instructions:
            raise ValueError('no decoded instructions for '+symbol)
        base = int(instructions[0][0], 16)
        for location, raw, mnemonic, operands in instructions:
            code = bytes.fromhex(raw)
            if architecture == 'aarch64':
                code = code[::-1]
            relative = int(location, 16)-base
            if data[offset+relative:offset+relative+len(code)] != code:
                raise ValueError('instruction/file mismatch for '+symbol)
        # Public stack stores do not start the data body. On ARM64 all arithmetic
        # reads through x0; scalar arguments are data from function entry.
        scalar = symbol in {'vk_montgomery_reduce_ct','vk_caddq_ct'}
        if architecture == 'aarch64':
            first = 0 if scalar else next((i for i,item in enumerate(instructions) if item[2].startswith(('ldr','ldur','ldp')) and '[x0' in item[3]), None)
        else:
            first = 0 if scalar else next((i for i,item in enumerate(instructions) if '(' in item[3] and not any(reg in item[3] for reg in ['%rsp','%rbp']) and not item[2].startswith(('lea','nop'))), None)
        if first is None:
            raise ValueError('input load not identified for '+symbol)
        body = instructions[first:]
        end = next((i for i,item in enumerate(body) if item[2] in {'ret','retq'}), None)
        if end is None:
            raise ValueError('missing return for '+symbol)
        body = body[:end+1]
        finding = audit_control_flow(body, architecture)
        size = int(instructions[-1][0], 16)-base+len(instructions[-1][1])//2
        symbols[symbol] = {**finding, 'symbol_rva':address, 'architecture':architecture,
                           'public_prefix_instructions':first, 'machine_code_hex':data[offset:offset+size].hex()}
    return {'verified':True, 'symbols':symbols, 'library_sha256':hashlib.sha256(data).hexdigest(),
            'scope':'six fixed-schedule arithmetic bodies; excludes protocol sampling, providers and operating system'}


def verify_library(path: Path | None = None) -> dict[str, object]:
    """Decode the real exported symbol, excluding public guards; O(B) time/space."""
    path = path or Path(str(library_path()._name))
    data = path.read_bytes()
    candidates = [shutil.which('llvm-objdump')]
    candidates += [str(p) for p in (ROOT/'dist/development/llvm').glob('*/bin/llvm-objdump.exe')]
    candidates += [shutil.which('objdump')]
    decoders = [p for p in candidates if p and Path(p).is_file()]
    if not decoders:
        raise RuntimeError('an instruction decoder is required; raw byte matches are unsound')
    symbol_offset = None
    symbol_rva = None
    architecture = 'decoded-object'
    if data[:2] == b'MZ':
        symbol_offset, symbol_rva, architecture = pe_export(data, SYMBOL)
    elif data[:4] == b'\x7fELF':
        symbol_offset, symbol_rva, architecture = elf_symbol(data, SYMBOL)
    decoded = decode_symbol(path, decoders)
    instructions = []
    for line in decoded.splitlines():
        match = re.match(r'\s*([0-9a-f]+):\s+((?:[0-9a-f]{2}\s+)+|[0-9a-f]{8}\s+)([a-z][a-z0-9.]*)\s*(.*)', line)
        if match:
            instructions.append((match[1], ''.join(match[2].split()), match[3], match[4]))
    if not instructions:
        raise ValueError('decoder did not resolve the requested symbol')
    # Guards may precede loads, but no conditional control flow may follow a read.
    first_read = next((i for i, item in enumerate(instructions) if item[2].startswith(('ldr', 'ldur')) or '(' in item[3] or '[' in item[3]), None)
    if first_read is None:
        raise ValueError('no comparison loads were decoded')
    prefix = instructions[:first_read]
    if architecture == 'aarch64':
        for address, raw, mnemonic, operands in prefix:
            if mnemonic == 'cbz' and operands.split(',')[0].strip() in {'x0', 'x1'}:
                continue
            if mnemonic not in {'mov', 'nop', 'bti'}:
                raise ValueError('unsupported pre-load guard instruction: '+mnemonic)
    body = instructions[first_read:]
    # A separate null-return block can follow the completed comparison return.
    end = next((i for i, item in enumerate(body) if item[2] in {'ret', 'retq'}), None)
    if end is None:
        raise ValueError('comparison has no return')
    body = body[:end+1]
    result = inspect_body(body)
    raw_hex = ''.join(item[1] for item in instructions)
    if symbol_offset is not None:
        byte_count = sum(len(item[1])//2 for item in instructions)
        # ARM decoders print words in host notation; report bytes from the file.
        raw_hex = data[symbol_offset:symbol_offset+byte_count].hex()
        base = int(instructions[0][0], 16)
        for address, encoded, mnemonic, operands in instructions:
            relative = int(address, 16)-base
            emitted = bytes.fromhex(encoded)
            if architecture == 'aarch64':
                emitted = emitted[::-1]
            if data[symbol_offset+relative:symbol_offset+relative+len(emitted)] != emitted:
                raise ValueError('decoded instructions do not match exported file bytes')
    return {**result, 'constant_time_asm_verified':True, 'architecture':architecture,
            'library':str(path), 'symbol':SYMBOL, 'symbol_rva':symbol_rva,
            'artifact_sha256':hashlib.sha256(data).hexdigest(), 'machine_code_hex':raw_hex,
            'guard_instruction_count':first_read,
            'scope':'branch-free decoded comparison body; public pointer guards excluded'}


def main() -> int:
    """Persist full six-symbol bytes and print compact findings; O(B) time/space."""
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--output',default=str(ROOT/'benchmarks/results/crypto_disassembly.json'))
    options = parser.parse_args()
    report = verify_crypto_symbols()
    destination = Path(options.output)
    destination.parent.mkdir(parents=True,exist_ok=True)
    destination.write_text(json.dumps(report,indent=2),encoding='utf-8')
    print(json.dumps({'verified':report['verified'],'symbols':{name:row['body_instruction_count'] for name,row in report['symbols'].items()},'report':str(destination)}))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
