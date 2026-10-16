import ctypes
import subprocess
from pathlib import Path
import pytest
from verikernel.m5_ringbuf.native import library_path


def test_comparator_all_byte_positions_and_null_guards():
    library = library_path()
    compare = library.vk_constant_time_compare_32
    compare.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
    compare.restype = ctypes.c_uint32
    original = bytes(range(32))
    a = ctypes.create_string_buffer(original)
    assert compare(a, a) == 1
    assert compare(None, a) == compare(a, None) == 0
    for index in range(32):
        changed = bytearray(original)
        changed[index] ^= 1
        assert compare(a, ctypes.create_string_buffer(bytes(changed))) == 0


def test_compiled_comparison_body_has_no_conditional_control_flow():
    from scripts.verify_constant_time_asm import verify_library
    report = verify_library()
    assert report['constant_time_asm_verified']
    assert report['body_instruction_count'] > 0
    assert report['conditional_branches_in_body'] == []
    assert report['machine_code_hex']


def test_instruction_classifier_rejects_branch_and_call():
    from scripts.verify_constant_time_asm import inspect_body
    for mnemonic in ['jne', 'cbnz', 'b.eq', 'callq', 'bl']:
        with pytest.raises(ValueError):
            inspect_body([('1000', '01000000', mnemonic, '1004')])


def test_decoder_falls_back_and_uses_gnu_symbol_option(monkeypatch):
    from scripts.verify_constant_time_asm import decode_symbol
    attempts = []
    def run(arguments, **options):
        attempts.append(arguments)
        if arguments[-1] == '--version':
            return subprocess.CompletedProcess(arguments, 0, 'GNU objdump', '')
        if arguments[0] == 'wrong-objdump':
            return subprocess.CompletedProcess(arguments, 1, '', 'unsupported target')
        return subprocess.CompletedProcess(arguments, 0, '00001000 <vk_constant_time_compare_32>:\n1000: c3 ret\n', '')
    monkeypatch.setattr(subprocess, 'run', run)
    result = decode_symbol(Path('library'), ['wrong-objdump', 'objdump'])
    assert '1000: c3 ret' in result
    assert any('--disassemble=vk_constant_time_compare_32' in command for command in attempts)
