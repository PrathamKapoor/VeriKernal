"""Seccomp bpf."""
from __future__ import annotations
import struct

SOCK_FILTER = struct.Struct('<HBBI')
BPF_LD_W_ABS, BPF_JMP_JEQ_K, BPF_RET_K = 0x20, 0x15, 0x06
BPF_JMP_JSET_K = 0x45
SECCOMP_RET_KILL_PROCESS = 0x80000000
SECCOMP_RET_TRAP = 0x00030000
SECCOMP_RET_ERRNO = 0x00050000
SECCOMP_RET_USER_NOTIF = 0x7fc00000
SECCOMP_RET_ALLOW = 0x7fff0000
OFFSET_NR, OFFSET_ARCH = 0, 4
AUDIT_ARCH_X86_64, AUDIT_ARCH_AARCH64 = 0xc000003e, 0xc00000b7


def verify_program(program: bytes) -> list[tuple[int,int,int,int]]:
    """Reject malformed instructions and out-of-range cBPF control flow. Complexity: O(n + W) time and O(n + M) space; n is traversed data, W delegated work, M retained delegated state."""
    if not program or len(program) % 8 or len(program)//8 > 4096:
        raise ValueError('invalid filter length')
    instructions = list(SOCK_FILTER.iter_unpack(program))
    for index, (op, yes, no, value) in enumerate(instructions):
        if op == BPF_RET_K:
            if yes or no:
                raise ValueError('noncanonical return')
        elif op == BPF_LD_W_ABS:
            if yes or no or value not in {OFFSET_NR, OFFSET_ARCH} or index+1 >= len(instructions):
                raise ValueError('invalid seccomp load')
        elif op in {BPF_JMP_JEQ_K, BPF_JMP_JSET_K}:
            if any(index+1+offset >= len(instructions) for offset in [yes, no]):
                raise ValueError('jump leaves filter')
        else:
            raise ValueError('unsupported classic filter instruction')
    return instructions


def compile_seccomp_bpf(trapped_syscalls: object, errno_syscalls: object=None, arch: object=AUDIT_ARCH_X86_64) -> object:
    """Compile architecture checks and syscall decisions into cBPF instructions. Complexity: O(n + W) time and O(n + M) space; n is traversed data, W delegated work, M retained delegated state."""
    if arch not in {AUDIT_ARCH_X86_64, AUDIT_ARCH_AARCH64}:
        raise ValueError('unsupported architecture')
    trapped = set(trapped_syscalls)
    denied = dict(errno_syscalls or {})
    if trapped & denied.keys() or any(type(n) is not int or not 0 <= n < 0x40000000 for n in trapped | denied.keys()):
        raise ValueError('ambiguous or invalid syscall rules')
    code = [(BPF_LD_W_ABS,0,0,OFFSET_ARCH), (BPF_JMP_JEQ_K,1,0,arch), (BPF_RET_K,0,0,SECCOMP_RET_KILL_PROCESS), (BPF_LD_W_ABS,0,0,OFFSET_NR)]
    if arch == AUDIT_ARCH_X86_64:
        code += [(BPF_JMP_JSET_K,0,1,0x40000000), (BPF_RET_K,0,0,SECCOMP_RET_KILL_PROCESS)]
    for syscall in sorted(trapped | denied.keys()):
        result = SECCOMP_RET_USER_NOTIF if syscall in trapped else SECCOMP_RET_ERRNO | (int(denied[syscall]) & 0xffff)
        code += [(BPF_JMP_JEQ_K,0,1,syscall), (BPF_RET_K,0,0,result)]
    code += [(BPF_RET_K,0,0,SECCOMP_RET_ALLOW)]
    program = b''.join(SOCK_FILTER.pack(*instruction) for instruction in code)
    verify_program(program)
    return program


def execute_cbpf_vm(program_bytes: object, syscall_nr: int, arch: object=AUDIT_ARCH_X86_64) -> object:
    """Evaluate a verified seccomp program against a syscall and architecture. Complexity: O(n + W) time and O(n + M) space; n is traversed data, W delegated work, M retained delegated state."""
    instructions = verify_program(program_bytes)
    accumulator, position = 0, 0
    while position < len(instructions):
        op, yes, no, value = instructions[position]
        if op == BPF_RET_K:
            return value
        if op == BPF_LD_W_ABS:
            accumulator = (syscall_nr if value == OFFSET_NR else arch) & 0xffffffff
            position += 1
        else:
            matches = accumulator == value if op == BPF_JMP_JEQ_K else bool(accumulator & value)
            position += 1 + (yes if matches else no)
    raise ValueError('unterminated filter')
