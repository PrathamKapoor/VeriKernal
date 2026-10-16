"""Binary inspector."""
from __future__ import annotations
import struct


def _unpack(fmt: object, data: object, offset: object) -> object:
    """unpack. Complexity: O(b^2) worst-case bounded-table/string traversal time and O(b) space; b is input size."""
    size = struct.calcsize(fmt)
    if offset < 0 or offset + size > len(data):
        raise ValueError("binary structure outside file")
    return struct.unpack_from(fmt, data, offset)


def _cstring(data: object, offset: object, limit: object=None) -> object:
    """cstring. Complexity: O(b^2) worst-case bounded-table/string traversal time and O(b) space; b is input size."""
    limit = len(data) if limit is None else min(limit, len(data))
    if not 0 <= offset < limit:
        raise ValueError("string offset outside table")
    end = data.find(b"\0", offset, limit)
    if end < 0:
        raise ValueError("unterminated binary string")
    return data[offset:end].decode("utf-8", errors="strict")


def parse_elf_needed(data: bytes) -> list[str]:
    """parse elf needed. Complexity: O(b^2) worst-case bounded-table/string traversal time and O(b) space; b is input size."""
    if len(data) < 16 or data[:4] != b"\x7fELF" or data[4] not in (1, 2) or data[5] not in (1, 2):
        raise ValueError("invalid ELF identification")
    endian = "<" if data[5] == 1 else ">"
    wide = data[4] == 2
    header = _unpack(endian + ("HHIQQQIHHHHHH" if wide else "HHIIIIIHHHHHH"), data, 16)
    phoff, phsize, phnum = header[4], header[8], header[9]
    segments = []
    dynamic = None
    required_size = 56 if wide else 32
    if phsize < required_size and phnum:
        raise ValueError("short ELF program header")
    for i in range(phnum):
        p = _unpack(endian + ("IIQQQQQQ" if wide else "IIIIIIII"), data, phoff + i * phsize)
        typ, offset, addr, size = (p[0], p[2], p[3], p[5]) if wide else (p[0], p[1], p[2], p[4])
        if offset + size > len(data):
            raise ValueError("truncated ELF segment")
        if typ == 1:
            segments.append((addr, offset, size))
        if typ == 2:
            dynamic = (offset, size)
    if dynamic is None:
        return []
    needed, straddr, strsize = [], None, None
    step = 16 if wide else 8
    for pos in range(dynamic[0], dynamic[0] + dynamic[1], step):
        tag, value = _unpack(endian + ("qQ" if wide else "iI"), data, pos)
        if tag == 0:
            break
        if tag == 1:
            needed.append(value)
        elif tag == 5:
            straddr = value
        elif tag == 10:
            strsize = value
    else:
        raise ValueError("unterminated ELF dynamic table")
    if not needed:
        return []
    if straddr is None or strsize is None:
        raise ValueError("missing ELF string table")
    for addr, offset, size in segments:
        if addr <= straddr and straddr + strsize <= addr + size:
            base = offset + straddr - addr
            return [_cstring(data, base + n, base + strsize) for n in needed]
    raise ValueError("unmapped ELF string table")


def build_synthetic_elf(needed_libs: list[str]) -> bytes:
    """build synthetic elf. Complexity: O(b^2) worst-case bounded-table/string traversal time and O(b) space; b is input size."""
    strings = b"\0"
    indices = []
    for lib in needed_libs:
        indices.append(len(strings))
        strings += lib.encode() + b"\0"
    dyn = b"".join(struct.pack("<qQ", 1, n) for n in indices)
    string_offset = 176 + len(dyn) + 48
    dyn += struct.pack("<qQqQqQ", 5, 0x400000 + string_offset, 10, len(strings), 0, 0)
    size = string_offset + len(strings)
    ident = b"\x7fELF\x02\x01\x01" + bytes(9)
    header = struct.pack("<HHIQQQIHHHHHH", 3, 62, 1, 0, 64, 0, 0, 64, 56, 2, 0, 0, 0)
    load = struct.pack("<IIQQQQQQ", 1, 4, 0, 0x400000, 0, size, size, 4096)
    dynamic = struct.pack("<IIQQQQQQ", 2, 4, 176, 0x4000B0, 0, len(dyn), len(dyn), 8)
    return ident + header + load + dynamic + dyn + strings


def parse_pe_imports(data: bytes) -> list[str]:
    """parse pe imports. Complexity: O(b^2) worst-case bounded-table/string traversal time and O(b) space; b is input size."""
    if data[:2] != b"MZ":
        raise ValueError("invalid DOS header")
    pe = _unpack("<I", data, 60)[0]
    if data[pe:pe+4] != b"PE\0\0":
        raise ValueError("invalid PE signature")
    _, sections, _, _, _, optsize, _ = _unpack("<HHIIIHH", data, pe + 4)
    opt = pe + 24
    magic = _unpack("<H", data, opt)[0]
    if magic not in (0x10B, 0x20B):
        raise ValueError("unsupported PE optional header")
    directories = opt + (112 if magic == 0x20B else 96)
    if opt + optsize > len(data) or directories + 16 > opt + optsize:
        raise ValueError("truncated PE optional header")
    rva, directory_size = _unpack("<II", data, directories + 8)
    maps = []
    for i in range(sections):
        _, vsize, va, rawsize, raw, _, _, _, _, _ = _unpack("<8sIIIIIIHHI", data, opt + optsize + i * 40)
        if raw + rawsize > len(data):
            raise ValueError("truncated PE section")
        maps.append((va, raw, rawsize))

    def translate(address: object, size: int=1) -> object:
        """translate. Complexity: O(b^2) worst-case bounded-table/string traversal time and O(b) space; b is input size."""
        for va, raw, rawsize in maps:
            if va <= address and address + size <= va + rawsize:
                return raw + address - va, raw + rawsize
        raise ValueError("unmapped PE RVA")

    if rva == 0:
        return []
    result = []
    for delta in range(0, directory_size, 20):
        pos, _ = translate(rva + delta, 20)
        descriptor = _unpack("<IIIII", data, pos)
        if not any(descriptor):
            return result
        name, limit = translate(descriptor[3])
        result.append(_cstring(data, name, limit))
    raise ValueError("unterminated PE import directory")


def build_synthetic_pe(imported_dlls: list[str]) -> bytes:
    """build synthetic pe. Complexity: O(b^2) worst-case bounded-table/string traversal time and O(b) space; b is input size."""
    table_size = (len(imported_dlls) + 1) * 20
    strings = b""
    descriptors = b""
    for name in imported_dlls:
        descriptors += struct.pack("<IIIII", 0, 0, 0, 0x1000 + table_size + len(strings), 0)
        strings += name.encode() + b"\0"
    body = descriptors + bytes(20) + strings
    rawsize = (len(body) + 511) & ~511
    head = bytearray(512)
    head[:2] = b"MZ"
    struct.pack_into("<I", head, 60, 128)
    head[128:132] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", head, 132, 0x8664, 1, 0, 0, 0, 240, 0x2022)
    struct.pack_into("<H", head, 152, 0x20B)
    struct.pack_into("<I", head, 152 + 108, 16)
    struct.pack_into("<II", head, 152 + 120, 0x1000, table_size)
    struct.pack_into("<8sIIIIIIHHI", head, 392, b".idata\0\0", len(body), 0x1000, rawsize, 512, 0, 0, 0, 0, 0x40000040)
    return bytes(head) + body + bytes(rawsize - len(body))
