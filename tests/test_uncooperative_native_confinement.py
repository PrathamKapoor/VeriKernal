import ctypes
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import pytest
from verikernel.m2_enforcer.native_supervisor import target_binary


def test_minimal_guest_keeps_runtime_and_rejects_toolchain_and_escaping_paths():
    from scripts.guest_image import keep_path
    assert keep_path('usr/bin/python3.12')
    assert keep_path('usr/lib/python3.12/subprocess.py')
    assert keep_path('usr/lib/python3.12/__pycache__/subprocess.cpython-312.pyc')
    assert not keep_path('usr/lib/modules/6.8/kernel.ko')
    assert not keep_path('root/.rustup/toolchain/rustc')
    assert not keep_path('usr/lib/python3.12/site-packages/unreviewed.py')
    with pytest.raises(ValueError):
        keep_path('../outside')


def test_real_job_object_denies_spawn_and_memory_without_preload(tmp_path):
    from verikernel.m2_enforcer.win32_job_sandbox import run_resource_confinement, verify_kernel_accounting
    result = run_resource_confinement(tmp_path/'ledger')
    assert result['spawn']['denied']
    assert result['memory']['denied']
    assert result['controls']['spawn_succeeded'] and result['controls']['memory_succeeded']
    from verikernel.m4_attest.ledger_store import verify_ledger_history
    assert verify_ledger_history(tmp_path/'ledger')['valid']
    assert verify_kernel_accounting(tmp_path/'ledger')['accounting_bound']
    payload = tmp_path/'ledger/kernel_accounting.json'
    payload.write_bytes(payload.read_bytes()+b' ')
    with pytest.raises(ValueError):
        verify_kernel_accounting(tmp_path/'ledger')
    if sys.platform == 'win32':
        assert result['spawn']['accounting']['total_processes'] >= 1
        assert result['spawn']['assigned_before_resume']
        assert result['memory']['memory_limit_bytes'] == 16*1024*1024


def test_real_linux_preexec_filter_denies_uncooperative_socket_and_spawn():
    from scripts.verify_native_confinement import verify_linux_confinement
    report = verify_linux_confinement()
    assert report['verified']
    assert report['socket']['errno'] == 13
    assert report['spawn']['denied']
    assert report['landlock']['denied']
    assert report['controls']['socket_succeeded'] and report['controls']['spawn_succeeded']


def test_pe_mapped_import_thunk_redirect_and_bounds():
    from verikernel.m5_ringbuf.native import library_path
    library = library_path()
    find = library.vk_pe_iat_find_thunk
    patch = library.vk_pe_iat_redirect
    find.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_char_p, ctypes.c_char_p, ctypes.POINTER(ctypes.c_size_t)]
    find.restype = ctypes.c_int
    patch.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_size_t, ctypes.c_uint64, ctypes.c_uint64]
    patch.restype = ctypes.c_int
    image = bytearray(4096)
    image[:2] = b'MZ'
    struct.pack_into('<I', image, 60, 128)
    image[128:132] = b'PE\0\0'
    struct.pack_into('<H', image, 152, 0x20b)
    struct.pack_into('<II', image, 152+120, 512, 40)
    struct.pack_into('<IIIII', image, 512, 640, 0, 0, 768, 896)
    image[768:781] = b'KERNEL32.dll\0'
    struct.pack_into('<QQ', image, 640, 1024, 0)
    image[1026:1039] = b'CreateFileW\0\0'
    struct.pack_into('<Q', image, 896, 0x12345678)
    data = (ctypes.c_uint8*len(image)).from_buffer(image)
    offset = ctypes.c_size_t()
    assert find(data,len(image),b'kernel32.dll',b'CreateFileW',ctypes.byref(offset)) == 0
    assert offset.value == 896
    assert patch(data,len(image),offset.value,0x12345678,0x87654321) == 0
    assert struct.unpack_from('<Q',image,896)[0] == 0x87654321
    assert patch(data,len(image),offset.value,0x12345678,0) != 0
    assert find(data,256,b'kernel32.dll',b'CreateFileW',ctypes.byref(offset)) != 0


def test_pe_enumerates_named_and_ordinal_thunks():
    from verikernel.m5_ringbuf.native import library_path
    from verikernel.m1_contract.binary_inspector import build_synthetic_pe
    count = library_path().vk_pe_iat_count
    count.argtypes = [ctypes.c_void_p,ctypes.c_size_t,ctypes.POINTER(ctypes.c_size_t)]
    count.restype = ctypes.c_int
    image = bytearray(4096)
    image[:2] = b'MZ'
    struct.pack_into('<I',image,60,128)
    image[128:132] = b'PE\0\0'
    struct.pack_into('<H',image,152,0x20b)
    struct.pack_into('<II',image,272,512,40)
    struct.pack_into('<IIIII',image,512,640,0,0,768,896)
    image[768:781] = b'KERNEL32.dll\0'
    for index,name in enumerate([b'CreateFileW\0',b'WriteFile\0',b'CreateProcessW\0']):
        struct.pack_into('<Q',image,640+index*8,1024+index*32)
        image[1026+index*32:1026+index*32+len(name)] = name
        struct.pack_into('<Q',image,896+index*8,0x1000+index)
    struct.pack_into('<Q',image,664,(1<<63)|12)
    struct.pack_into('<Q',image,920,0x1234)
    data = (ctypes.c_uint8*len(image)).from_buffer(image)
    total = ctypes.c_size_t()
    assert count(data,len(image),ctypes.byref(total)) == 0
    assert total.value == 4


def test_native_launcher_assigns_kernel_limits_before_execution(tmp_path):
    binary = target_binary()
    launcher = binary.parent/('verikernel-sandbox-exec.exe' if sys.platform == 'win32' else 'verikernel-sandbox-exec')
    marker = tmp_path/'forbidden-child.marker'
    result = subprocess.run([str(launcher),'--',str(binary),'--uncooperative-spawn','--marker',str(marker)],capture_output=True,text=True,timeout=20)
    assert result.returncode != 0 and not marker.exists()
    attacks = [json.loads(line) for line in result.stdout.splitlines() if line.startswith('{')]
    assert attacks[-1]['denied']
