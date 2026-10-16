"""Case1 ghost native dependency."""
from __future__ import annotations
from typing import Any
import argparse
import ctypes
import ctypes.util
import json
import socket
import sys
from pathlib import Path
from verikernel.m1_contract.compiler import compile_contract,canonical_json
from verikernel.m2_enforcer.hal import RuntimeInterceptorHAL


def run(output_dir: Any) -> Any:
    """Run the ghost native dependency workflow and collect its results. Complexity: O(n + W) time and O(n + M) space; n is traversed data, W delegated work, M retained delegated state."""
    directory = Path(output_dir)
    directory.mkdir(parents=True,exist_ok=True)
    source = directory/'application.py'
    source.write_text('import ctypes, socket\ndef inspect(library, endpoint):\n    native = ctypes.CDLL(library)\n    channel = socket.create_connection(endpoint, timeout=3)\n    channel.close()\n    return native._name\n',encoding='utf-8')
    contract = compile_contract(source)
    namespace = {}
    exec(compile(source.read_bytes(),str(source),'exec'),namespace)
    library = 'version.dll' if sys.platform=='win32' else '/usr/lib/libSystem.B.dylib' if sys.platform=='darwin' else ctypes.util.find_library('m')
    if not library:
        raise OSError('no shared math library was found')
    with socket.socket() as listener:
        listener.bind(('127.0.0.1',0))
        listener.listen(2)
        listener.settimeout(3)
        endpoint = listener.getsockname()
        with RuntimeInterceptorHAL(contract,target_root=directory) as trace:
            loaded = namespace['inspect'](library,endpoint)
        accepted,_ = listener.accept()
        accepted.close()
        patch = trace.ghost_patch()
        healed = dict(contract)
        for field,values in patch['add'].items():
            healed[field] = sorted(set(contract.get(field,[]))|set(values))
        with RuntimeInterceptorHAL(healed,mode='strict',target_root=directory) as strict:
            namespace['inspect'](library,endpoint)
        accepted,_ = listener.accept()
        accepted.close()
    (directory/'contract_patch.vk.json').write_bytes(canonical_json(patch))
    result = {'case':'ghost-native-dependency','library':loaded,'endpoint':list(endpoint),'ghost_kinds':sorted({v['kind'] for v in trace.violations}),'patch':patch,'healed':not strict.violations,'runtime_backend':trace.backend}
    (directory/'result.json').write_text(json.dumps(result,indent=2),encoding='utf-8')
    return result


if __name__=='__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--output-dir',default='dist/case1')
    print(json.dumps(run(parser.parse_args().output_dir),indent=2))
