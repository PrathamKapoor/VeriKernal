import ctypes
import pytest


def test_recursive_json_and_contract_validation():
    from verikernel.type_boundaries import validate_contract_dict, validate_json
    assert validate_contract_dict({'filesystem':['hello'], 'network':[]})['filesystem'] == ['hello']
    for malformed in [[], {'filesystem':'hello'}, {'network':[1]}, {'inputs':{'a':4}}, {'filesystem':[None]}]:
        with pytest.raises((TypeError, ValueError)):
            validate_contract_dict(malformed)
    for malformed in [float('nan'), {1:'bad'}, {'bad':object()}, bytes(1)]:
        with pytest.raises((TypeError, ValueError)):
            validate_json(malformed)


def test_bundle_rejects_wrong_types_and_lengths():
    from verikernel.type_boundaries import validate_bundle_dict
    for malformed in [{}, {'manifest':[], 'public_key':'00', 'envelope':{}}, {'manifest':{'event_count':True}, 'public_key':'00'*1952, 'envelope':{}}]:
        with pytest.raises((TypeError, ValueError)):
            validate_bundle_dict(malformed)


def test_audit_and_wire_boundary():
    from verikernel.type_boundaries import narrow_audit_args, WireEvent
    assert ctypes.sizeof(WireEvent) == 128
    assert WireEvent.ratchet_tag.offset == 96
    assert narrow_audit_args('open', ('file', 'r', 0))[0] == 'file'
    assert narrow_audit_args('socket.connect', (object(), ('localhost', 80)))[1] == ('localhost', 80)
    for name, args in [('open', (object(),)), ('socket.connect', (1,)), ('open', [])]:
        with pytest.raises((TypeError, ValueError)):
            narrow_audit_args(name, args)


def test_quality_rejects_aliased_dynamic_annotations(tmp_path):
    from scripts.quality_audit import audit_python_source
    path = tmp_path/'boundary.py'
    path.write_text('"""Boundary."""\nfrom typing import Any as Loose\ndef typed(x: Loose) -> Loose:\n    """O(1) identity."""\n    return x\n')
    assert any(item['rule'] == 'dynamic-annotation' for item in audit_python_source(path))
