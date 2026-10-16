"""Validated serialization and runtime boundaries; O(B) traversal time and space."""
from __future__ import annotations
import ctypes
import math
import os
from collections.abc import Callable, Sequence
from typing import Protocol, TypedDict, cast

JSONScalar = str | int | float | bool | None
JSONValue = JSONScalar | list['JSONValue'] | dict[str, 'JSONValue']


class ContractDict(TypedDict, total=False):
    """Declared capabilities and artifact identities; O(B) stored bytes."""
    schema: str
    root: str
    imports: list[str]
    declared_imports: list[str]
    ghost_imports: list[str]
    shared_libraries: list[str]
    subprocesses: list[str]
    environment: list[str]
    filesystem: list[str]
    network: list[str]
    inputs: dict[str, str]
    input_manifest_gitoid: str
    contract_gitoid: str


class GhostDiffItemDict(TypedDict):
    """One runtime capability delta; O(B) target bytes."""
    kind: str
    field: str
    target: str


class ContractPatchDict(TypedDict):
    """Machine-applicable observed capability patch; O(N) entries."""
    schema: str
    base_contract_gitoid: str | None
    add: dict[str, list[str]]


class EpochHeaderDict(TypedDict):
    """Sealed epoch endpoint and tree commitments; O(1) space."""
    event_count: int
    merkle_root: str
    ratchet_commitment: str
    ratchet_terminal: str
    hash_algorithm: str


class MerkleProofDict(TypedDict):
    """Logarithmic authentication path; O(log N) nodes."""
    index: int
    tree_size: int
    proof: list[str]
    root: str


class DSSESignatureEntryDict(TypedDict):
    """Encoded signature and key identifier; O(S) encoded bytes."""
    keyid: str
    sig: str


class DSSEEnvelopeDict(TypedDict):
    """Payload-bound signature envelope; O(B + S) bytes."""
    payloadType: str
    payload: str
    signatures: list[DSSESignatureEntryDict]


class VkrBundleDict(TypedDict):
    """Container metadata; event bytes are stored separately; O(B) space."""
    manifest: dict[str, JSONValue]
    public_key: str
    envelope: DSSEEnvelopeDict


class BenchmarkMetricRowDict(TypedDict):
    """Measured numeric sample with units; O(1) fields."""
    name: str
    value: float
    unit: str


class QuantumFirewallReceiptDict(TypedDict):
    """Bound uncertainty verdict; O(Q) physical layout entries."""
    verdict: str
    layout: list[int]
    unitary_fidelity: float
    expected_fidelity: float


class EventSink(Protocol):
    """Minimal packed-event consumer interface; complexity depends on consumer."""
    write: Callable[[bytes], int]


class WireEvent(ctypes.LittleEndianStructure):
    """Exact C-ABI descriptor; O(1) fixed 128-byte storage."""
    _fields_ = [('seq_no', ctypes.c_uint64), ('timestamp_ns', ctypes.c_uint64),
                ('pid', ctypes.c_uint32), ('tid', ctypes.c_uint32),
                ('syscall_nr', ctypes.c_uint32), ('fault_injected', ctypes.c_int32),
                ('dev_id', ctypes.c_uint64), ('inode_nr', ctypes.c_uint64),
                ('mtime_ns', ctypes.c_uint64), ('call_stack_hash', ctypes.c_uint64),
                ('target_digest', ctypes.c_uint8*32), ('ratchet_tag', ctypes.c_uint8*32)]


def validate_json(value: object, depth: int = 0) -> JSONValue:
    """Reject non-JSON objects and excessive nesting; O(B) time/space, depth <= 64."""
    if depth > 64:
        raise ValueError('JSON nesting exceeds 64 levels')
    if value is None or type(value) in (str, int, bool):
        return cast(JSONScalar, value)
    if type(value) is float and math.isfinite(value):
        return value
    if isinstance(value, list):
        return [validate_json(item, depth+1) for item in value]
    if isinstance(value, dict) and all(isinstance(key, str) for key in value):
        return {key:validate_json(item, depth+1) for key, item in value.items()}
    raise TypeError('value is not finite, string-keyed JSON')


def _mapping(value: object) -> dict[str, JSONValue]:
    """Validate a JSON object; O(B) time and space."""
    result = validate_json(value)
    if not isinstance(result, dict):
        raise TypeError('expected a JSON object')
    return result


def validate_contract_dict(value: object) -> ContractDict:
    """Narrow capabilities and artifact maps; O(B) time and space."""
    result = _mapping(value)
    for key in ('imports', 'declared_imports', 'ghost_imports', 'shared_libraries', 'subprocesses', 'environment', 'filesystem', 'network'):
        if key in result and (not isinstance(result[key], list) or not all(isinstance(item, str) for item in result[key])):
            raise TypeError(key+' must be a list of strings')
    for key in ('schema', 'root', 'input_manifest_gitoid', 'contract_gitoid'):
        if key in result and not isinstance(result[key], str):
            raise TypeError(key+' must be a string')
    if 'inputs' in result and (not isinstance(result['inputs'], dict) or not all(isinstance(item, str) for item in result['inputs'].values())):
        raise TypeError('inputs must map paths to string identifiers')
    return cast(ContractDict, result)


def validate_dsse_dict(value: object) -> DSSEEnvelopeDict:
    """Narrow DSSE structure before cryptographic decoding; O(B) time/space."""
    result = _mapping(value)
    if not isinstance(result.get('payloadType'), str) or not isinstance(result.get('payload'), str):
        raise TypeError('DSSE payload fields must be strings')
    signatures = result.get('signatures')
    if not isinstance(signatures, list) or len(signatures) != 1:
        raise ValueError('exactly one DSSE signature is required')
    for signature in signatures:
        if not isinstance(signature, dict) or not isinstance(signature.get('keyid'), str) or not isinstance(signature.get('sig'), str):
            raise TypeError('invalid DSSE signature entry')
    return cast(DSSEEnvelopeDict, result)


def validate_bundle_dict(value: object) -> VkrBundleDict:
    """Validate sealed receipt metadata, lengths and counters; O(B) time/space."""
    result = _mapping(value)
    manifest = result.get('manifest')
    if not isinstance(manifest, dict):
        raise TypeError('manifest must be an object')
    count = manifest.get('event_count')
    if type(count) is not int or count < 0:
        raise ValueError('event_count must be a nonnegative integer')
    for field in ('merkle_root', 'ratchet_commitment', 'ratchet_terminal'):
        encoded = manifest.get(field)
        if not isinstance(encoded, str) or len(encoded) != 64 or len(bytes.fromhex(encoded)) != 32:
            raise ValueError(field+' must encode 32 bytes')
    key = result.get('public_key')
    if not isinstance(key, str) or len(key) != 3904 or len(bytes.fromhex(key)) != 1952:
        raise ValueError('invalid ML-DSA-65 public key length')
    validate_dsse_dict(result.get('envelope'))
    return cast(VkrBundleDict, result)


def narrow_audit_args(event: str, args: object) -> Sequence[object]:
    """Validate handled PEP 578 tuple shapes; O(A) time/space for A arguments."""
    if not isinstance(args, tuple):
        raise TypeError('audit arguments must be a tuple')
    if event in {'open', 'ctypes.dlopen', 'os.exec', 'os.system', 'subprocess.Popen'}:
        if not args:
            raise ValueError('missing audited target')
        target = args[0]
        if target is not None and not isinstance(target, (str, bytes, int, os.PathLike)):
            raise TypeError('invalid audited target type')
    if event == 'socket.connect' and (len(args) != 2 or not isinstance(args[1], (tuple, str, bytes))):
        raise ValueError('invalid socket audit address')
    return args
