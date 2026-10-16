"""Rust bridge."""
from __future__ import annotations
import ctypes
import time
import hashlib
import hmac
import struct
from collections import OrderedDict
from verikernel.m4_attest.ratchet import digest
from verikernel.m4_attest.merkle_tiles import mth
from verikernel.m5_ringbuf.native import library_path

MASK = (1 << 64)-1


class LatticeEngine:
    """Fixed 256-coefficient native ring operations; O(256) marshaling space."""
    def __init__(self) -> None:
        """Bind exact C signatures; O(1) time and space."""
        self.library = library_path()
        pointer = ctypes.POINTER(ctypes.c_int32)
        for name, arguments, result in [
            ('vk_montgomery_reduce_ct', [ctypes.c_int64], ctypes.c_int32),
            ('vk_caddq_ct', [ctypes.c_int32], ctypes.c_int32),
            ('vk_ntt_256_ct', [pointer], ctypes.c_int32),
            ('vk_inv_ntt_256_ct', [pointer], ctypes.c_int32),
            ('vk_poly_chknorm_ct', [pointer, ctypes.c_int32], ctypes.c_uint32),
            ('vk_poly_pointwise_montgomery_ct', [pointer, pointer, pointer], ctypes.c_int32)]:
            function = getattr(self.library, name)
            function.argtypes, function.restype = arguments, result

    def _array(self, coefficients: list[int]) -> ctypes.Array:
        """Validate a fixed signed array; O(256) time and space."""
        if len(coefficients) != 256 or any(type(value) is not int or not -(1 << 31) <= value < 1 << 31 for value in coefficients):
            raise ValueError('expected 256 signed 32-bit coefficients')
        return (ctypes.c_int32*256)(*coefficients)

    def montgomery(self, value: int) -> int:
        """Reduce a FIPS-bounded product; O(1) time and space."""
        if not -(8380417 << 31) <= value <= 8380417 << 31:
            raise ValueError('Montgomery product outside specified input range')
        return self.library.vk_montgomery_reduce_ct(value)

    def caddq(self, value: int) -> int:
        """Canonicalize one coefficient in [-Q,Q); O(1) time and space."""
        if not -8380417 <= value < 8380417:
            raise ValueError('conditional addition input outside [-Q,Q)')
        return self.library.vk_caddq_ct(value)

    def ntt(self, coefficients: list[int]) -> list[int]:
        """Forward transform, standard input residues; O(256 log 256) time/space."""
        data = self._array([value % 8380417 for value in coefficients])
        if self.library.vk_ntt_256_ct(data):
            raise ValueError('native forward transform rejected input')
        return list(data)

    def inverse(self, coefficients: list[int]) -> list[int]:
        """Reference inverse with Montgomery factor R; O(256 log 256) time/space."""
        data = self._array([value % 8380417 for value in coefficients])
        if self.library.vk_inv_ntt_256_ct(data):
            raise ValueError('native inverse transform rejected input')
        return list(data)

    def pointwise(self, left: list[int], right: list[int]) -> list[int]:
        """Multiply NTT coordinates with R^-1 factor; O(256) time and space."""
        a, b, out = self._array(left), self._array(right), (ctypes.c_int32*256)()
        if self.library.vk_poly_pointwise_montgomery_ct(out, a, b):
            raise ValueError('native pointwise multiplication rejected input')
        return list(out)

    def check_norm(self, coefficients: list[int], bound: int) -> bool:
        """Reject a centered polynomial outside its strict bound; O(256) time/space."""
        if any(abs(value) > 8380417//2 for value in coefficients):
            raise ValueError('norm inputs must be centered coefficients')
        return bool(self.library.vk_poly_chknorm_ct(self._array(coefficients), bound))

    def multiply(self, left: list[int], right: list[int]) -> list[int]:
        """Negacyclic product in standard residues; O(256 log 256) time/space."""
        return [value % 8380417 for value in self.inverse(self.pointwise(self.ntt(left), self.ntt(right)))]


def constant_time_compare_32(a: bytes, b: bytes) -> bool:
    """Compare fixed buffers through the native ABI; O(1) time and space."""
    if len(a) != 32 or len(b) != 32:
        raise ValueError('comparison requires two 32-byte buffers')
    try:
        function = library_path().vk_constant_time_compare_32
    except (OSError, AttributeError):
        return hmac.compare_digest(a, b)
    function.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
    function.restype = ctypes.c_uint32
    return function(ctypes.create_string_buffer(a), ctypes.create_string_buffer(b)) == 1


def python_splitmix64(value: object) -> object:
    """python splitmix64. Complexity: O(1) time and O(1) space for bounded machine-word inputs."""
    value = (value + 0x9e3779b97f4a7c15) & MASK
    value = ((value ^ (value >> 30))*0xbf58476d1ce4e5b9) & MASK
    value = ((value ^ (value >> 27))*0x94d049bb133111eb) & MASK
    return value ^ (value >> 31)


def python_fnv1a_hash(data: object) -> object:
    """Compute the portable 64-bit FNV-1a reference hash. Complexity: O(n + W) time and O(n + M) space; n is traversed data, W delegated work, M retained delegated state."""
    value = 0xcbf29ce484222325
    for byte in data:
        value = ((value ^ byte)*0x100000001b3) & MASK
    return value


def python_compute_site_key(stack_hash: object, syscall_nr: int, ordinal: int, seed: object) -> object:
    """Mix a stack, operation, ordinal and seed into a replay site key. Complexity: O(n + W) time and O(n + M) space; n is traversed data, W delegated work, M retained delegated state."""
    return python_splitmix64((stack_hash ^ ((syscall_nr & 0xffffffff) << 32) ^ ordinal ^ seed) & MASK)


class RustBridge:
    """RustBridge. Complexity: O(n + W) time and O(n + M) space; n is traversed data, W delegated work, M retained delegated state."""
    def __init__(self, native: bool=True) -> None:
        """Initialize the owned state and validate configuration limits. Complexity: O(n + W) time and O(n + M) space; n is traversed data, W delegated work, M retained delegated state."""
        self.library = None
        if native:
            try:
                library = library_path()
                library.vk_abi_version.restype = ctypes.c_uint32
                if library.vk_abi_version() != 200:
                    raise OSError('unsupported native ABI')
                signatures = {'vk_event_struct_size': ([], ctypes.c_size_t), 'vk_splitmix64': ([ctypes.c_uint64], ctypes.c_uint64), 'vk_fnv1a_hash': ([ctypes.c_void_p, ctypes.c_size_t], ctypes.c_uint64), 'vk_compute_site_key': ([ctypes.c_uint64, ctypes.c_uint32, ctypes.c_uint64, ctypes.c_uint64], ctypes.c_uint64), 'vk_ratchet_step': ([ctypes.c_void_p]*3, ctypes.c_int), 'vk_merkle_root_256': ([ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p], ctypes.c_int)}
                for name, (args, result) in signatures.items():
                    function = getattr(library, name)
                    function.argtypes, function.restype = args, result
                if library.vk_event_struct_size() != 128:
                    raise OSError('native wire size mismatch')
                self.library = library
            except (OSError, AttributeError):
                self.library = None

    def splitmix64(self, value: object) -> object:
        """splitmix64. Complexity: O(1) time and O(1) space for bounded machine-word inputs."""
        return self.library.vk_splitmix64(value & MASK) if self.library else python_splitmix64(value & MASK)

    def fnv1a_hash(self, data: object) -> object:
        """Hash bytes through the selected native or portable backend. Complexity: O(n + W) time and O(n + M) space; n is traversed data, W delegated work, M retained delegated state."""
        data = bytes(data)
        return self.library.vk_fnv1a_hash(ctypes.create_string_buffer(data), len(data)) if self.library else python_fnv1a_hash(data)

    def compute_site_key(self, stack: object, op: object, ordinal: int, seed: object) -> object:
        """Compute a deterministic fault site key through the selected backend. Complexity: O(n + W) time and O(n + M) space; n is traversed data, W delegated work, M retained delegated state."""
        return self.library.vk_compute_site_key(stack & MASK, op & 0xffffffff, ordinal & MASK, seed & MASK) if self.library else python_compute_site_key(stack, op, ordinal, seed)

    def ratchet_step(self, key: object, tag: object) -> bytes:
        """Derive the next event key from the current key and tag. Complexity: O(n + W) time and O(n + M) space; n is traversed data, W delegated work, M retained delegated state."""
        if len(key) != 32 or len(tag) != 32:
            raise ValueError('key and tag require 32 bytes')
        if not self.library:
            return digest(b'VK-RATCHET-STEP-V1'+key+tag)
        out = ctypes.create_string_buffer(32)
        if self.library.vk_ratchet_step(ctypes.create_string_buffer(key), ctypes.create_string_buffer(tag), out):
            raise ValueError('native ratchet rejected input')
        return out.raw

    def merkle_root_256(self, leaves: object) -> object:
        """Compute the native Merkle root for fixed-width leaves. Complexity: O(n + W) time and O(n + M) space; n is traversed data, W delegated work, M retained delegated state."""
        leaves = list(leaves)
        if any(len(leaf) != 256 for leaf in leaves):
            raise ValueError('leaves require 256 bytes')
        if not self.library:
            return mth(leaves)
        out = ctypes.create_string_buffer(32)
        if self.library.vk_merkle_root_256(ctypes.create_string_buffer(b''.join(leaves)), len(leaves), out):
            raise ValueError('native Merkle rejected input')
        return out.raw


_bridge = RustBridge()


def is_native_rust_loaded() -> bool:
    """is native rust loaded. Complexity: O(1) time and O(1) space for bounded machine-word inputs."""
    return _bridge.library is not None


def abi_version() -> object:
    """abi version. Complexity: O(1) time and O(1) space for bounded machine-word inputs."""
    return _bridge.library.vk_abi_version() if _bridge.library else 200


def event_size() -> object:
    """event size. Complexity: O(1) time and O(1) space for bounded machine-word inputs."""
    return _bridge.library.vk_event_struct_size() if _bridge.library else 128


rust_splitmix64 = _bridge.splitmix64
rust_fnv1a_hash = _bridge.fnv1a_hash
rust_compute_site_key = _bridge.compute_site_key


def benchmark_bridge(count: int=20000) -> object:
    """Measure scalar native calls against the Python reference. Complexity: O(n + W) time and O(n + M) space; n is traversed data, W delegated work, M retained delegated state."""
    data = bytes(range(256))*4
    results = {}
    for name, function in [('python', python_fnv1a_hash), ('native', rust_fnv1a_hash)]:
        start = time.perf_counter()
        checksum = 0
        for index in range(count):
            checksum ^= function(data)
        results[name] = {'seconds': time.perf_counter()-start, 'calls': count, 'checksum': checksum}
    return {'native_loaded': is_native_rust_loaded(), 'fnv1a_1024': results, 'speedup': results['python']['seconds']/results['native']['seconds']}


class BatchEngine:
    """SHA-256 event profile; O(n) work and O(capacity + log n) native workspace."""

    def __init__(self, native: bool = True) -> None:
        """Initialize the owned state and validate configuration limits. Complexity: O(n + W) time and O(n + M) space; n is traversed data, W delegated work, M retained delegated state."""
        self.library = _bridge.library if native else None
        if self.library and not all(hasattr(self.library,name) for name in ['vk_sha256','vk_ratchet_seal_batch','vk_ratchet_verify_batch','vk_merkle_root_rfc9162','vk_dedup_filter_batch']):
            self.library = None
        if self.library:
            for name,args,result in [
                ('vk_sha256',[ctypes.c_void_p,ctypes.c_size_t,ctypes.c_void_p],ctypes.c_int),
                ('vk_ratchet_seal_batch',[ctypes.c_void_p,ctypes.c_size_t]+[ctypes.c_void_p]*3,ctypes.c_int),
                ('vk_ratchet_verify_batch',[ctypes.c_void_p,ctypes.c_size_t]+[ctypes.c_void_p]*4,ctypes.c_int),
                ('vk_merkle_root_rfc9162',[ctypes.c_void_p,ctypes.c_size_t,ctypes.c_void_p],ctypes.c_int),
                ('vk_dedup_filter_batch',[ctypes.c_void_p,ctypes.c_size_t,ctypes.c_size_t,ctypes.c_void_p],ctypes.c_size_t)]:
                function = getattr(self.library,name)
                function.argtypes,function.restype = args,result
        self.native = self.library is not None

    @staticmethod
    def _view(buffer: bytearray, events: bool = True) -> ctypes.Array:
        """Expose a writable buffer to ctypes without copying its contents. Complexity: O(n + W) time and O(n + M) space; n is traversed data, W delegated work, M retained delegated state."""
        if not isinstance(buffer,bytearray) or events and len(buffer)%128:
            raise ValueError('a mutable whole-event bytearray is required')
        return (ctypes.c_uint8*len(buffer)).from_buffer(buffer)

    @staticmethod
    def _key(value: bytes) -> ctypes.Array:
        """Validate and expose a fixed-width key to the native interface. Complexity: O(n + W) time and O(n + M) space; n is traversed data, W delegated work, M retained delegated state."""
        if len(value)!=32:
            raise ValueError('key or commitment requires 32 bytes')
        return ctypes.create_string_buffer(value,32)

    def sha256(self, buffer: bytearray) -> bytes:
        """Hash bytes in O(n) time, O(1) native space without input copying."""
        view = self._view(buffer,False)
        if not self.library:
            return hashlib.sha256(buffer).digest()
        out = ctypes.create_string_buffer(32)
        if self.library.vk_sha256(view,len(buffer),out):
            raise ValueError('native SHA-256 rejected input')
        return out.raw

    def seal(self, buffer: bytearray, seed: bytes) -> tuple[bytes,bytes]:
        """Write tags in place in O(n) time and O(1) native space."""
        view,key = self._view(buffer),self._key(seed)
        c0,kn = ctypes.create_string_buffer(32),ctypes.create_string_buffer(32)
        if self.library:
            if self.library.vk_ratchet_seal_batch(view,len(buffer)//128,key,c0,kn):
                raise ValueError('native sealing rejected input')
            return c0.raw,kn.raw
        state = bytearray(seed)
        commitment = hashlib.sha256(b'VK-RATCHET-COMMIT-V1'+state).digest()
        for offset in range(0,len(buffer),128):
            tag = hashlib.sha256(b'VK-RATCHET-TAG-V1'+state+buffer[offset:offset+96]).digest()
            next_key = hashlib.sha256(b'VK-RATCHET-STEP-V1'+state+tag).digest()
            state[:] = bytes(32)
            state[:] = next_key
            buffer[offset+96:offset+128] = tag
        terminal = bytes(state)
        state[:] = bytes(32)
        return commitment,terminal

    def verify(self, buffer: bytearray, seed: bytes, commitment: bytes, terminal: bytes) -> tuple[int,int]:
        """Verify all records in O(n) time and O(1) native workspace."""
        view,key,c0,kn = self._view(buffer),self._key(seed),self._key(commitment),self._key(terminal)
        if self.library:
            failed = ctypes.c_int64(-1)
            status = self.library.vk_ratchet_verify_batch(view,len(buffer)//128,key,c0,kn,ctypes.byref(failed))
            return status,failed.value
        state,first = seed,-1
        initial_ok = hmac.compare_digest(hashlib.sha256(b'VK-RATCHET-COMMIT-V1'+seed).digest(),commitment)
        for index,offset in enumerate(range(0,len(buffer),128)):
            tag = hashlib.sha256(b'VK-RATCHET-TAG-V1'+state+buffer[offset:offset+96]).digest()
            valid = hmac.compare_digest(tag,buffer[offset+96:offset+128])
            sequence_ok = struct.unpack_from('<Q',buffer,offset)[0]==index
            if not (valid and sequence_ok) and first<0:
                first = index
            state = hashlib.sha256(b'VK-RATCHET-STEP-V1'+state+tag).digest()
        final_ok = hmac.compare_digest(state,terminal)
        if not initial_ok:
            return -1,-1
        if first>=0:
            return -1,first
        return (0,-1) if final_ok else (-2,len(buffer)//128)

    def root(self, buffer: bytearray) -> bytes:
        """Compute RFC 9162 SHA-256 MTH in O(n) time, O(log n) native stack."""
        view = self._view(buffer)
        if self.library:
            out = ctypes.create_string_buffer(32)
            if self.library.vk_merkle_root_rfc9162(view,len(buffer)//128,out):
                raise ValueError('native Merkle rejected input')
            return out.raw
        def walk(start: int, count: int) -> bytes:
            """Traverse the current subtree and accumulate its result. Complexity: O(n + W) time and O(n + M) space; n is traversed data, W delegated work, M retained delegated state."""
            if count==0:
                return hashlib.sha256(b'').digest()
            if count==1:
                return hashlib.sha256(b'\0'+buffer[start:start+128]).digest()
            split = 1<<((count-1).bit_length()-1)
            return hashlib.sha256(b'\1'+walk(start,split)+walk(start+split*128,count-split)).digest()
        return walk(0,len(buffer)//128)

    def dedup(self, buffer: bytearray, capacity: int = 16384) -> bytearray:
        """Return a batch-local keep mask; expected O(n) time and O(capacity) space."""
        view = self._view(buffer)
        if capacity<0:
            raise ValueError('negative cache capacity')
        count = len(buffer)//128
        mask = bytearray(count)
        if self.library:
            self.library.vk_dedup_filter_batch(view,count,capacity,self._view(mask,False))
            return mask
        cache: OrderedDict = OrderedDict()
        for i in range(count):
            key = (struct.unpack_from('<I',buffer,i*128+24)[0],*struct.unpack_from('<QQQ',buffer,i*128+32))
            seen = key in cache
            if seen:
                cache.move_to_end(key)
            elif capacity:
                cache[key] = True
                if len(cache)>capacity:
                    cache.popitem(last=False)
            mask[i] = int(not seen)
        return mask
