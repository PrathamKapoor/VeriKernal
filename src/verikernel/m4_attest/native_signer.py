"""Native signer."""
from __future__ import annotations
import ctypes
import secrets
from functools import lru_cache
from verikernel.m5_ringbuf.native import library_path


@lru_cache(maxsize=1)
def _library() -> object:
    """library. Complexity: O(b + R) time and O(b) workspace for fixed ML-DSA-65 dimensions; R is signing rejection-loop work when applicable."""
    library = library_path()
    library.vk_mldsa_keygen.argtypes = [ctypes.c_void_p]*3
    library.vk_mldsa_keygen.restype = ctypes.c_int
    library.vk_mldsa_sign.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p, ctypes.c_void_p]
    library.vk_mldsa_sign.restype = ctypes.c_int
    library.vk_mldsa_verify.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p]
    library.vk_mldsa_verify.restype = ctypes.c_int
    return library


def verify_signature(public_key: object, message: object, signature: object) -> bool:
    """verify signature. Complexity: O(b + R) time and O(b) workspace for fixed ML-DSA-65 dimensions; R is signing rejection-loop work when applicable."""
    if len(public_key) != 1952 or len(signature) != 3309:
        return False
    return _library().vk_mldsa_verify(ctypes.create_string_buffer(public_key), ctypes.create_string_buffer(message), len(message), ctypes.create_string_buffer(signature)) == 1


class RustMLDSA65:
    """RustMLDSA65. Complexity: O(b + R) time and O(b) workspace for fixed ML-DSA-65 dimensions; R is signing rejection-loop work when applicable."""
    def __init__(self, seed: object) -> None:
        """init. Complexity: O(b + R) time and O(b) workspace for fixed ML-DSA-65 dimensions; R is signing rejection-loop work when applicable."""
        if len(seed) != 32:
            raise ValueError("ML-DSA seed must contain 32 bytes")
        self.library = _library()
        public, secret = ctypes.create_string_buffer(1952), ctypes.create_string_buffer(4032)
        if self.library.vk_mldsa_keygen(ctypes.create_string_buffer(seed), public, secret):
            raise ValueError("native ML-DSA key generation failed")
        self.public_key, self.secret_key = public.raw, secret.raw

    def sign(self, message: object, deterministic: bool=True) -> bytes:
        """Sign the benchmark message through the selected provider. Complexity: O(b + R) time and O(b) workspace for fixed ML-DSA-65 dimensions; R is signing rejection-loop work when applicable."""
        signature = ctypes.create_string_buffer(3309)
        randomizer = bytes(32) if deterministic else secrets.token_bytes(32)
        result = self.library.vk_mldsa_sign(ctypes.create_string_buffer(self.secret_key), ctypes.create_string_buffer(message), len(message), signature, ctypes.create_string_buffer(randomizer))
        if result:
            raise ValueError("native ML-DSA signing failed")
        return signature.raw

    def verify(self, public_key: object, message: object, signature: object) -> bool:
        """Validate the captured evidence and return the verification result. Complexity: O(b + R) time and O(b) workspace for fixed ML-DSA-65 dimensions; R is signing rejection-loop work when applicable."""
        return verify_signature(public_key, message, signature)
