"""Pqc signer."""
from __future__ import annotations
import secrets
import os
import importlib.util
from pathlib import Path
from dilithium_py.ml_dsa import ML_DSA_65

try:
    from pqcrypto.sign import ml_dsa_65 as native
    from pqcrypto import InvalidSignatureError
    NATIVE_ERRORS = (InvalidSignatureError,)
except ImportError:
    native = None
    NATIVE_ERRORS = ()

PUBLIC_KEY_BYTES = 1952
SECRET_KEY_BYTES = 4032
SIGNATURE_BYTES = 3309


def native_ring_provider(counts: dict[str, int]) -> object:
    """Clone the standard protocol with native polynomial operations; O(256) setup."""
    import copy
    from dilithium_py.polynomials.polynomials import Polynomial, PolynomialNTT
    from verikernel.rust_bridge import LatticeEngine
    engine = LatticeEngine()
    q, r = 8380417, 2**32 % 8380417
    r_inverse = pow(r, -1, q)
    class NativePolynomial(Polynomial):
        """Reference encoding with compiled arithmetic; O(256) storage."""
        def to_ntt(self) -> object:
            """Use the native forward transform; O(256 log 256) time/space."""
            counts['ntt'] += 1
            return self.parent([value % q for value in engine.ntt(self.coeffs)], is_ntt=True)

        def check_norm_bound(self, bound: int) -> bool:
            """Scan the complete polynomial natively; O(256) time and space."""
            counts['norm'] += 1
            centered = [(value+q//2) % q-q//2 for value in self.coeffs]
            return engine.check_norm(centered, bound)

    class NativePolynomialNTT(PolynomialNTT, NativePolynomial):
        """Native fixed-schedule transform representation; O(256) storage."""
        def from_ntt(self) -> object:
            """Remove the inverse Montgomery factor; O(256 log 256) time/space."""
            counts['inverse'] += 1
            return self.parent([value*r_inverse % q for value in engine.inverse(self.coeffs)])

        def ntt_coefficient_multiplication(self, left: list[int], right: list[int]) -> list[int]:
            """Restore the reference ring representation; O(256) time/space."""
            counts['pointwise'] += 1
            return [value*r % q for value in engine.pointwise(left, right)]

    provider = copy.copy(ML_DSA_65)
    provider.M = copy.copy(ML_DSA_65.M)
    provider.R = copy.copy(ML_DSA_65.R)
    provider.R.element, provider.R.element_ntt = NativePolynomial, NativePolynomialNTT
    provider.M.ring = provider.R
    return provider


def _verification_encoding(signature: bytes) -> tuple[bool,bytes]:
    """Validate and normalize public response/hint encoding; O(n) time and space.

    Repaired bytes are used only for backend work. Original noncanonical input
    is rejected regardless of the backend result. This is not a timing proof.
    """
    work = bytearray(signature)
    valid = True
    for index in range(1280):
        offset,shift = 48+index*20//8,index*20%8
        word = int.from_bytes(work[offset:offset+3],'little')
        encoded = (word>>shift)&0xfffff
        good = 196<encoded<1048380
        valid &= good
        if not good:
            word = (word&~(0xfffff<<shift))|(524288<<shift)
            work[offset:offset+3] = word.to_bytes(3,'little')
    def canonical_hints(data: bytearray) -> bool:
        """canonical hints. Complexity: O(b + R) time and O(b) workspace for fixed ML-DSA-65 dimensions; R is signing rejection-loop work when applicable."""
        previous = 0
        good = True
        for end in data[3303:3309]:
            good &= previous<=end<=55
            safe_end = min(55,max(previous,end))
            values = data[3248+previous:3248+safe_end]
            good &= all(values[i]<values[i+1] for i in range(len(values)-1))
            previous = safe_end
        good &= not any(data[3248+previous:3303])
        return bool(good)
    hints_ok = canonical_hints(work)
    valid &= hints_ok
    repaired = bytearray(work)
    used = max([0]+[i+1 for i,value in enumerate(work[3248:3303]) if value])
    repaired[-1] = max(min(work[-2],55),used)
    repair_ok = canonical_hints(repaired)
    repair_mask = 255*int(repair_ok)
    original_mask = 255*int(hints_ok)
    for index in range(3248,3309):
        repaired[index] &= repair_mask
        work[index] = (work[index]&original_mask)|(repaired[index]&(255^original_mask))
    return bool(valid),bytes(work)


class MLDSA65Signer:
    """MLDSA65Signer. Complexity: O(b + R) time and O(b) workspace for fixed ML-DSA-65 dimensions; R is signing rejection-loop work when applicable."""
    backend = "dilithium-py-fips204"

    def __init__(self, seed: object=None, arithmetic_backend: str = 'default') -> None:
        """init. Complexity: O(b + R) time and O(b) workspace for fixed ML-DSA-65 dimensions; R is signing rejection-loop work when applicable."""
        seed = secrets.token_bytes(32) if seed is None else seed
        if len(seed) != 32:
            raise ValueError("signing seed must contain 32 bytes")
        if arithmetic_backend not in {'default', 'native-ring'}:
            raise ValueError('unknown arithmetic provider')
        self.arithmetic_counts = dict(ntt=0, inverse=0, pointwise=0, norm=0)
        self._ring_provider = native_ring_provider(self.arithmetic_counts) if arithmetic_backend == 'native-ring' else None
        self._rust = None
        self._oqs = None
        if self._ring_provider is not None:
            self.public_key, self.secret_key = self._ring_provider.key_derive(seed)
            self.backend = 'fips204-native-ring-reference-protocol'
            return
        try:
            from .native_signer import RustMLDSA65
            self._rust = RustMLDSA65(seed)
        except (OSError, AttributeError):
            self._rust = None
        if self._rust:
            self.public_key, self.secret_key = self._rust.public_key, self._rust.secret_key
            self.backend = "fips204-rust-native"
        else:
            self.public_key, self.secret_key = ML_DSA_65.key_derive(seed)
        if importlib.util.find_spec("oqs") is not None:
            os.environ.setdefault("OQS_INSTALL_PATH", str(Path(__file__).resolve().parents[3] / "dist" / "oqs"))
            import oqs
            self._oqs = oqs
            self.backend = "oqs-ML-DSA-65"

    def sign(self, message: object, deterministic: bool=True) -> bytes:
        """Sign the benchmark message through the selected provider. Complexity: O(b + R) time and O(b) workspace for fixed ML-DSA-65 dimensions; R is signing rejection-loop work when applicable."""
        if self._ring_provider is not None:
            return self._ring_provider.sign(self.secret_key, message, deterministic=deterministic)
        if self._oqs is not None and not deterministic:
            with self._oqs.Signature("ML-DSA-65", secret_key=self.secret_key) as signer:
                return signer.sign(message)
        if self._rust:
            return self._rust.sign(message, deterministic)
        if not deterministic and native is not None:
            return native.sign(self.secret_key, message)
        return ML_DSA_65.sign(self.secret_key, message, deterministic=True)

    @staticmethod
    def verify(public_key: object, message: object, signature: object) -> bool:
        """Validate the captured evidence and return the verification result. Complexity: O(b + R) time and O(b) workspace for fixed ML-DSA-65 dimensions; R is signing rejection-loop work when applicable."""
        if len(public_key) != PUBLIC_KEY_BYTES or len(signature) != SIGNATURE_BYTES:
            return False
        encoding_ok,work = _verification_encoding(signature)
        try:
            from .native_signer import verify_signature
            accepted = verify_signature(public_key, message, work)
        except (OSError, AttributeError):
            accepted = _portable_verify(public_key, message, work)
        return bool(encoding_ok & accepted)


def _portable_verify(public_key: object, message: object, signature: object) -> object:
        """portable verify. Complexity: O(b + R) time and O(b) workspace for fixed ML-DSA-65 dimensions; R is signing rejection-loop work when applicable."""
        try:
            if native is not None:
                result = native.verify(public_key, message, signature)
                return result is None or bool(result)
            return bool(ML_DSA_65.verify(public_key, message, signature))
        except (ValueError, IndexError, AssertionError, OverflowError) + NATIVE_ERRORS:
            return False
