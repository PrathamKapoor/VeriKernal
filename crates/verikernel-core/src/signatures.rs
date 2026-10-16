//! ML-DSA-65 key generation, signing and verification through the native provider.
use fips204::{
    ml_dsa_65,
    traits::{KeyGen, SerDes, Signer, Verifier},
};

#[no_mangle]
/// Generate an ML-DSA-65 key pair into caller-owned buffers. Complexity: O(n + W) time and O(n + M) space, including called operations W and retained state M.
pub unsafe extern "C" fn vk_mldsa_keygen(seed: *const u8, public: *mut u8, secret: *mut u8) -> i32 {
    if seed.is_null() || public.is_null() || secret.is_null() {
        return -1;
    }
    let mut xi = [0u8; 32];
    std::ptr::copy_nonoverlapping(seed, xi.as_mut_ptr(), 32);
    let (pk, sk) = ml_dsa_65::KG::keygen_from_seed(&xi);
    std::ptr::copy_nonoverlapping(pk.into_bytes().as_ptr(), public, 1952);
    std::ptr::copy_nonoverlapping(sk.into_bytes().as_ptr(), secret, 4032);
    0
}
#[no_mangle]
/// Sign the caller-provided message using the native ML-DSA provider. Complexity: O(n + W) time and O(n + M) space, including called operations W and retained state M.
pub unsafe extern "C" fn vk_mldsa_sign(
    secret: *const u8,
    message: *const u8,
    length: usize,
    signature: *mut u8,
    randomizer: *const u8,
) -> i32 {
    if secret.is_null()
        || message.is_null()
        || signature.is_null()
        || randomizer.is_null()
        || length > 16_777_216
    {
        return -1;
    }
    let mut bytes = [0u8; 4032];
    std::ptr::copy_nonoverlapping(secret, bytes.as_mut_ptr(), 4032);
    let key = match ml_dsa_65::PrivateKey::try_from_bytes(bytes) {
        Ok(key) => key,
        Err(_) => return -2,
    };
    let mut rnd = [0u8; 32];
    std::ptr::copy_nonoverlapping(randomizer, rnd.as_mut_ptr(), 32);
    match key.try_sign_with_seed(&rnd, std::slice::from_raw_parts(message, length), &[]) {
        Ok(sig) => {
            std::ptr::copy_nonoverlapping(sig.as_ptr(), signature, 3309);
            0
        }
        Err(_) => -3,
    }
}
#[no_mangle]
/// Verify an ML-DSA-65 signature using the native provider. Complexity: O(n + W) time and O(n + M) space, including called operations W and retained state M.
pub unsafe extern "C" fn vk_mldsa_verify(
    public: *const u8,
    message: *const u8,
    length: usize,
    signature: *const u8,
) -> i32 {
    if public.is_null() || message.is_null() || signature.is_null() || length > 16_777_216 {
        return -1;
    }
    let mut pk = [0u8; 1952];
    let mut sig = [0u8; 3309];
    std::ptr::copy_nonoverlapping(public, pk.as_mut_ptr(), 1952);
    std::ptr::copy_nonoverlapping(signature, sig.as_mut_ptr(), 3309);
    match ml_dsa_65::PublicKey::try_from_bytes(pk) {
        Ok(key) => i32::from(key.verify(std::slice::from_raw_parts(message, length), &sig, &[])),
        Err(_) => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    /// Check standard sizes and corruption against the expected result. Complexity: O(n + W) time and O(n + M) space, including called operations W and retained state M.
    fn standard_sizes_and_corruption() -> () {
        let (pk, sk) = ml_dsa_65::KG::keygen_from_seed(&[0u8; 32]);
        let sig = sk.try_sign_with_seed(&[0u8; 32], b"receipt", &[]).unwrap();
        assert!(pk.verify(b"receipt", &sig, &[]));
        assert!(!pk.verify(b"changed", &sig, &[]));
        assert_eq!(pk.into_bytes().len(), 1952);
        assert_eq!(sk.into_bytes().len(), 4032);
        assert_eq!(sig.len(), 3309);
    }
}
