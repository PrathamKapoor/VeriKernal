//! Public native interfaces for telemetry, cryptography and deterministic replay.
pub mod lattice_ct;
pub mod pe_iat_patcher;
pub use lattice_ct::*;
pub mod batch;
pub mod ringbuf;
pub use batch::*;
pub mod fault_engine;
pub mod merkle;
pub mod ratchet;
pub mod sandbox;
pub mod signatures;
/// Compare exactly 32 readable bytes; null pointers are rejected before reads.
/// Complexity: O(1) time and O(1) space; callers own pointer validity.
#[no_mangle]
#[inline(never)]
pub extern "C" fn vk_constant_time_compare_32(a: *const u8, b: *const u8) -> u32 {
    if a.is_null() || b.is_null() {
        return 0;
    }
    let mut acc: u8 = 0;
    macro_rules! compare_bytes {
        ($($i:expr),*) => {$(
            acc |= unsafe { core::ptr::read_volatile(a.add($i)) }
                ^ unsafe { core::ptr::read_volatile(b.add($i)) };
        )*};
    }
    compare_bytes!(
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
        25, 26, 27, 28, 29, 30, 31
    );
    ((acc as u32).wrapping_sub(1) >> 31) & 1
}
#[no_mangle]
/// Return the supported native ABI version. Complexity: O(1) time and space.
pub extern "C" fn vk_abi_version() -> u32 {
    200
}
#[no_mangle]
/// Return the aligned telemetry record size. Complexity: O(1) time and space.
pub extern "C" fn vk_event_struct_size() -> usize {
    core::mem::size_of::<verikernel_schema::KernelTelemetryEvent>()
}
#[no_mangle]
/// Return the telemetry wire size for older callers. Complexity: O(1) time and space.
pub extern "C" fn vk_event_size() -> usize {
    vk_event_struct_size()
}
#[no_mangle]
/// Expose the deterministic mixer through the C interface. Complexity: O(1) time and space.
pub extern "C" fn vk_splitmix64(value: u64) -> u64 {
    fault_engine::splitmix64(value)
}
#[no_mangle]
/// Hash a validated byte range with 64-bit FNV-1a. Complexity: O(n + W) time and O(n + M) space, including called operations W and retained state M.
pub extern "C" fn vk_fnv1a_hash(ptr: *const u8, len: usize) -> u64 {
    if ptr.is_null() || len > isize::MAX as usize {
        return 0;
    }
    let mut result = 0xcbf29ce484222325u64;
    for byte in unsafe { std::slice::from_raw_parts(ptr, len) } {
        result = (result ^ (*byte as u64)).wrapping_mul(0x100000001b3);
    }
    result
}
#[no_mangle]
/// Preserve the FNV-1a entry point used by existing callers. Complexity: O(n + W) time and O(n + M) space, including called operations W and retained state M.
pub extern "C" fn vk_fnv1a_64(ptr: *const u8, len: usize) -> u64 {
    vk_fnv1a_hash(ptr, len)
}
#[no_mangle]
/// Bind the stack, syscall, ordinal and seed into a replay key. Complexity: O(1) time and space.
pub extern "C" fn vk_compute_site_key(stack: u64, op: u32, ordinal: u64, seed: u64) -> u64 {
    vk_splitmix64(stack ^ ((op as u64) << 32) ^ ordinal ^ seed)
}
#[no_mangle]
/// Derive one BLAKE3 ratchet state transition. Complexity: O(1) time and space.
pub extern "C" fn vk_ratchet_step(key: *const u8, tag: *const u8, out: *mut u8) -> i32 {
    if key.is_null() || tag.is_null() || out.is_null() {
        return -1;
    }
    let result = unsafe {
        ratchet::hash(&[
            b"VK-RATCHET-STEP-V1",
            std::slice::from_raw_parts(key, 32),
            std::slice::from_raw_parts(tag, 32),
        ])
    };
    unsafe {
        std::ptr::copy_nonoverlapping(result.as_ptr(), out, 32);
    }
    0
}
#[no_mangle]
/// Compute the Merkle root of contiguous fixed-width leaves. Complexity: O(n + W) time and O(n + M) space, including called operations W and retained state M.
pub extern "C" fn vk_merkle_root_256(data: *const u8, count: usize, out: *mut u8) -> i32 {
    if out.is_null() || count > isize::MAX as usize / 256 || (count > 0 && data.is_null()) {
        return -1;
    }
    let leaves = if count == 0 {
        vec![]
    } else {
        unsafe { std::slice::from_raw_parts(data, count * 256) }
            .chunks_exact(256)
            .map(|s| s.to_vec())
            .collect()
    };
    let result = merkle::root(&leaves);
    unsafe {
        std::ptr::copy_nonoverlapping(result.as_ptr(), out, 32);
    }
    0
}
#[cfg(test)]
mod ffi_tests {
    use super::*;
    #[test]
    /// Check public boundary vectors against the expected result. Complexity: O(n + W) time and O(n + M) space, including called operations W and retained state M.
    fn public_boundary_vectors() -> () {
        assert_eq!(vk_event_size(), 128);
        assert_eq!(vk_splitmix64(0), 0xe220a8397b1dcdaf);
        assert_eq!(vk_fnv1a_hash(b"hello".as_ptr(), 5), 0xa430d84680aabd0b);
        assert_eq!(vk_fnv1a_hash(std::ptr::null(), 0), 0);
        assert_eq!(
            vk_ratchet_step(std::ptr::null(), std::ptr::null(), std::ptr::null_mut()),
            -1
        );
    }
}
#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(target_os = "linux")]
pub mod probes;
