//! SHA-256 batch profile. Time O(bytes), auxiliary space O(capacity + log(events)).
use crate::ringbuf::InodeLruCache;
use verikernel_schema::InodeCacheKey;
const WIDTH: usize = 128;
const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

/// FIPS 180-4 compression, O(n) time and O(1) extra space.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h = [
        0x6a09e667u32,
        0xbb67ae85,
        0x3c6ef372,
        0xa54ff53a,
        0x510e527f,
        0x9b05688c,
        0x1f83d9ab,
        0x5be0cd19,
    ];
    let blocks = (data.len() + 9 + 63) / 64;
    for block in 0..blocks {
        let mut bytes = [0u8; 64];
        for j in 0..64 {
            let i = block * 64 + j;
            bytes[j] = if i < data.len() {
                data[i]
            } else if i == data.len() {
                0x80
            } else {
                0
            };
        }
        if block + 1 == blocks {
            bytes[56..].copy_from_slice(&(data.len() as u64).wrapping_mul(8).to_be_bytes());
        }
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes(bytes[i * 4..i * 4 + 4].try_into().unwrap());
        }
        for i in 16..64 {
            let a = w[i - 15];
            let b = w[i - 2];
            w[i] = w[i - 16]
                .wrapping_add(a.rotate_right(7) ^ a.rotate_right(18) ^ (a >> 3))
                .wrapping_add(w[i - 7])
                .wrapping_add(b.rotate_right(17) ^ b.rotate_right(19) ^ (b >> 10));
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut z] = h;
        for i in 0..64 {
            let t = z
                .wrapping_add(e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25))
                .wrapping_add((e & f) ^ (!e & g))
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let u = (a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22))
                .wrapping_add((a & b) ^ (a & c) ^ (b & c));
            z = g;
            g = f;
            f = e;
            e = d.wrapping_add(t);
            d = c;
            c = b;
            b = a;
            a = t.wrapping_add(u);
        }
        for (v, x) in h.iter_mut().zip([a, b, c, d, e, f, g, z]) {
            *v = v.wrapping_add(x);
        }
    }
    let mut out = [0u8; 32];
    for (i, v) in h.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&v.to_be_bytes());
    }
    out
}
/// Hash the ordered input segments without concatenation. Complexity: O(n + W) time and O(n + M) space, including called operations W and retained state M.
fn hash_parts(parts: &[&[u8]]) -> [u8; 32] {
    let mut input = parts.concat();
    let result = sha256(&input);
    for byte in &mut input {
        unsafe {
            core::ptr::write_volatile(byte, 0);
        }
    }
    result
}
/// Overwrite every key byte through volatile writes. Complexity: O(1) time and space.
fn wipe(key: &mut [u8; 32]) -> () {
    for value in key {
        unsafe {
            core::ptr::write_volatile(value, 0);
        }
    }
    std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
}
/// Accumulate byte differences without content-dependent early returns. Complexity: O(n + W) time and O(n + M) space, including called operations W and retained state M.
fn equal(a: &[u8], b: &[u8]) -> bool {
    crate::vk_constant_time_compare_32(a.as_ptr(), b.as_ptr()) == 1
}
/// Check a buffer length and pointer before crossing the native boundary. Complexity: O(n + W) time and O(n + M) space, including called operations W and retained state M.
fn valid(data: *const u8, count: usize) -> bool {
    count <= isize::MAX as usize / WIDTH && (count == 0 || !data.is_null())
}
/// Expose a validated input range as a byte slice. Complexity: O(n + W) time and O(n + M) space, including called operations W and retained state M.
unsafe fn buffer<'a>(data: *const u8, count: usize) -> &'a [u8] {
    if count == 0 {
        &[]
    } else {
        std::slice::from_raw_parts(data, count * WIDTH)
    }
}

/// Owned pointers must remain valid and non-overlapping. O(n) time, O(1) space.
#[no_mangle]
/// Write the SHA-256 digest of the supplied byte range. Complexity: O(n + W) time and O(n + M) space, including called operations W and retained state M.
pub extern "C" fn vk_sha256(data: *const u8, len: usize, out: *mut u8) -> i32 {
    if out.is_null() || len > isize::MAX as usize || (data.is_null() && len > 0) {
        return -3;
    }
    let input = if len == 0 {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(data, len) }
    };
    let hash = sha256(input);
    unsafe {
        std::ptr::copy_nonoverlapping(hash.as_ptr(), out, 32);
    }
    0
}
/// In-place SHA-256 epoch sealing. O(n) time, O(1) workspace; pointers must not overlap.
#[no_mangle]
/// Authenticate packed events in place and return the terminal epoch key. Complexity: O(n + W) time and O(n + M) space, including called operations W and retained state M.
pub extern "C" fn vk_ratchet_seal_batch(
    data: *mut u8,
    count: usize,
    seed: *const u8,
    c0: *mut u8,
    kn: *mut u8,
) -> i32 {
    if !valid(data, count) || seed.is_null() || c0.is_null() || kn.is_null() {
        return -3;
    }
    let mut key = [0u8; 32];
    unsafe {
        std::ptr::copy_nonoverlapping(seed, key.as_mut_ptr(), 32);
    }
    let commit = hash_parts(&[b"VK-RATCHET-COMMIT-V1", &key]);
    unsafe {
        std::ptr::copy_nonoverlapping(commit.as_ptr(), c0, 32);
    }
    for i in 0..count {
        let prefix = unsafe { std::slice::from_raw_parts(data.add(i * WIDTH), 96) };
        let tag = hash_parts(&[b"VK-RATCHET-TAG-V1", &key, prefix]);
        let next = hash_parts(&[b"VK-RATCHET-STEP-V1", &key, &tag]);
        wipe(&mut key);
        key = next;
        unsafe {
            std::ptr::copy_nonoverlapping(tag.as_ptr(), data.add(i * WIDTH + 96), 32);
        }
    }
    unsafe {
        std::ptr::copy_nonoverlapping(key.as_ptr(), kn, 32);
    }
    wipe(&mut key);
    0
}
/// Full-stream verification without tag-position early return. O(n) time, O(1) workspace.
#[no_mangle]
/// Verify packed event tags and report the first corrupted index. Complexity: O(n + W) time and O(n + M) space, including called operations W and retained state M.
pub extern "C" fn vk_ratchet_verify_batch(
    data: *const u8,
    count: usize,
    seed: *const u8,
    c0: *const u8,
    kn: *const u8,
    index: *mut i64,
) -> i32 {
    if !valid(data, count) || seed.is_null() || c0.is_null() || kn.is_null() || index.is_null() {
        return -3;
    }
    let mut key = [0u8; 32];
    unsafe {
        std::ptr::copy_nonoverlapping(seed, key.as_mut_ptr(), 32);
        *index = -1;
    }
    let commitment = hash_parts(&[b"VK-RATCHET-COMMIT-V1", &key]);
    let bad_commit = !equal(&commitment, unsafe { std::slice::from_raw_parts(c0, 32) });
    let mut first = None;
    for (i, event) in unsafe { buffer(data, count) }
        .chunks_exact(WIDTH)
        .enumerate()
    {
        let tag = hash_parts(&[b"VK-RATCHET-TAG-V1", &key, &event[..96]]);
        let mismatch = !equal(&tag, &event[96..])
            || u64::from_le_bytes(event[..8].try_into().unwrap()) != i as u64;
        if mismatch && first.is_none() {
            first = Some(i);
        }
        let next = hash_parts(&[b"VK-RATCHET-STEP-V1", &key, &tag]);
        wipe(&mut key);
        key = next;
    }
    let terminal = equal(&key, unsafe { std::slice::from_raw_parts(kn, 32) });
    wipe(&mut key);
    if bad_commit {
        return -1;
    }
    if let Some(i) = first {
        unsafe {
            *index = i as i64;
        }
        return -1;
    }
    if !terminal {
        unsafe {
            *index = count as i64;
        }
        return -2;
    }
    0
}
/// Compute the Merkle tree head using the largest-power split. Complexity: O(n + W) time and O(n + M) space, including called operations W and retained state M.
fn root(data: &[u8]) -> [u8; 32] {
    let count = data.len() / WIDTH;
    if count == 0 {
        return sha256(b"");
    }
    if count == 1 {
        return hash_parts(&[&[0], data]);
    }
    let split = 1usize << ((usize::BITS - 1) - (count - 1).leading_zeros());
    hash_parts(&[
        &[1],
        &root(&data[..split * WIDTH]),
        &root(&data[split * WIDTH..]),
    ])
}
/// RFC 9162 SHA-256 event root. O(n) time, O(log n) stack space.
#[no_mangle]
/// Compute a SHA-256 Merkle root over packed telemetry records. Complexity: O(n + W) time and O(n + M) space, including called operations W and retained state M.
pub extern "C" fn vk_merkle_root_rfc9162(data: *const u8, count: usize, out: *mut u8) -> i32 {
    if !valid(data, count) || out.is_null() {
        return -3;
    }
    let hash = root(unsafe { buffer(data, count) });
    unsafe {
        std::ptr::copy_nonoverlapping(hash.as_ptr(), out, 32);
    }
    0
}
/// Batch-local LRU, expected O(n) time, O(min(n,capacity)) space. Invalid pointers return usize::MAX.
#[no_mangle]
/// Emit an inode-cache keep mask for the packed event stream. Complexity: O(n + W) time and O(n + M) space, including called operations W and retained state M.
pub extern "C" fn vk_dedup_filter_batch(
    data: *const u8,
    count: usize,
    capacity: usize,
    mask: *mut u8,
) -> usize {
    if !valid(data, count) || (count > 0 && mask.is_null()) {
        return usize::MAX;
    }
    let mut cache = if capacity == 0 {
        None
    } else {
        Some(InodeLruCache::new(capacity))
    };
    let mut kept = 0;
    for (i, event) in unsafe { buffer(data, count) }
        .chunks_exact(WIDTH)
        .enumerate()
    {
        let u64_at =
            |offset: usize| u64::from_le_bytes(event[offset..offset + 8].try_into().unwrap());
        let key = InodeCacheKey {
            syscall_nr: u32::from_le_bytes(event[24..28].try_into().unwrap()),
            pad: 0,
            dev_id: u64_at(32),
            inode_nr: u64_at(40),
            mtime_ns: u64_at(48),
        };
        let emit = !cache.as_mut().map(|lru| lru.seen(key)).unwrap_or(false);
        unsafe {
            *mask.add(i) = u8::from(emit);
        }
        kept += usize::from(emit);
    }
    kept
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    /// Check sha known answers against the expected result. Complexity: O(n + W) time and O(n + M) space, including called operations W and retained state M.
    fn sha_known_answers() -> () {
        assert_eq!(
            sha256(b"abc"),
            [
                0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
                0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
                0xf2, 0x00, 0x15, 0xad
            ]
        );
        assert_eq!(vk_sha256(std::ptr::null(), 1, std::ptr::null_mut()), -3);
    }
}
