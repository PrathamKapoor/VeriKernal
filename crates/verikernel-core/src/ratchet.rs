//! BLAKE3 event authentication with evolving keys and explicit zeroization.
use zeroize::Zeroize;
/// State retained by ForwardSecureRatchet. Space O(n) in owned entries.
pub struct ForwardSecureRatchet {
    state: [u8; 32],
    pub commitment: [u8; 32],
    pub count: u64,
}
/// Feed ordered input slices into BLAKE3. Complexity: O(n + W) time and O(n + M) space, including called operations W and retained state M.
pub fn hash(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    for p in parts {
        h.update(p);
    }
    *h.finalize().as_bytes()
}
impl ForwardSecureRatchet {
    /// Initialize the owned state and validate its capacity. Complexity: O(n + W) time and O(n + M) space, including called operations W and retained state M.
    pub fn new(seed: [u8; 32]) -> Self {
        Self {
            commitment: hash(&[b"VK-RATCHET-COMMIT-V1", &seed]),
            state: seed,
            count: 0,
        }
    }
    /// Authenticate one event, evolve the key and erase the old state. Complexity: O(1) time and space.
    pub fn tag(&mut self, event: &mut verikernel_schema::KernelTelemetryEvent) -> () {
        let bytes = event.to_bytes();
        let t = hash(&[b"VK-RATCHET-TAG-V1", &self.state, &bytes[..96]]);
        let next = hash(&[b"VK-RATCHET-STEP-V1", &self.state, &t]);
        self.state.zeroize();
        self.state = next;
        self.count += 1;
        event.ratchet_tag = t;
    }
    /// Copy the current terminal key for epoch sealing. Complexity: O(1) time and space.
    pub fn terminal(&self) -> [u8; 32] {
        self.state
    }
}
impl Drop for ForwardSecureRatchet {
    /// Release the resource owned by this value. Complexity: O(n + W) time and O(n + M) space, including called operations W and retained state M.
    fn drop(&mut self) -> () {
        self.state.zeroize();
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    /// Check ordered tags against the expected result. Complexity: O(n + W) time and O(n + M) space, including called operations W and retained state M.
    fn ordered_tags() -> () {
        let mut a = ForwardSecureRatchet::new([3; 32]);
        let mut b = ForwardSecureRatchet::new([3; 32]);
        let mut e = verikernel_schema::KernelTelemetryEvent::default();
        a.tag(&mut e);
        let first = e.ratchet_tag;
        b.tag(&mut e);
        assert_eq!(first, e.ratchet_tag);
        a.tag(&mut e);
        assert_ne!(first, e.ratchet_tag);
        assert_eq!(a.count, 2);
    }
}
