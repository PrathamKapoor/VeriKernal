//! Stable little-endian telemetry records shared by native and Python readers.
#[repr(C, align(64))]
#[derive(Clone, Debug, Default, PartialEq, Eq)]
/// State retained by KernelTelemetryEvent. Space O(n) in owned entries.
pub struct KernelTelemetryEvent {
    pub seq_no: u64,
    pub timestamp_ns: u64,
    pub pid: u32,
    pub tid: u32,
    pub syscall_nr: u32,
    pub fault_injected: i32,
    pub dev_id: u64,
    pub inode_nr: u64,
    pub mtime_ns: u64,
    pub call_stack_hash: u64,
    pub target_digest: [u8; 32],
    pub ratchet_tag: [u8; 32],
}
impl KernelTelemetryEvent {
    /// Encode the event fields at their fixed little-endian wire offsets. Complexity: O(1) time and space.
    pub fn to_bytes(&self) -> [u8; 128] {
        let mut out = [0u8; 128];
        out[0..8].copy_from_slice(&self.seq_no.to_le_bytes());
        out[8..16].copy_from_slice(&self.timestamp_ns.to_le_bytes());
        for (i, value) in [
            self.pid,
            self.tid,
            self.syscall_nr,
            self.fault_injected as u32,
        ]
        .iter()
        .enumerate()
        {
            out[16 + i * 4..20 + i * 4].copy_from_slice(&value.to_le_bytes());
        }
        for (i, value) in [
            self.dev_id,
            self.inode_nr,
            self.mtime_ns,
            self.call_stack_hash,
        ]
        .iter()
        .enumerate()
        {
            out[32 + i * 8..40 + i * 8].copy_from_slice(&value.to_le_bytes());
        }
        out[64..96].copy_from_slice(&self.target_digest);
        out[96..128].copy_from_slice(&self.ratchet_tag);
        out
    }
    /// Decode the fixed-width event fields from little-endian bytes. Complexity: O(1) time and space.
    pub fn from_bytes(b: &[u8; 128]) -> Self {
        let u64at = |i| u64::from_le_bytes(b[i..i + 8].try_into().unwrap());
        let u32at = |i| u32::from_le_bytes(b[i..i + 4].try_into().unwrap());
        Self {
            seq_no: u64at(0),
            timestamp_ns: u64at(8),
            pid: u32at(16),
            tid: u32at(20),
            syscall_nr: u32at(24),
            fault_injected: u32at(28) as i32,
            dev_id: u64at(32),
            inode_nr: u64at(40),
            mtime_ns: u64at(48),
            call_stack_hash: u64at(56),
            target_digest: b[64..96].try_into().unwrap(),
            ratchet_tag: b[96..128].try_into().unwrap(),
        }
    }
}
#[repr(C)]
#[derive(Clone, Copy, Hash, Eq, PartialEq, Debug)]
/// State retained by InodeCacheKey. Space O(n) in owned entries.
pub struct InodeCacheKey {
    pub syscall_nr: u32,
    pub pad: u32,
    pub dev_id: u64,
    pub inode_nr: u64,
    pub mtime_ns: u64,
}
#[repr(C)]
/// State retained by FaultRule. Space O(n) in owned entries.
pub struct FaultRule {
    pub syscall_nr: u32,
    pub err_code: i32,
    pub stack_hash: u64,
    pub probability_ppm: u32,
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    /// Check wire roundtrip against the expected result. Complexity: O(n + W) time and O(n + M) space, including called operations W and retained state M.
    fn wire_roundtrip() -> () {
        let e = KernelTelemetryEvent {
            fault_injected: -11,
            seq_no: 91,
            ..Default::default()
        };
        assert_eq!(core::mem::size_of::<KernelTelemetryEvent>(), 128);
        assert_eq!(core::mem::align_of::<KernelTelemetryEvent>(), 64);
        assert_eq!(&e.to_bytes()[28..32], &[245, 255, 255, 255]);
        assert_eq!(KernelTelemetryEvent::from_bytes(&e.to_bytes()), e);
    }
}
