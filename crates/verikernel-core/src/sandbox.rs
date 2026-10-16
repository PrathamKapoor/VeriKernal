//! Architecture-checked classic BPF notification policy.
use serde::{Deserialize, Serialize};
#[derive(Clone, Debug, Serialize, Deserialize)]
/// State retained by SandboxPolicy. Space O(n) in owned entries.
pub struct SandboxPolicy {
    pub read_only: Vec<String>,
    pub read_write: Vec<String>,
    pub notify_syscalls: Vec<u32>,
    pub architecture: u32,
    #[serde(default)]
    pub network: Vec<String>,
}
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
/// State retained by FilterInstruction. Space O(n) in owned entries.
pub struct FilterInstruction {
    pub code: u16,
    pub jt: u8,
    pub jf: u8,
    pub k: u32,
}
/// Construct one classic BPF instruction. Complexity: O(1) time and space.
fn instruction(code: u16, jt: u8, jf: u8, k: u32) -> FilterInstruction {
    FilterInstruction { code, jt, jf, k }
}
/// Build an architecture-checked syscall notification program. Complexity: O(n + W) time and O(n + M) space, including called operations W and retained state M.
pub fn notification_filter(
    syscalls: &[u32],
    architecture: u32,
) -> Result<Vec<FilterInstruction>, String> {
    if ![0xc000003e, 0xc00000b7].contains(&architecture) {
        return Err("unsupported audit architecture".into());
    }
    if syscalls.len() > 1000 || syscalls.iter().any(|n| *n >= 0x40000000) {
        return Err("invalid syscall list".into());
    }
    let mut out = vec![
        instruction(0x20, 0, 0, 4),
        instruction(0x15, 1, 0, architecture),
        instruction(0x06, 0, 0, 0x80000000),
        instruction(0x20, 0, 0, 0),
    ];
    if architecture == 0xc000003e {
        out.extend([
            instruction(0x35, 0, 1, 0x40000000),
            instruction(0x06, 0, 0, 0x80000000),
        ]);
    }
    let mut unique = syscalls.to_vec();
    unique.sort_unstable();
    unique.dedup();
    for nr in unique {
        out.extend([
            instruction(0x15, 0, 1, nr),
            instruction(0x06, 0, 0, 0x7fc00000),
        ]);
    }
    out.push(instruction(0x06, 0, 0, 0x7fff0000));
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    /// Evaluate the supported filter instructions against a syscall. Complexity: O(n + W) time and O(n + M) space, including called operations W and retained state M.
    fn evaluate(code: &[FilterInstruction], arch: u32, nr: u32) -> u32 {
        let (mut pc, mut accumulator) = (0, 0);
        loop {
            let op = code[pc];
            match op.code {
                0x20 => {
                    accumulator = if op.k == 4 { arch } else { nr };
                    pc += 1;
                }
                0x15 => {
                    pc += 1 + if accumulator == op.k {
                        op.jt as usize
                    } else {
                        op.jf as usize
                    }
                }
                0x35 => {
                    pc += 1 + if accumulator >= op.k {
                        op.jt as usize
                    } else {
                        op.jf as usize
                    }
                }
                0x06 => return op.k,
                _ => panic!("unexpected filter instruction"),
            }
        }
    }
    #[test]
    /// Check dispatch and architecture fail closed against the expected result. Complexity: O(n + W) time and O(n + M) space, including called operations W and retained state M.
    fn dispatch_and_architecture_fail_closed() -> () {
        let code = notification_filter(&[0, 1, 257], 0xc000003e).unwrap();
        assert_eq!(evaluate(&code, 0xc000003e, 257), 0x7fc00000);
        assert_eq!(evaluate(&code, 0xc000003e, 2), 0x7fff0000);
        assert_eq!(evaluate(&code, 0xc00000b7, 257), 0x80000000);
        assert_eq!(evaluate(&code, 0xc000003e, 0x40000000), 0x80000000);
        assert!(notification_filter(&[], 0).is_err());
    }
}
