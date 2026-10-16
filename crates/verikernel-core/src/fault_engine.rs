//! Seeded fault decisions and complement-based counterexample reduction.
/// Advance the fixed-width SplitMix64 mixing function. Complexity: O(1) time and space.
pub fn splitmix64(mut x: u64) -> u64 {
    x = x.wrapping_add(0x9e3779b97f4a7c15);
    x = (x ^ (x >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
    x = (x ^ (x >> 27)).wrapping_mul(0x94d049bb133111eb);
    x ^ (x >> 31)
}
/// Compare a deterministic site draw with the configured probability. Complexity: O(1) time and space.
pub fn should_inject_fault(seed: u64, stack: u64, syscall: u32, ordinal: u64, ppm: u32) -> bool {
    splitmix64(seed ^ splitmix64(stack) ^ splitmix64(syscall as u64) ^ splitmix64(ordinal))
        % 1_000_000
        < (ppm.min(1_000_000) as u64)
}
/// Remove fault complements until no single remaining fault can be discarded. Complexity: O(n^2) oracle calls in the worst case; each call also builds candidate subsets.
pub fn ddmin_shrink<F: FnMut(&[usize]) -> bool>(
    mut candidates: Vec<usize>,
    mut fails: F,
) -> Vec<usize> {
    assert!(fails(&candidates));
    if fails(&[]) {
        return vec![];
    }
    let mut n = 2;
    while candidates.len() >= 2 {
        let size = (candidates.len() + n - 1) / n;
        let mut found = None;
        for chunk in candidates.chunks(size) {
            let rest: Vec<_> = candidates
                .iter()
                .copied()
                .filter(|x| !chunk.contains(x))
                .collect();
            if fails(&rest) {
                found = Some(rest);
                break;
            }
        }
        if let Some(rest) = found {
            candidates = rest;
            n = 2.max(n - 1);
        } else if n >= candidates.len() {
            break;
        } else {
            n = (n * 2).min(candidates.len());
        }
    }
    candidates
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    /// Check reduce pair against the expected result. Complexity: O(n + W) time and O(n + M) space, including called operations W and retained state M.
    fn reduce_pair() -> () {
        assert_eq!(
            ddmin_shrink((0..32).collect(), |s| s.contains(&7) && s.contains(&23)),
            vec![7, 23]
        );
        assert_eq!(splitmix64(0), 0xe220a8397b1dcdaf);
    }
}
