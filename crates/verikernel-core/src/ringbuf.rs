//! Bounded shared FIFO transport, inode caching and ordered CPU staging.
use std::collections::{BTreeMap, HashMap};
use verikernel_schema::{InodeCacheKey, KernelTelemetryEvent};
/// State retained by NativeFifo. Space O(n) in owned entries.
pub struct NativeFifo {
    queue: crossbeam_queue::ArrayQueue<KernelTelemetryEvent>,
}
impl NativeFifo {
    /// Initialize the owned state and validate its capacity. Complexity: O(n + W) time and O(n + M) space, including called operations W and retained state M.
    pub fn new(capacity: usize) -> Self {
        assert!(capacity > 0);
        Self {
            queue: crossbeam_queue::ArrayQueue::new(capacity),
        }
    }
    /// Attempt one nonblocking FIFO publication. Complexity: O(1) time and space.
    pub fn try_push(&self, event: KernelTelemetryEvent) -> Result<(), KernelTelemetryEvent> {
        self.queue.push(event)
    }
    /// Attempt one nonblocking FIFO read. Complexity: O(1) time and space.
    pub fn try_pop(&self) -> Option<KernelTelemetryEvent> {
        self.queue.pop()
    }
}

#[no_mangle]
/// Allocate a bounded FIFO for C callers. Complexity: O(n + W) time and O(n + M) space, including called operations W and retained state M.
pub extern "C" fn vk_ring_new(capacity: usize) -> *mut NativeFifo {
    if capacity == 0 || capacity > 16_777_216 {
        return std::ptr::null_mut();
    }
    Box::into_raw(Box::new(NativeFifo::new(capacity)))
}
#[no_mangle]
/// Publish a packed event into the bounded native FIFO. Complexity: O(1) time and space.
pub unsafe extern "C" fn vk_ring_push(ring: *const NativeFifo, data: *const u8) -> i32 {
    if ring.is_null() || data.is_null() {
        return -1;
    }
    let mut bytes = [0u8; 128];
    std::ptr::copy_nonoverlapping(data, bytes.as_mut_ptr(), 128);
    match (*ring).try_push(KernelTelemetryEvent::from_bytes(&bytes)) {
        Ok(()) => 1,
        Err(_) => 0,
    }
}
#[no_mangle]
/// Read the next packed event from the native FIFO. Complexity: O(1) time and space.
pub unsafe extern "C" fn vk_ring_pop(ring: *const NativeFifo, data: *mut u8) -> i32 {
    if ring.is_null() || data.is_null() {
        return -1;
    }
    match (*ring).try_pop() {
        Some(event) => {
            std::ptr::copy_nonoverlapping(event.to_bytes().as_ptr(), data, 128);
            1
        }
        None => 0,
    }
}
#[no_mangle]
/// Destroy an owned native FIFO handle. Complexity: O(n + W) time and O(n + M) space, including called operations W and retained state M.
pub unsafe extern "C" fn vk_ring_free(ring: *mut NativeFifo) -> () {
    if !ring.is_null() {
        drop(Box::from_raw(ring));
    }
}
/// State retained by InodeLruCache. Space O(n) in owned entries.
pub struct InodeLruCache {
    capacity: usize,
    entries: HashMap<InodeCacheKey, (Option<InodeCacheKey>, Option<InodeCacheKey>)>,
    head: Option<InodeCacheKey>,
    tail: Option<InodeCacheKey>,
}
impl InodeLruCache {
    /// Initialize the owned state and validate its capacity. Complexity: O(n + W) time and O(n + M) space, including called operations W and retained state M.
    pub fn new(capacity: usize) -> Self {
        assert!(capacity > 0);
        Self {
            capacity,
            entries: HashMap::new(),
            head: None,
            tail: None,
        }
    }
    /// Detach a cache entry from the recency chain. Complexity: O(n + W) time and O(n + M) space, including called operations W and retained state M.
    fn unlink(&mut self, key: InodeCacheKey) -> () {
        let (previous, next) = self.entries[&key];
        if let Some(p) = previous {
            self.entries.get_mut(&p).unwrap().1 = next;
        } else {
            self.head = next;
        }
        if let Some(n) = next {
            self.entries.get_mut(&n).unwrap().0 = previous;
        } else {
            self.tail = previous;
        }
    }
    /// Refresh an inode key and evict the oldest entry when full. Complexity: O(n + W) time and O(n + M) space, including called operations W and retained state M.
    pub fn seen(&mut self, key: InodeCacheKey) -> bool {
        if self.tail == Some(key) {
            return true;
        }
        let existed = self.entries.contains_key(&key);
        if existed {
            self.unlink(key);
        } else if self.entries.len() == self.capacity {
            let victim = self.head.unwrap();
            self.unlink(victim);
            self.entries.remove(&victim);
        }
        self.entries.insert(key, (self.tail, None));
        if let Some(t) = self.tail {
            self.entries.get_mut(&t).unwrap().1 = Some(key);
        } else {
            self.head = Some(key);
        }
        self.tail = Some(key);
        existed
    }
}
/// State retained by ZeroDropRingBuffer. Space O(n) in owned entries.
pub struct ZeroDropRingBuffer {
    l1: Vec<Vec<KernelTelemetryEvent>>,
    shared: BTreeMap<u64, KernelTelemetryEvent>,
    capacity: usize,
}
impl ZeroDropRingBuffer {
    /// Initialize the owned state and validate its capacity. Complexity: O(n + W) time and O(n + M) space, including called operations W and retained state M.
    pub fn new(cpus: usize, capacity: usize) -> Self {
        assert!(cpus > 0 && capacity > 0);
        Self {
            l1: vec![vec![]; cpus],
            shared: BTreeMap::new(),
            capacity,
        }
    }
    /// Stage a telemetry record in its CPU queue. Complexity: O(n + W) time and O(n + M) space, including called operations W and retained state M.
    pub fn push(&mut self, cpu: usize, event: KernelTelemetryEvent) -> () {
        self.l1[cpu].push(event);
        if self.l1[cpu].len() >= self.capacity {
            self.flush(cpu);
        }
    }
    /// Move CPU staging records to the shared ordered stream. Complexity: O(n + W) time and O(n + M) space, including called operations W and retained state M.
    fn flush(&mut self, cpu: usize) -> () {
        for e in self.l1[cpu].drain(..) {
            assert!(self.shared.insert(e.seq_no, e).is_none());
        }
    }
    /// Release staged records in global sequence order. Complexity: O(n + W) time and O(n + M) space, including called operations W and retained state M.
    pub fn drain(&mut self) -> Vec<KernelTelemetryEvent> {
        for cpu in 0..self.l1.len() {
            self.flush(cpu);
        }
        std::mem::take(&mut self.shared).into_values().collect()
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    /// Check preserves sequences against the expected result. Complexity: O(n + W) time and O(n + M) space, including called operations W and retained state M.
    fn preserves_sequences() -> () {
        let mut q = ZeroDropRingBuffer::new(4, 8);
        for i in (0..100).rev() {
            q.push(
                i % 4,
                KernelTelemetryEvent {
                    seq_no: i as u64,
                    ..Default::default()
                },
            );
        }
        let events = q.drain();
        assert_eq!(events.len(), 100);
        for (i, e) in events.iter().enumerate() {
            assert_eq!(e.seq_no, i as u64);
        }
    }
}

#[cfg(test)]
mod cache_tests {
    use super::*;
    #[test]
    /// Check refresh and evict against the expected result. Complexity: O(n + W) time and O(n + M) space, including called operations W and retained state M.
    fn refresh_and_evict() -> () {
        let mut c = InodeLruCache::new(2);
        let a = InodeCacheKey {
            syscall_nr: 2,
            pad: 0,
            dev_id: 1,
            inode_nr: 1,
            mtime_ns: 1,
        };
        let b = InodeCacheKey { inode_nr: 2, ..a };
        let d = InodeCacheKey { inode_nr: 3, ..a };
        assert!(!c.seen(a));
        assert!(!c.seen(b));
        assert!(c.seen(a));
        assert!(!c.seen(d));
        assert!(!c.seen(b));
        assert!(!c.seen(InodeCacheKey { mtime_ns: 2, ..a }));
    }
}

#[cfg(test)]
mod concurrent_tests {
    use super::*;
    use std::sync::Arc;
    #[test]
    /// Check bounded fifo preserves every publication against the expected result. Complexity: O(n + W) time and O(n + M) space, including called operations W and retained state M.
    fn bounded_fifo_preserves_every_publication() -> () {
        let ring = Arc::new(NativeFifo::new(32));
        let handles: Vec<_> = (0..4)
            .map(|cpu| {
                let ring = ring.clone();
                std::thread::spawn(move || {
                    for index in 0..1000 {
                        let mut event = KernelTelemetryEvent {
                            seq_no: (cpu * 1000 + index) as u64,
                            ..Default::default()
                        };
                        loop {
                            match ring.try_push(event) {
                                Ok(()) => break,
                                Err(returned) => {
                                    event = returned;
                                    std::thread::yield_now();
                                }
                            }
                        }
                    }
                })
            })
            .collect();
        let mut observed = std::collections::HashSet::new();
        while observed.len() < 4000 {
            if let Some(event) = ring.try_pop() {
                assert!(observed.insert(event.seq_no));
            } else {
                std::thread::yield_now();
            }
        }
        for handle in handles {
            handle.join().unwrap();
        }
        assert!(ring.try_pop().is_none());
    }
}
