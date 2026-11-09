use std::collections::BTreeMap;

/// Bounded, wrap-aware TCP stream reassembler for one direction.
///
/// Sequence numbers are normalised against the first observed payload byte.
/// Retransmissions are trimmed, out-of-order data is queued, and conflicting
/// gaps are resolved conservatively. Once the byte budget is exhausted the
/// stream is marked truncated; no unbounded memory growth is possible.
#[derive(Debug)]
pub struct TcpReassembler {
    isn: Option<u32>,
    next_off: u64,
    data: Vec<u8>,
    pending: BTreeMap<u64, Vec<u8>>,
    pending_bytes: usize,
    max_bytes: usize,
    truncated: bool,
    total_seen: u64,
}

impl TcpReassembler {
    pub fn new(max_bytes: usize) -> Self {
        Self {
            isn: None,
            next_off: 0,
            data: Vec::new(),
            pending: BTreeMap::new(),
            pending_bytes: 0,
            max_bytes: max_bytes.max(1),
            truncated: false,
            total_seen: 0,
        }
    }

    pub fn data(&self) -> &[u8] {
        &self.data
    }

    pub fn len(&self) -> usize {
        self.data.len()
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    pub fn is_truncated(&self) -> bool {
        self.truncated
    }

    pub fn pending_bytes(&self) -> usize {
        self.pending_bytes
    }

    pub fn total_seen(&self) -> u64 {
        self.total_seen
    }

    /// Returns true when the contiguous prefix grew as a result of this
    /// segment (including gap-filling).
    pub fn push(&mut self, seq: u32, payload: &[u8]) -> bool {
        if payload.is_empty() || self.truncated {
            return false;
        }
        let isn = *self.isn.get_or_insert(seq);
        let relative = seq.wrapping_sub(isn) as u64;
        if relative > u32::MAX as u64 / 2 {
            // Segment starts before our base; it cannot extend the prefix.
            return false;
        }
        let end = relative.saturating_add(payload.len() as u64);
        self.total_seen = self.total_seen.saturating_add(payload.len() as u64);
        if end <= self.next_off {
            return false;
        }

        if relative > self.next_off {
            if self.pending_bytes + payload.len() <= self.max_bytes {
                match self.pending.get(&relative) {
                    Some(existing) if existing.len() >= payload.len() => {}
                    Some(existing) => {
                        self.pending_bytes -= existing.len();
                        self.pending_bytes += payload.len();
                        self.pending.insert(relative, payload.to_vec());
                    }
                    None => {
                        self.pending_bytes += payload.len();
                        self.pending.insert(relative, payload.to_vec());
                    }
                }
            }
            return false;
        }

        // Trim bytes already delivered.
        let skip = (self.next_off - relative) as usize;
        let fresh = &payload[skip.min(payload.len())..];
        if fresh.is_empty() {
            return false;
        }
        let room = self.max_bytes.saturating_sub(self.data.len());
        if room == 0 {
            self.truncated = true;
            return false;
        }
        let take = fresh.len().min(room);
        self.data.extend_from_slice(&fresh[..take]);
        self.next_off = self.next_off.saturating_add(take as u64);
        if take < fresh.len() {
            self.truncated = true;
            self.pending.clear();
            self.pending_bytes = 0;
            return true;
        }
        self.drain_pending();
        true
    }

    fn drain_pending(&mut self) {
        while let Some((&offset, _)) = self.pending.first_key_value() {
            if offset > self.next_off {
                break;
            }
            let Some(part) = self.pending.remove(&offset) else {
                break;
            };
            self.pending_bytes = self.pending_bytes.saturating_sub(part.len());
            let skip = (self.next_off - offset) as usize;
            if skip >= part.len() {
                continue;
            }
            let room = self.max_bytes.saturating_sub(self.data.len());
            if room == 0 {
                self.truncated = true;
                self.pending.clear();
                self.pending_bytes = 0;
                return;
            }
            let take = (part.len() - skip).min(room);
            self.data.extend_from_slice(&part[skip..skip + take]);
            self.next_off = self.next_off.saturating_add(take as u64);
            if take < part.len() - skip {
                self.truncated = true;
                self.pending.clear();
                self.pending_bytes = 0;
                return;
            }
        }
    }

    /// Feed a SYN's sequence number before data is seen. The next payload byte
    /// is then treated as offset zero.
    pub fn observe_syn(&mut self, seq: u32) {
        if self.isn.is_none() {
            self.isn = Some(seq.wrapping_add(1));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn in_order() {
        let mut r = TcpReassembler::new(1024);
        assert!(r.push(100, b"hello"));
        assert!(r.push(105, b" world"));
        assert_eq!(r.data(), b"hello world");
    }

    #[test]
    fn out_of_order_then_gap_fill() {
        let mut r = TcpReassembler::new(1024);
        r.observe_syn(99);
        assert!(!r.push(106, b"world"));
        assert!(r.push(100, b"hello "));
        assert_eq!(r.data(), b"hello world");
        assert_eq!(r.pending_bytes(), 0);
    }

    #[test]
    fn retransmission_is_ignored() {
        let mut r = TcpReassembler::new(1024);
        r.push(100, b"abcdef");
        assert!(!r.push(100, b"abcdef"));
        assert!(!r.push(102, b"cdef"));
        assert_eq!(r.data(), b"abcdef");
    }

    #[test]
    fn partial_overlap_is_trimmed() {
        let mut r = TcpReassembler::new(1024);
        r.push(100, b"abcdef");
        assert!(r.push(103, b"defghi"));
        assert_eq!(r.data(), b"abcdefghi");
    }

    #[test]
    fn sequence_wrap_works() {
        let mut r = TcpReassembler::new(1024);
        let start = u32::MAX - 2;
        assert!(r.push(start, b"abcd"));
        assert!(r.push(1, b"efgh"));
        assert_eq!(r.data(), b"abcdefgh");
    }

    #[test]
    fn memory_is_capped() {
        let mut r = TcpReassembler::new(8);
        assert!(r.push(0, b"0123456789"));
        assert!(r.is_truncated());
        assert_eq!(r.data(), b"01234567");
        assert!(!r.push(10, b"more"));
    }

    #[test]
    fn pending_is_bounded() {
        let mut r = TcpReassembler::new(16);
        for i in 0..100 {
            r.push(10_000 + i * 4, b"xxxx");
        }
        assert!(r.pending_bytes() <= 16);
    }

    #[test]
    fn syn_sets_expected_offset() {
        let mut r = TcpReassembler::new(1024);
        r.observe_syn(1000);
        assert!(r.push(1001, b"data"));
        assert_eq!(r.data(), b"data");
    }
}
