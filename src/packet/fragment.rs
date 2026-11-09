use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant, SystemTime};

use super::{IpProtocol, ReassembledPacket, MAX_IP_PACKET};

const MAX_PIECES_PER_SET: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FragmentKey {
    pub src: IpAddr,
    pub dst: IpAddr,
    pub id: u32,
    pub protocol: u8,
    pub ipv6: bool,
}

#[derive(Debug)]
struct Piece {
    offset: u32,
    data: Vec<u8>,
}

#[derive(Debug)]
struct FragmentSet {
    pieces: Vec<Piece>,
    total_len: Option<u32>,
    updated: Instant,
    first_timestamp: Option<SystemTime>,
    last_timestamp: Option<SystemTime>,
    ipv6: bool,
    protocol: IpProtocol,
    bytes: usize,
}

/// Bounded IPv4/IPv6 fragment reassembly cache.
///
/// Conflicting overlaps are discarded instead of silently picking one
/// interpretation; this closes a common IDS/IPS evasion technique.
#[derive(Debug)]
pub struct FragmentCache {
    sets: HashMap<FragmentKey, FragmentSet>,
    max_sets: usize,
    max_total_bytes: usize,
    timeout: Duration,
    total_bytes: usize,
}

impl FragmentCache {
    pub fn new(max_sets: usize, max_total_bytes: usize, timeout: Duration) -> Self {
        Self {
            sets: HashMap::new(),
            max_sets: max_sets.max(1),
            max_total_bytes: max_total_bytes.max(MAX_IP_PACKET),
            timeout,
            total_bytes: 0,
        }
    }

    pub fn len(&self) -> usize {
        self.sets.len()
    }

    pub fn is_empty(&self) -> bool {
        self.sets.is_empty()
    }

    pub fn memory_bytes(&self) -> usize {
        self.total_bytes
    }

    /// Insert a fragment and return a completed packet when all bytes are
    /// present. Any malformed, oversized or conflicting input is dropped.
    pub fn insert(
        &mut self,
        view: &super::FragmentedView<'_>,
        now: Instant,
    ) -> Option<ReassembledPacket> {
        self.expire(now);
        if view.payload.is_empty() && view.more_fragments {
            return None;
        }
        let end = view.offset as usize + view.payload.len();
        if end > MAX_IP_PACKET {
            return None;
        }
        let key = FragmentKey {
            src: view.src,
            dst: view.dst,
            id: view.id,
            protocol: view.protocol.0,
            ipv6: view.ipv6,
        };

        if !self.sets.contains_key(&key) {
            if self.sets.len() >= self.max_sets {
                self.evict_oldest();
            }
            self.sets.insert(
                key,
                FragmentSet {
                    pieces: Vec::new(),
                    total_len: None,
                    updated: now,
                    first_timestamp: view.timestamp,
                    last_timestamp: view.timestamp,
                    ipv6: view.ipv6,
                    protocol: view.protocol,
                    bytes: 0,
                },
            );
        }

        // Reject if the new payload cannot fit under the memory budget after
        // making room by evicting stale sets.
        while self.total_bytes + view.payload.len() > self.max_total_bytes && !self.sets.is_empty()
        {
            self.evict_oldest();
        }
        if self.total_bytes + view.payload.len() > self.max_total_bytes {
            return None;
        }

        let set = self.sets.get_mut(&key)?;
        set.updated = now;
        if view.timestamp.is_some() {
            if set.first_timestamp.is_none() {
                set.first_timestamp = view.timestamp;
            }
            set.last_timestamp = view.timestamp;
        }
        if !view.more_fragments {
            let total = view.offset + view.payload.len() as u32;
            set.total_len = Some(match set.total_len {
                Some(existing) if existing != total => {
                    // Contradictory final lengths are an attack or corruption.
                    let bytes = set.bytes;
                    self.sets.remove(&key);
                    self.total_bytes = self.total_bytes.saturating_sub(bytes);
                    return None;
                }
                _ => total,
            });
        }
        if let Some(total) = set.total_len {
            if end > total as usize {
                return None;
            }
        }
        if set.pieces.len() >= MAX_PIECES_PER_SET {
            return None;
        }
        for piece in &set.pieces {
            if piece.offset == view.offset && piece.data.len() >= view.payload.len() {
                return None; // duplicate or fully shadowed
            }
        }
        let data = view.payload.to_vec();
        self.total_bytes += data.len();
        set.bytes += data.len();
        set.pieces.push(Piece {
            offset: view.offset,
            data,
        });
        set.pieces.sort_by_key(|p| p.offset);

        self.try_complete(&key)
    }

    fn try_complete(&mut self, key: &FragmentKey) -> Option<ReassembledPacket> {
        let set = self.sets.get(key)?;
        let total = set.total_len?;
        if set.pieces.first().map(|p| p.offset) != Some(0) {
            return None;
        }
        let mut covered = 0u32;
        for piece in &set.pieces {
            if piece.offset > covered {
                return None;
            }
            covered = covered.max(piece.offset + piece.data.len() as u32);
        }
        if covered < total {
            return None;
        }

        // Overlap consistency check.
        let mut out = vec![0u8; total as usize];
        let mut filled = vec![false; total as usize];
        for piece in &set.pieces {
            let start = piece.offset as usize;
            for (i, byte) in piece.data.iter().enumerate() {
                let pos = start + i;
                if pos >= out.len() {
                    break;
                }
                if filled[pos] && out[pos] != *byte {
                    let set = self.sets.remove(key)?;
                    self.total_bytes = self.total_bytes.saturating_sub(set.bytes);
                    return None;
                }
                out[pos] = *byte;
                filled[pos] = true;
            }
        }

        let set = self.sets.remove(key)?;
        self.total_bytes = self.total_bytes.saturating_sub(set.bytes);
        Some(ReassembledPacket {
            timestamp: set.first_timestamp.or(set.last_timestamp),
            src: key.src,
            dst: key.dst,
            protocol: set.protocol,
            ipv6: set.ipv6,
            payload: out,
        })
    }

    pub fn expire(&mut self, now: Instant) {
        let timeout = self.timeout;
        let before = self.total_bytes;
        self.sets.retain(|_, set| {
            let keep = now.saturating_duration_since(set.updated) < timeout;
            if !keep {
                // total_bytes is recomputed below from retained sets.
            }
            keep
        });
        let bytes: usize = self.sets.values().map(|s| s.bytes).sum();
        self.total_bytes = bytes;
        if before != bytes {
            // Values are recomputed, no further action needed.
        }
    }

    fn evict_oldest(&mut self) {
        let Some(oldest) = self
            .sets
            .iter()
            .min_by_key(|(_, set)| set.updated)
            .map(|(key, _)| *key)
        else {
            return;
        };
        if let Some(set) = self.sets.remove(&oldest) {
            self.total_bytes = self.total_bytes.saturating_sub(set.bytes);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::FragmentedView;
    use std::net::{IpAddr, Ipv4Addr};

    fn frag(offset: u32, data: &'static [u8], more: bool) -> FragmentedView<'static> {
        FragmentedView {
            timestamp: None,
            src: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            dst: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 2)),
            protocol: IpProtocol::TCP,
            id: 7,
            offset,
            more_fragments: more,
            payload: data,
            ipv6: false,
        }
    }

    #[test]
    fn out_of_order_reassembly() {
        let mut cache = FragmentCache::new(16, 1 << 20, Duration::from_secs(30));
        let now = Instant::now();
        assert!(cache.insert(&frag(16, b"cccccccc", false), now).is_none());
        let done = cache.insert(&frag(0, b"aaaaaaaabbbbbbbb", true), now);
        let pkt = done.expect("complete");
        assert_eq!(&pkt.payload[..], b"aaaaaaaabbbbbbbbcccccccc");
    }

    #[test]
    fn overlap_conflict_is_dropped() {
        let mut cache = FragmentCache::new(16, 1 << 20, Duration::from_secs(30));
        let now = Instant::now();
        assert!(cache.insert(&frag(0, b"aaaa", true), now).is_none());
        // Prefix overlap with conflicting data, plus a final fragment.
        assert!(cache.insert(&frag(2, b"XXXX", true), now).is_none());
        assert!(cache.insert(&frag(4, b"cccc", false), now).is_none());
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn expires_incomplete_sets() {
        let mut cache = FragmentCache::new(16, 1 << 20, Duration::from_millis(10));
        let now = Instant::now();
        cache.insert(&frag(0, b"aaaa", true), now);
        cache.expire(now + Duration::from_secs(1));
        assert!(cache.is_empty());
    }

    #[test]
    fn bounds_piece_count() {
        let mut cache = FragmentCache::new(16, 1 << 20, Duration::from_secs(30));
        let now = Instant::now();
        for i in 0..(MAX_PIECES_PER_SET + 2) {
            let offset = (i as u32 + 1) * 8;
            let data = vec![0u8; 8];
            let view = FragmentedView {
                payload: &data,
                offset,
                more_fragments: true,
                ..frag(0, b"", true)
            };
            cache.insert(&view, now);
        }
        assert!(cache.len() <= 1);
    }
}
