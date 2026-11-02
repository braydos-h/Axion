use etherparse::{NetSlice, SlicedPacket, TransportSlice};
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, SocketAddr};

/// At most this much TCP payload is copied per capture event, solely for handshake parsing.
pub const MAX_PAYLOAD: usize = 16 * 1024;
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Protocol {
    Tcp,
    Udp,
}
#[derive(Clone, Debug)]
pub struct Packet {
    pub timestamp_ms: u64,
    pub src: SocketAddr,
    pub dst: SocketAddr,
    pub protocol: Protocol,
    pub wire_len: u32,
    pub tcp_seq: Option<u32>,
    /// TCP flags in their wire bit positions.
    pub tcp_flags: u8,
    pub payload: Vec<u8>,
}

/// Parse Ethernet, Linux cooked v1/v2, or raw IP using the capture link type.
/// Unsupported, fragmented, malformed and truncated packets are ignored.
pub fn parse(data: &[u8], wire_len: u32, timestamp_ms: u64, linktype: i32) -> Option<Packet> {
    let sliced = match linktype {
        1 => SlicedPacket::from_ethernet(data).ok()?,
        101 | 12 => SlicedPacket::from_ip(data).ok()?,
        // Strip the fixed cooked-capture headers, preserving VLAN/IP parsing.
        113 if data.len() >= 16 => SlicedPacket::from_ether_type(
            etherparse::EtherType(u16::from_be_bytes([data[14], data[15]])),
            &data[16..],
        )
        .ok()?,
        276 if data.len() >= 20 => SlicedPacket::from_ether_type(
            etherparse::EtherType(u16::from_be_bytes([data[0], data[1]])),
            &data[20..],
        )
        .ok()?,
        _ => return None,
    };
    if sliced.is_ip_payload_fragmented() {
        return None;
    }
    let (src, dst) = match sliced.net? {
        NetSlice::Ipv4(ip) => (
            IpAddr::V4(ip.header().source_addr()),
            IpAddr::V4(ip.header().destination_addr()),
        ),
        NetSlice::Ipv6(ip) => (
            IpAddr::V6(ip.header().source_addr()),
            IpAddr::V6(ip.header().destination_addr()),
        ),
        _ => return None,
    };
    let (sp, dp, protocol, seq, flags, payload) = match sliced.transport? {
        TransportSlice::Tcp(tcp) => {
            let h = &tcp;
            let flags = u8::from(h.fin())
                | (u8::from(h.syn()) << 1)
                | (u8::from(h.rst()) << 2)
                | (u8::from(h.psh()) << 3)
                | (u8::from(h.ack()) << 4);
            (
                h.source_port(),
                h.destination_port(),
                Protocol::Tcp,
                Some(h.sequence_number()),
                flags,
                tcp.payload(),
            )
        }
        TransportSlice::Udp(udp) => (
            udp.source_port(),
            udp.destination_port(),
            Protocol::Udp,
            None,
            0,
            &[][..],
        ),
        _ => return None,
    };
    Some(Packet {
        timestamp_ms,
        src: SocketAddr::new(src, sp),
        dst: SocketAddr::new(dst, dp),
        protocol,
        wire_len,
        tcp_seq: seq,
        tcp_flags: flags,
        payload: payload[..payload.len().min(MAX_PAYLOAD)].to_vec(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_bad_packets() {
        for n in 0..60 {
            assert!(parse(&vec![0; n], n as u32, 0, 1).is_none());
        }
    }
    #[test]
    fn parses_ipv4_tcp_and_ipv6_udp() {
        let p = etherparse::PacketBuilder::ethernet2([1; 6], [2; 6])
            .ipv4([10, 0, 0, 1], [10, 0, 0, 2], 64)
            .tcp(1234, 443, 42, 1024)
            .syn();
        let mut bytes = Vec::new();
        p.write(&mut bytes, &[]).unwrap();
        let result = parse(&bytes, bytes.len() as u32, 100, 1).unwrap();
        assert_eq!(result.src.port(), 1234);
        assert_eq!(result.protocol, Protocol::Tcp);
        assert_eq!(result.tcp_flags & 2, 2);
        let p = etherparse::PacketBuilder::ethernet2([1; 6], [2; 6])
            .ipv6([0; 16], [1; 16], 64)
            .udp(42, 53);
        let mut bytes = Vec::new();
        p.write(&mut bytes, &[]).unwrap();
        let result = parse(&bytes, bytes.len() as u32, 101, 1).unwrap();
        assert!(result.src.is_ipv6());
        assert_eq!(result.protocol, Protocol::Udp);
    }
}
