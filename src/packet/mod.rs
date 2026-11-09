//! Safe, bounded parsing of Ethernet, IPv4/IPv6, TCP, UDP and ICMP.
//!
//! The parser never panics on hostile input: every read is length-checked and
//! every variable-length field is capped. Fragment reassembly is intentionally
//! separate so callers can apply their own memory policy.

mod ethernet;
mod fragment;
mod ip;
pub mod pcap;
mod transport;

pub use fragment::{FragmentCache, FragmentKey};
pub use pcap::{LinkType, PcapReader, PcapRecord};

/// Parse a capture frame according to its pcap link type.
pub fn parse_link_frame(
    link_type: LinkType,
    data: &[u8],
    timestamp: Option<SystemTime>,
) -> ParseOutcome<'_> {
    match link_type {
        LinkType::Ethernet => parse_ethernet(data, timestamp),
        LinkType::RawIp => parse_l3(data, timestamp),
        LinkType::LinuxSll => {
            if data.len() < 16 {
                return ParseOutcome::Malformed(ParseError::Truncated("Linux SLL header"));
            }
            let proto = u16::from_be_bytes([data[14], data[15]]);
            match proto {
                0x0800 | 0x86dd => parse_l3(&data[16..], timestamp),
                _ => ParseOutcome::Unsupported("non-IP Linux SLL frame"),
            }
        }
        LinkType::LinuxSll2 => {
            if data.len() < 20 {
                return ParseOutcome::Malformed(ParseError::Truncated("Linux SLL2 header"));
            }
            let proto = u16::from_be_bytes([data[0], data[1]]);
            match proto {
                0x0800 | 0x86dd => parse_l3(&data[20..], timestamp),
                _ => ParseOutcome::Unsupported("non-IP Linux SLL2 frame"),
            }
        }
        LinkType::Null | LinkType::Loop => {
            if data.len() < 4 {
                return ParseOutcome::Malformed(ParseError::Truncated("loopback header"));
            }
            parse_l3(&data[4..], timestamp)
        }
    }
}
pub use transport::{TcpFlags, TcpSegment, UdpDatagram, L4};

use std::fmt;
use std::net::IpAddr;
use std::time::SystemTime;

/// Maximum IP packet size Axion will ever retain. IPv6 jumbograms are not
/// supported and are treated as truncated.
pub const MAX_IP_PACKET: usize = 65_535;

/// IP protocol number wrapper with readable formatting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct IpProtocol(pub u8);

impl IpProtocol {
    pub const ICMP: Self = Self(1);
    pub const TCP: Self = Self(6);
    pub const UDP: Self = Self(17);
    pub const ICMPV6: Self = Self(58);

    pub fn as_str(self) -> &'static str {
        match self.0 {
            1 => "icmp",
            6 => "tcp",
            17 => "udp",
            58 => "icmpv6",
            _ => "other",
        }
    }

    pub fn is_transport_port(self) -> bool {
        self == Self::TCP || self == Self::UDP
    }
}

impl fmt::Display for IpProtocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            1 => f.write_str("icmp"),
            6 => f.write_str("tcp"),
            17 => f.write_str("udp"),
            58 => f.write_str("icmpv6"),
            other => write!(f, "ip-{other}"),
        }
    }
}

impl serde::Serialize for IpProtocol {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

/// A fully parsed L3/L4 packet. Slices borrow from the capture buffer, so the
/// caller must finish processing before recycling it.
#[derive(Debug)]
pub struct PacketView<'a> {
    pub timestamp: Option<SystemTime>,
    pub src: IpAddr,
    pub dst: IpAddr,
    pub protocol: IpProtocol,
    pub ttl: u8,
    pub vlan: Option<u16>,
    pub l4: L4<'a>,
    /// Captured length was smaller than the length declared in the IP header.
    pub truncated: bool,
}

impl PacketView<'_> {
    pub fn src_port(&self) -> u16 {
        self.l4.src_port()
    }

    pub fn dst_port(&self) -> u16 {
        self.l4.dst_port()
    }

    pub fn payload(&self) -> &[u8] {
        self.l4.payload()
    }

    pub fn is_tcp(&self) -> bool {
        self.protocol == IpProtocol::TCP
    }

    pub fn is_udp(&self) -> bool {
        self.protocol == IpProtocol::UDP
    }
}

/// A packet that must be reassembled before L4 parsing.
#[derive(Debug)]
pub struct FragmentedView<'a> {
    pub timestamp: Option<SystemTime>,
    pub src: IpAddr,
    pub dst: IpAddr,
    pub protocol: IpProtocol,
    pub id: u32,
    pub offset: u32,
    pub more_fragments: bool,
    pub payload: &'a [u8],
    pub ipv6: bool,
}

/// Parse the transport header of a reassembled IP payload.
pub fn parse_reassembled(packet: &ReassembledPacket) -> ParseOutcome<'_> {
    match transport::parse(packet.protocol, &packet.payload, false) {
        Ok(l4) => {
            let protocol = l4.protocol();
            ParseOutcome::Packet(PacketView {
                timestamp: packet.timestamp,
                src: packet.src,
                dst: packet.dst,
                protocol,
                ttl: 0,
                vlan: None,
                l4,
                truncated: false,
            })
        }
        Err(err) => ParseOutcome::Malformed(err),
    }
}

/// Reassembled L3 payload (starts with the transport header).
#[derive(Debug)]
pub struct ReassembledPacket {
    pub timestamp: Option<SystemTime>,
    pub src: IpAddr,
    pub dst: IpAddr,
    pub protocol: IpProtocol,
    pub ipv6: bool,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseError {
    Malformed(&'static str),
    Truncated(&'static str),
    Unsupported(&'static str),
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParseError::Malformed(reason) => write!(f, "malformed packet: {reason}"),
            ParseError::Truncated(reason) => write!(f, "truncated packet: {reason}"),
            ParseError::Unsupported(reason) => write!(f, "unsupported packet: {reason}"),
        }
    }
}

impl std::error::Error for ParseError {}

#[derive(Debug)]
pub enum ParseOutcome<'a> {
    Packet(PacketView<'a>),
    Fragment(FragmentedView<'a>),
    Unsupported(&'static str),
    Malformed(ParseError),
}

/// Parse an Ethernet II frame, optionally with up to three VLAN tags.
pub fn parse_ethernet(frame: &[u8], timestamp: Option<SystemTime>) -> ParseOutcome<'_> {
    ethernet::parse(frame, timestamp)
}

/// Parse a raw IP packet, as delivered by NFQUEUE or a DLT_RAW capture.
pub fn parse_l3(buf: &[u8], timestamp: Option<SystemTime>) -> ParseOutcome<'_> {
    match buf.first().map(|b| b >> 4) {
        Some(4) => ip::parse_v4(buf, timestamp, None),
        Some(6) => ip::parse_v6(buf, timestamp, None),
        Some(_) => ParseOutcome::Malformed(ParseError::Malformed("unknown IP version")),
        None => ParseOutcome::Malformed(ParseError::Truncated("empty IP packet")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ipv4_tcp_frame(payload: &[u8]) -> Vec<u8> {
        let mut frame = vec![0u8; 14 + 20 + 20];
        frame[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
        let ip = &mut frame[14..34];
        ip[0] = 0x45;
        ip[2..4].copy_from_slice(&((20 + 20 + payload.len()) as u16).to_be_bytes());
        ip[8] = 64;
        ip[9] = 6;
        let tcp = &mut frame[34..54];
        tcp[12] = 0x50;
        tcp[13] = 0x18;
        frame.extend_from_slice(payload);
        frame
    }

    #[test]
    fn parses_ipv4_tcp() {
        let frame = ipv4_tcp_frame(b"hello");
        match parse_ethernet(&frame, None) {
            ParseOutcome::Packet(p) => {
                assert_eq!(p.protocol, IpProtocol::TCP);
                assert_eq!(p.payload(), b"hello");
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn rejects_short_frame() {
        assert!(matches!(
            parse_ethernet(&[0u8; 4], None),
            ParseOutcome::Malformed(_)
        ));
    }

    #[test]
    fn rejects_impossible_ihl() {
        let mut frame = ipv4_tcp_frame(b"");
        frame[14] = 0x44;
        assert!(matches!(
            parse_ethernet(&frame, None),
            ParseOutcome::Malformed(_)
        ));
    }

    #[test]
    fn vlan_is_transparent() {
        let mut frame = ipv4_tcp_frame(b"x");
        frame[12..14].copy_from_slice(&0x8100u16.to_be_bytes());
        frame.splice(14..14, [0x00, 0x64, 0x08, 0x00]);
        match parse_ethernet(&frame, None) {
            ParseOutcome::Packet(p) => {
                assert_eq!(p.vlan, Some(100));
                assert_eq!(p.payload(), b"x");
            }
            other => panic!("unexpected {other:?}"),
        }
    }
}
