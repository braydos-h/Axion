use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::SystemTime;

use super::{transport, FragmentedView, IpProtocol, PacketView, ParseError, ParseOutcome};

pub(super) fn parse_v4(
    buf: &[u8],
    timestamp: Option<SystemTime>,
    vlan: Option<u16>,
) -> ParseOutcome<'_> {
    if buf.len() < 20 {
        return ParseOutcome::Malformed(ParseError::Truncated("IPv4 header"));
    }
    if buf[0] >> 4 != 4 {
        return ParseOutcome::Malformed(ParseError::Malformed("IPv4 version mismatch"));
    }
    let ihl = (buf[0] & 0x0f) as usize * 4;
    if ihl < 20 {
        return ParseOutcome::Malformed(ParseError::Malformed("IPv4 IHL below minimum"));
    }
    if buf.len() < ihl {
        return ParseOutcome::Malformed(ParseError::Truncated("IPv4 options"));
    }
    let total_len = u16::from_be_bytes([buf[2], buf[3]]) as usize;
    if total_len < ihl {
        return ParseOutcome::Malformed(ParseError::Malformed("IPv4 total length below IHL"));
    }
    let truncated = total_len > buf.len();
    let end = total_len.min(buf.len());
    let protocol = IpProtocol(buf[9]);
    let ttl = buf[8];
    let src = IpAddr::V4(Ipv4Addr::new(buf[12], buf[13], buf[14], buf[15]));
    let dst = IpAddr::V4(Ipv4Addr::new(buf[16], buf[17], buf[18], buf[19]));

    let flags_frag = u16::from_be_bytes([buf[6], buf[7]]);
    let more_fragments = flags_frag & 0x2000 != 0;
    let frag_offset = ((flags_frag & 0x1fff) as u32) * 8;
    let payload = &buf[ihl..end];

    if more_fragments || frag_offset != 0 {
        if frag_offset as usize > super::MAX_IP_PACKET {
            return ParseOutcome::Malformed(ParseError::Malformed(
                "IPv4 fragment offset out of range",
            ));
        }
        return ParseOutcome::Fragment(FragmentedView {
            timestamp,
            src,
            dst,
            protocol,
            id: u16::from_be_bytes([buf[4], buf[5]]) as u32,
            offset: frag_offset,
            more_fragments,
            payload,
            ipv6: false,
        });
    }

    match transport::parse(protocol, payload, truncated) {
        Ok(l4) => {
            let protocol = l4.protocol();
            ParseOutcome::Packet(PacketView {
                timestamp,
                src,
                dst,
                protocol,
                ttl,
                vlan,
                l4,
                truncated,
            })
        }
        Err(err) => ParseOutcome::Malformed(err),
    }
}

pub(super) fn parse_v6(
    buf: &[u8],
    timestamp: Option<SystemTime>,
    vlan: Option<u16>,
) -> ParseOutcome<'_> {
    if buf.len() < 40 {
        return ParseOutcome::Malformed(ParseError::Truncated("IPv6 header"));
    }
    if buf[0] >> 4 != 6 {
        return ParseOutcome::Malformed(ParseError::Malformed("IPv6 version mismatch"));
    }
    let payload_len = u16::from_be_bytes([buf[4], buf[5]]) as usize;
    if payload_len == 0 {
        return ParseOutcome::Unsupported("IPv6 jumbogram");
    }
    let declared = 40usize.saturating_add(payload_len);
    let truncated = declared > buf.len();
    let end = declared.min(buf.len());
    let ttl = buf[7];
    let mut src_bytes = [0u8; 16];
    src_bytes.copy_from_slice(&buf[8..24]);
    let mut dst_bytes = [0u8; 16];
    dst_bytes.copy_from_slice(&buf[24..40]);
    let src = IpAddr::V6(Ipv6Addr::from(src_bytes));
    let dst = IpAddr::V6(Ipv6Addr::from(dst_bytes));
    let mut next = buf[6];
    let mut offset = 40usize;

    for _ in 0..8 {
        match next {
            0 | 43 | 60 => {
                // Hop-by-Hop, Routing, Destination Options.
                if offset + 2 > end {
                    return ParseOutcome::Malformed(ParseError::Truncated("IPv6 extension header"));
                }
                let ext_len = (buf[offset + 1] as usize + 1) * 8;
                if offset + ext_len > end {
                    return ParseOutcome::Malformed(ParseError::Truncated(
                        "IPv6 extension header body",
                    ));
                }
                next = buf[offset];
                offset += ext_len;
            }
            51 => {
                // Authentication Header: length is in 4-byte units, minus 2.
                if offset + 2 > end {
                    return ParseOutcome::Malformed(ParseError::Truncated("IPv6 AH header"));
                }
                let ext_len = (buf[offset + 1] as usize + 2) * 4;
                if offset + ext_len > end {
                    return ParseOutcome::Malformed(ParseError::Truncated("IPv6 AH body"));
                }
                next = buf[offset];
                offset += ext_len;
            }
            44 => {
                if offset + 8 > end {
                    return ParseOutcome::Malformed(ParseError::Truncated("IPv6 fragment header"));
                }
                let frag_next = buf[offset];
                let word = u16::from_be_bytes([buf[offset + 2], buf[offset + 3]]);
                let frag_offset = ((word >> 3) as u32) * 8;
                let more = word & 1 != 0;
                let id = u32::from_be_bytes([
                    buf[offset + 4],
                    buf[offset + 5],
                    buf[offset + 6],
                    buf[offset + 7],
                ]);
                let payload = &buf[offset + 8..end];
                if frag_offset != 0 || more {
                    return ParseOutcome::Fragment(FragmentedView {
                        timestamp,
                        src,
                        dst,
                        protocol: IpProtocol(frag_next),
                        id,
                        offset: frag_offset,
                        more_fragments: more,
                        payload,
                        ipv6: true,
                    });
                }
                next = frag_next;
                offset += 8;
            }
            50 => return ParseOutcome::Unsupported("IPv6 ESP payload"),
            59 => return ParseOutcome::Unsupported("IPv6 no-next-header"),
            _ => break,
        }
    }

    if offset > end {
        return ParseOutcome::Malformed(ParseError::Truncated("IPv6 payload"));
    }
    let protocol = IpProtocol(next);
    match transport::parse(protocol, &buf[offset..end], truncated) {
        Ok(l4) => {
            let protocol = l4.protocol();
            ParseOutcome::Packet(PacketView {
                timestamp,
                src,
                dst,
                protocol,
                ttl,
                vlan,
                l4,
                truncated,
            })
        }
        Err(err) => ParseOutcome::Malformed(err),
    }
}

#[cfg(test)]
mod tests {
    use super::super::{parse_ethernet, ParseOutcome, L4};

    fn ipv4_udp(payload: &[u8]) -> Vec<u8> {
        let mut ip = vec![0u8; 28];
        ip[0] = 0x45;
        ip[2..4].copy_from_slice(&((28 + payload.len()) as u16).to_be_bytes());
        ip[8] = 64;
        ip[9] = 17;
        ip[12..16].copy_from_slice(&[192, 0, 2, 1]);
        ip[16..20].copy_from_slice(&[198, 51, 100, 2]);
        ip[20..22].copy_from_slice(&1234u16.to_be_bytes());
        ip[22..24].copy_from_slice(&53u16.to_be_bytes());
        ip[24..26].copy_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
        ip.extend_from_slice(payload);
        let mut frame = vec![0u8; 14];
        frame[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
        frame.extend_from_slice(&ip);
        frame
    }

    #[test]
    fn parses_udp() {
        let frame = ipv4_udp(b"dns");
        match parse_ethernet(&frame, None) {
            ParseOutcome::Packet(p) => {
                assert_eq!(p.src_port(), 1234);
                assert_eq!(p.dst_port(), 53);
                assert!(matches!(p.l4, L4::Udp(_)));
                assert_eq!(p.payload(), b"dns");
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn truncated_udp_is_still_bounded() {
        let mut frame = ipv4_udp(b"hello");
        // Increase the IPv4 total length beyond the captured size.
        frame[16..18].copy_from_slice(&200u16.to_be_bytes());
        match parse_ethernet(&frame, None) {
            ParseOutcome::Packet(p) => {
                assert!(p.truncated);
                assert_eq!(p.payload(), b"hello");
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn ipv4_fragment_is_detected() {
        let mut frame = ipv4_udp(b"abcdefgh");
        frame[14 + 6] = 0x20; // MF
        match parse_ethernet(&frame, None) {
            ParseOutcome::Fragment(f) => {
                assert!(f.more_fragments);
                assert_eq!(f.offset, 0);
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    fn ipv6_fragment_frame(offset: u16, more: bool, payload: &[u8]) -> Vec<u8> {
        let mut frame = vec![0u8; 14 + 40 + 8];
        frame[12..14].copy_from_slice(&0x86ddu16.to_be_bytes());
        let ip = &mut frame[14..54];
        ip[0] = 0x60;
        ip[4..6].copy_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
        ip[6] = 44; // Fragment header
        ip[7] = 64;
        ip[8..24].copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        ip[24..40].copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
        let frag = &mut frame[54..62];
        frag[0] = 17; // UDP
        let word = ((offset / 8) << 3) | if more { 1 } else { 0 };
        frag[2..4].copy_from_slice(&word.to_be_bytes());
        frag[4..8].copy_from_slice(&0x1234u32.to_be_bytes());
        frame.extend_from_slice(payload);
        frame
    }

    #[test]
    fn ipv6_fragments_reassemble() {
        use crate::packet::{parse_reassembled, FragmentCache, ParseOutcome};
        use std::time::{Duration, Instant};
        let udp = [
            0x30, 0x39, 0x00, 0x35, 0x00, 0x0d, 0x00, 0x00, b'h', b'e', b'l', b'l', b'o',
        ];
        let mut cache = FragmentCache::new(8, 1 << 20, Duration::from_secs(30));
        let now = Instant::now();
        let second = ipv6_fragment_frame(8, false, &udp[8..]);
        let first = ipv6_fragment_frame(0, true, &udp[..8]);
        let ParseOutcome::Fragment(second) = parse_ethernet(&second, None) else {
            panic!("expected second IPv6 fragment");
        };
        assert!(cache.insert(&second, now).is_none());
        let ParseOutcome::Fragment(first) = parse_ethernet(&first, None) else {
            panic!("expected first IPv6 fragment");
        };
        let complete = cache.insert(&first, now).expect("reassembled");
        assert_eq!(complete.protocol, super::super::IpProtocol::UDP);
        let ParseOutcome::Packet(packet) = parse_reassembled(&complete) else {
            panic!("expected reassembled UDP packet");
        };
        assert_eq!(packet.src_port(), 12345);
        assert_eq!(packet.dst_port(), 53);
        assert_eq!(packet.payload(), b"hello");
    }

    #[test]
    fn ipv6_tcp_is_parsed() {
        let mut frame = vec![0u8; 14 + 40 + 20];
        frame[12..14].copy_from_slice(&0x86ddu16.to_be_bytes());
        let ip = &mut frame[14..54];
        ip[0] = 0x60;
        ip[4..6].copy_from_slice(&20u16.to_be_bytes());
        ip[6] = 6;
        ip[7] = 64;
        ip[8..24].copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        ip[24..40].copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
        let tcp = &mut frame[54..74];
        tcp[0..2].copy_from_slice(&5555u16.to_be_bytes());
        tcp[2..4].copy_from_slice(&443u16.to_be_bytes());
        tcp[12] = 0x50;
        tcp[13] = 0x02;
        match parse_ethernet(&frame, None) {
            ParseOutcome::Packet(p) => {
                assert_eq!(p.dst_port(), 443);
                assert!(p.is_tcp());
            }
            other => panic!("unexpected {other:?}"),
        }
    }
}
