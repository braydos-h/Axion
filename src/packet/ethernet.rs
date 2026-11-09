use std::time::SystemTime;

use super::{ip, ParseError, ParseOutcome};

const ETHERTYPE_IPV4: u16 = 0x0800;
const ETHERTYPE_IPV6: u16 = 0x86dd;
const VLAN_TYPES: [u16; 4] = [0x8100, 0x88a8, 0x9100, 0x9200];

pub(super) fn parse(frame: &[u8], timestamp: Option<SystemTime>) -> ParseOutcome<'_> {
    if frame.len() < 14 {
        return ParseOutcome::Malformed(ParseError::Truncated("Ethernet header"));
    }
    let mut ethertype = u16::from_be_bytes([frame[12], frame[13]]);
    let mut offset = 14usize;
    let mut vlan = None;

    for _ in 0..3 {
        if !VLAN_TYPES.contains(&ethertype) {
            break;
        }
        if frame.len() < offset + 4 {
            return ParseOutcome::Malformed(ParseError::Truncated("VLAN header"));
        }
        let tci = u16::from_be_bytes([frame[offset], frame[offset + 1]]);
        vlan = Some(tci & 0x0fff);
        ethertype = u16::from_be_bytes([frame[offset + 2], frame[offset + 3]]);
        offset += 4;
    }

    if ethertype < 0x0600 {
        return ParseOutcome::Unsupported("IEEE 802.3 LLC frame");
    }

    let payload = match frame.get(offset..) {
        Some(p) => p,
        None => return ParseOutcome::Malformed(ParseError::Truncated("Ethernet payload")),
    };

    match ethertype {
        ETHERTYPE_IPV4 => ip::parse_v4(payload, timestamp, vlan),
        ETHERTYPE_IPV6 => ip::parse_v6(payload, timestamp, vlan),
        _ => ParseOutcome::Unsupported("non-IP EtherType"),
    }
}
