use super::{IpProtocol, ParseError};

/// Parsed layer-4 data. All slices borrow from the captured packet.
#[derive(Debug)]
pub enum L4<'a> {
    Tcp(TcpSegment<'a>),
    Udp(UdpDatagram<'a>),
    Icmp(IcmpMessage<'a>),
    Other {
        protocol: IpProtocol,
        payload: &'a [u8],
    },
}

impl L4<'_> {
    pub fn protocol(&self) -> IpProtocol {
        match self {
            L4::Tcp(_) => IpProtocol::TCP,
            L4::Udp(_) => IpProtocol::UDP,
            L4::Icmp(msg) if msg.v6 => IpProtocol::ICMPV6,
            L4::Icmp(_) => IpProtocol::ICMP,
            L4::Other { protocol, .. } => *protocol,
        }
    }

    pub fn src_port(&self) -> u16 {
        match self {
            L4::Tcp(tcp) => tcp.src_port,
            L4::Udp(udp) => udp.src_port,
            _ => 0,
        }
    }

    pub fn dst_port(&self) -> u16 {
        match self {
            L4::Tcp(tcp) => tcp.dst_port,
            L4::Udp(udp) => udp.dst_port,
            _ => 0,
        }
    }

    pub fn payload(&self) -> &[u8] {
        match self {
            L4::Tcp(tcp) => tcp.payload,
            L4::Udp(udp) => udp.payload,
            L4::Icmp(icmp) => icmp.payload,
            L4::Other { payload, .. } => payload,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TcpFlags(pub u8);

impl TcpFlags {
    pub const FIN: u8 = 0x01;
    pub const SYN: u8 = 0x02;
    pub const RST: u8 = 0x04;
    pub const PSH: u8 = 0x08;
    pub const ACK: u8 = 0x10;
    pub const URG: u8 = 0x20;
    pub const ECE: u8 = 0x40;
    pub const CWR: u8 = 0x80;

    pub fn syn(self) -> bool {
        self.0 & Self::SYN != 0
    }

    pub fn ack(self) -> bool {
        self.0 & Self::ACK != 0
    }

    pub fn fin(self) -> bool {
        self.0 & Self::FIN != 0
    }

    pub fn rst(self) -> bool {
        self.0 & Self::RST != 0
    }

    pub fn psh(self) -> bool {
        self.0 & Self::PSH != 0
    }

    pub fn contains(self, flag: u8) -> bool {
        self.0 & flag != 0
    }
}

#[derive(Debug)]
pub struct TcpSegment<'a> {
    pub src_port: u16,
    pub dst_port: u16,
    pub seq: u32,
    pub ack: u32,
    pub flags: TcpFlags,
    pub window: u16,
    pub payload: &'a [u8],
}

#[derive(Debug)]
pub struct UdpDatagram<'a> {
    pub src_port: u16,
    pub dst_port: u16,
    pub payload: &'a [u8],
}

#[derive(Debug)]
pub struct IcmpMessage<'a> {
    pub icmp_type: u8,
    pub code: u8,
    pub v6: bool,
    /// Bytes after the 4-byte ICMP base header.
    pub payload: &'a [u8],
}

pub(super) fn parse(
    protocol: IpProtocol,
    buf: &[u8],
    _ip_truncated: bool,
) -> Result<L4<'_>, ParseError> {
    match protocol {
        IpProtocol::TCP => parse_tcp(buf),
        IpProtocol::UDP => parse_udp(buf),
        IpProtocol::ICMP => parse_icmp(buf, false),
        IpProtocol::ICMPV6 => parse_icmp(buf, true),
        other => Ok(L4::Other {
            protocol: other,
            payload: buf,
        }),
    }
}

fn parse_tcp(buf: &[u8]) -> Result<L4<'_>, ParseError> {
    if buf.len() < 20 {
        return Err(ParseError::Truncated("TCP header"));
    }
    let data_offset = (buf[12] >> 4) as usize * 4;
    if data_offset < 20 {
        return Err(ParseError::Malformed("TCP data offset below minimum"));
    }
    if buf.len() < data_offset {
        return Err(ParseError::Truncated("TCP options"));
    }
    Ok(L4::Tcp(TcpSegment {
        src_port: u16::from_be_bytes([buf[0], buf[1]]),
        dst_port: u16::from_be_bytes([buf[2], buf[3]]),
        seq: u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]),
        ack: u32::from_be_bytes([buf[8], buf[9], buf[10], buf[11]]),
        flags: TcpFlags(buf[13]),
        window: u16::from_be_bytes([buf[14], buf[15]]),
        payload: &buf[data_offset..],
    }))
}

fn parse_udp(buf: &[u8]) -> Result<L4<'_>, ParseError> {
    if buf.len() < 8 {
        return Err(ParseError::Truncated("UDP header"));
    }
    let udp_len = u16::from_be_bytes([buf[4], buf[5]]) as usize;
    let end = if udp_len == 0 {
        // IPv6 jumbogram convention; use captured bytes.
        buf.len()
    } else if udp_len < 8 {
        return Err(ParseError::Malformed("UDP length below header size"));
    } else {
        udp_len.min(buf.len())
    };
    Ok(L4::Udp(UdpDatagram {
        src_port: u16::from_be_bytes([buf[0], buf[1]]),
        dst_port: u16::from_be_bytes([buf[2], buf[3]]),
        payload: &buf[8..end],
    }))
}

fn parse_icmp(buf: &[u8], v6: bool) -> Result<L4<'_>, ParseError> {
    if buf.len() < 4 {
        return Err(ParseError::Truncated("ICMP header"));
    }
    Ok(L4::Icmp(IcmpMessage {
        icmp_type: buf[0],
        code: buf[1],
        v6,
        payload: &buf[4..],
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tcp_flags() {
        let flags = TcpFlags(TcpFlags::SYN | TcpFlags::ACK);
        assert!(flags.syn());
        assert!(flags.ack());
        assert!(!flags.fin());
    }

    #[test]
    fn malformed_tcp_offset() {
        let buf = [0u8; 20];
        // data offset 0 is invalid
        assert!(parse_tcp(&buf).is_err());
    }

    #[test]
    fn udp_zero_length_uses_captured() {
        let mut buf = [0u8; 12];
        buf[4..6].copy_from_slice(&0u16.to_be_bytes());
        buf[8..].copy_from_slice(b"data");
        let L4::Udp(udp) = parse_udp(&buf).unwrap() else {
            panic!()
        };
        assert_eq!(udp.payload, b"data");
    }
}
