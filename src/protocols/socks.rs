use serde::Serialize;

#[derive(Debug, Clone, Serialize, Default)]
pub struct SocksInfo {
    pub version: u8,
    pub stage: String,
    pub command: Option<u8>,
    pub address: Option<String>,
    pub port: Option<u16>,
    pub methods: Vec<u8>,
}

/// Parse SOCKS4/4a and SOCKS5 client-side handshakes. The parser accepts a
/// greeting-only buffer (the most common first segment) as well as a combined
/// greeting+request buffer.
pub fn parse_socks(data: &[u8], tcp: bool) -> Option<SocksInfo> {
    if data.is_empty() {
        return None;
    }
    if tcp {
        match data[0] {
            4 => parse_socks4(data),
            5 => parse_socks5(data),
            _ => None,
        }
    } else {
        parse_socks5_udp(data)
    }
}

fn parse_socks5(data: &[u8]) -> Option<SocksInfo> {
    if data.len() < 3 || data[1] == 0 || data[1] > 16 {
        return None;
    }
    let n = data[1] as usize;
    if data.len() < 2 + n {
        return None;
    }
    let methods = data[2..2 + n].to_vec();
    let mut info = SocksInfo {
        version: 5,
        stage: "greeting".to_string(),
        methods,
        ..Default::default()
    };
    let offset = 2 + n;
    if data.len() <= offset {
        return Some(info);
    }
    let req = &data[offset..];
    if req.len() < 4 || req[0] != 5 || !(1..=3).contains(&req[1]) || req[2] != 0 {
        // A short/malformed request after a valid greeting is still a strong
        // SOCKS5 signal; return the greeting stage.
        return Some(info);
    }
    let cmd = req[1];
    let (address, port, consumed) = parse_address(&req[3..])?;
    let _ = consumed;
    info.stage = "request".to_string();
    info.command = Some(cmd);
    info.address = Some(address);
    info.port = Some(port);
    Some(info)
}

fn parse_socks4(data: &[u8]) -> Option<SocksInfo> {
    if data.len() < 9 || data[0] != 4 || !(1..=2).contains(&data[1]) {
        return None;
    }
    let port = u16::from_be_bytes([data[2], data[3]]);
    let ip = [data[4], data[5], data[6], data[7]];
    let user_end = data[8..]
        .iter()
        .position(|b| *b == 0)
        .map(|p| 8 + p)
        .unwrap_or(data.len());
    if user_end >= data.len() {
        return Some(SocksInfo {
            version: 4,
            stage: "request".to_string(),
            command: Some(data[1]),
            ..Default::default()
        });
    }
    let user = &data[8..user_end];
    let _ = user;
    let mut address = format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3]);
    let after = &data[user_end + 1..];
    // SOCKS4a: 0.0.0.x with x != 0 carries a hostname.
    if ip[0] == 0 && ip[1] == 0 && ip[2] == 0 && ip[3] != 0 {
        let end = after.iter().position(|b| *b == 0)?;
        let host = &after[..end];
        if host.is_empty() || host.len() > 253 {
            return None;
        }
        address = String::from_utf8_lossy(host).to_ascii_lowercase();
    }
    Some(SocksInfo {
        version: 4,
        stage: "request".to_string(),
        command: Some(data[1]),
        address: Some(address),
        port: Some(port),
        ..Default::default()
    })
}

fn parse_socks5_udp(data: &[u8]) -> Option<SocksInfo> {
    if data.len() < 4 || data[0] != 0 || data[1] != 0 || data[2] != 0 {
        return None;
    }
    let (address, port, _) = parse_address(&data[3..])?;
    Some(SocksInfo {
        version: 5,
        stage: "udp".to_string(),
        command: Some(3),
        address: Some(address),
        port: Some(port),
        ..Default::default()
    })
}

fn parse_address(buf: &[u8]) -> Option<(String, u16, usize)> {
    let atyp = *buf.first()?;
    match atyp {
        1 => {
            if buf.len() < 7 {
                return None;
            }
            let address = format!("{}.{}.{}.{}", buf[1], buf[2], buf[3], buf[4]);
            let port = u16::from_be_bytes([buf[5], buf[6]]);
            Some((address, port, 7))
        }
        3 => {
            if buf.len() < 2 {
                return None;
            }
            let len = buf[1] as usize;
            if len == 0 || buf.len() < 2 + len + 2 {
                return None;
            }
            let host = &buf[2..2 + len];
            if host.is_empty()
                || host.len() > 253
                || !host
                    .iter()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
            {
                return None;
            }
            let port_at = 2 + len;
            let port = u16::from_be_bytes([buf[port_at], buf[port_at + 1]]);
            Some((
                String::from_utf8_lossy(host).to_ascii_lowercase(),
                port,
                port_at + 2,
            ))
        }
        4 => {
            if buf.len() < 19 {
                return None;
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&buf[1..17]);
            let port = u16::from_be_bytes([buf[17], buf[18]]);
            Some((std::net::Ipv6Addr::from(octets).to_string(), port, 19))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn socks5_greeting_only() {
        let info = parse_socks(&[5, 2, 0, 2], true).unwrap();
        assert_eq!(info.stage, "greeting");
        assert_eq!(info.methods, vec![0, 2]);
    }

    #[test]
    fn socks5_greeting_and_domain_request() {
        let mut data = vec![5, 1, 0];
        data.extend_from_slice(&[5, 1, 0, 3, 11]);
        data.extend_from_slice(b"example.com");
        data.extend_from_slice(&443u16.to_be_bytes());
        let info = parse_socks(&data, true).unwrap();
        assert_eq!(info.stage, "request");
        assert_eq!(info.command, Some(1));
        assert_eq!(info.address.as_deref(), Some("example.com"));
        assert_eq!(info.port, Some(443));
    }

    #[test]
    fn socks4a() {
        let mut data = vec![4, 1, 0, 80, 0, 0, 0, 1, b'u', b's', b'e', b'r', 0];
        data.extend_from_slice(b"example.org\0");
        let info = parse_socks(&data, true).unwrap();
        assert_eq!(info.address.as_deref(), Some("example.org"));
        assert_eq!(info.port, Some(80));
    }

    #[test]
    fn rejects_bad_version() {
        assert!(parse_socks(&[3, 1, 2], true).is_none());
    }
}
