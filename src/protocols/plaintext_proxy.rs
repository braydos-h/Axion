use serde::Serialize;

use super::tls::valid_hostname;

#[derive(Debug, Clone, Serialize, Default)]
pub struct VlessInfo {
    pub version: u8,
    pub uuid: String,
    pub addons_len: usize,
    pub command: u8,
    pub port: u16,
    pub address: String,
    pub address_type: &'static str,
    pub uuid_v4_like: bool,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct TrojanInfo {
    pub command: u8,
    pub port: u16,
    pub address: String,
    pub address_type: &'static str,
}

/// Detect a plaintext VLESS request header.
///
/// VLESS is normally wrapped in TLS. This parser only succeeds when the header
/// is actually visible (misconfiguration, plaintext fallback, or a capture
/// taken after a terminating proxy). It does not claim to inspect encrypted
/// VLESS sessions.
pub fn parse_vless(data: &[u8]) -> Option<VlessInfo> {
    if data.len() < 24 || data[0] != 0 {
        return None;
    }
    let uuid = &data[1..17];
    if uuid.iter().all(|b| *b == 0) || uuid.iter().all(|b| *b == 0xff) {
        return None;
    }
    let addons_len = data[17] as usize;
    if addons_len > 64 {
        return None;
    }
    let mut pos = 18usize;
    if data.len() < pos + addons_len + 1 + 2 + 1 {
        return None;
    }
    pos += addons_len;
    let command = data[pos];
    if !(1..=3).contains(&command) {
        return None;
    }
    pos += 1;
    let port = u16::from_be_bytes([data[pos], data[pos + 1]]);
    if port == 0 {
        return None;
    }
    pos += 2;
    let atyp = data[pos];
    pos += 1;
    let (address, address_type) = match atyp {
        1 => {
            if data.len() < pos + 4 {
                return None;
            }
            let addr = format!(
                "{}.{}.{}.{}",
                data[pos],
                data[pos + 1],
                data[pos + 2],
                data[pos + 3]
            );
            (addr, "ipv4")
        }
        2 => {
            if data.len() < pos + 1 {
                return None;
            }
            let len = data[pos] as usize;
            pos += 1;
            if len == 0 || len > 253 || data.len() < pos + len {
                return None;
            }
            let host = std::str::from_utf8(&data[pos..pos + len]).ok()?;
            if !valid_hostname(host) {
                return None;
            }
            (host.to_ascii_lowercase(), "domain")
        }
        3 => {
            if data.len() < pos + 16 {
                return None;
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&data[pos..pos + 16]);
            (std::net::Ipv6Addr::from(octets).to_string(), "ipv6")
        }
        _ => return None,
    };
    let uuid_hex = uuid
        .iter()
        .enumerate()
        .fold(String::with_capacity(36), |mut out, (i, b)| {
            if matches!(i, 4 | 6 | 8 | 10) {
                out.push('-');
            }
            out.push_str(&format!("{b:02x}"));
            out
        });
    let uuid_v4_like = uuid[6] >> 4 == 4 && uuid[8] >> 6 == 2;
    Some(VlessInfo {
        version: data[0],
        uuid: uuid_hex,
        addons_len,
        command,
        port,
        address,
        address_type,
        uuid_v4_like,
    })
}

/// Detect a plaintext Trojan request header (56 hex password bytes + CRLF,
/// command, address, port, CRLF). Trojan over TLS is not visible to a passive
/// observer and is intentionally not claimed here.
pub fn parse_trojan(data: &[u8]) -> Option<TrojanInfo> {
    if data.len() < 56 + 2 + 1 + 1 + 2 + 2 {
        return None;
    }
    if !data[..56].iter().all(u8::is_ascii_hexdigit) {
        return None;
    }
    if &data[56..58] != b"\r\n" {
        return None;
    }
    let mut pos = 58usize;
    let command = data[pos];
    if command != 1 && command != 3 {
        return None;
    }
    pos += 1;
    let atyp = data[pos];
    pos += 1;
    let (address, address_type) = match atyp {
        1 => {
            if data.len() < pos + 4 + 2 + 2 {
                return None;
            }
            let addr = format!(
                "{}.{}.{}.{}",
                data[pos],
                data[pos + 1],
                data[pos + 2],
                data[pos + 3]
            );
            pos += 4;
            (addr, "ipv4")
        }
        3 => {
            if data.len() < pos + 1 {
                return None;
            }
            let len = data[pos] as usize;
            pos += 1;
            if len == 0 || len > 253 || data.len() < pos + len + 2 + 2 {
                return None;
            }
            let host = std::str::from_utf8(&data[pos..pos + len]).ok()?;
            if !valid_hostname(host) {
                return None;
            }
            pos += len;
            (host.to_ascii_lowercase(), "domain")
        }
        4 => {
            if data.len() < pos + 16 + 2 + 2 {
                return None;
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&data[pos..pos + 16]);
            pos += 16;
            (std::net::Ipv6Addr::from(octets).to_string(), "ipv6")
        }
        _ => return None,
    };
    let port = u16::from_be_bytes([data[pos], data[pos + 1]]);
    if port == 0 {
        return None;
    }
    pos += 2;
    if data.len() < pos + 2 || &data[pos..pos + 2] != b"\r\n" {
        return None;
    }
    Some(TrojanInfo {
        command,
        port,
        address,
        address_type,
    })
}

/// Shannon entropy in bits per byte, computed over at most 4096 bytes.
pub fn byte_entropy(data: &[u8]) -> f32 {
    if data.is_empty() {
        return 0.0;
    }
    let sample = &data[..data.len().min(4096)];
    let mut counts = [0u32; 256];
    for byte in sample {
        counts[*byte as usize] += 1;
    }
    let len = sample.len() as f32;
    let mut entropy = 0.0f32;
    for count in counts {
        if count > 0 {
            let p = count as f32 / len;
            entropy -= p * p.log2();
        }
    }
    entropy
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vless_request() -> Vec<u8> {
        let mut data = vec![0u8];
        // A v4-style UUID.
        data.extend_from_slice(&[
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x47, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
            0xff, 0x00,
        ]);
        data.push(0); // addons
        data.push(1); // command TCP
        data.extend_from_slice(&443u16.to_be_bytes());
        data.push(2); // domain
        data.push(11);
        data.extend_from_slice(b"example.com");
        data.extend_from_slice(b"payload");
        data
    }

    #[test]
    fn parses_vless() {
        let info = parse_vless(&vless_request()).unwrap();
        assert_eq!(info.port, 443);
        assert_eq!(info.address, "example.com");
        assert!(info.uuid_v4_like);
    }

    #[test]
    fn rejects_tls_as_vless() {
        let tls = super::super::test_utils::client_hello("example.com", &["h2"], 0x0304);
        assert!(parse_vless(&tls).is_none());
    }

    #[test]
    fn parses_trojan() {
        let mut data = vec![b'a'; 56];
        data.extend_from_slice(b"\r\n\x01\x03\x0bexample.com");
        data.extend_from_slice(&8443u16.to_be_bytes());
        data.extend_from_slice(b"\r\n");
        let info = parse_trojan(&data).unwrap();
        assert_eq!(info.port, 8443);
        assert_eq!(info.address, "example.com");
    }

    #[test]
    fn trojan_needs_hex_password() {
        let mut data = vec![b'z'; 56];
        data.extend_from_slice(b"\r\n\x01\x01\x01\x02\x03\x04");
        data.extend_from_slice(&80u16.to_be_bytes());
        data.extend_from_slice(b"\r\n");
        assert!(parse_trojan(&data).is_none());
    }

    #[test]
    fn entropy_bounds() {
        assert!(byte_entropy(b"aaaaaaaa") < 0.1);
        assert!(byte_entropy(&[0u8, 1, 2, 3, 4, 5, 6, 7]) > 2.0);
    }
}
