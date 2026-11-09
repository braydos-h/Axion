use md5::{Digest, Md5};
use serde::Serialize;

use super::looks_like_tls_record;

/// Metadata extracted from a TLS ClientHello or ServerHello. No attempt is
/// made to decrypt application data.
#[derive(Debug, Clone, Serialize, Default)]
pub struct TlsInfo {
    pub handshake: String,
    pub record_version: u16,
    pub legacy_version: u16,
    pub negotiated_version: Option<u16>,
    pub sni: Option<String>,
    pub alpn: Vec<String>,
    pub cipher_suites: Vec<u16>,
    pub extensions: Vec<u16>,
    pub supported_groups: Vec<u16>,
    pub ec_point_formats: Vec<u8>,
    pub signature_algorithms: Vec<u16>,
    pub supported_versions: Vec<u16>,
    pub session_id_len: u8,
    pub key_share_groups: Vec<u16>,
    pub ech_present: bool,
    pub grease_count: usize,
    /// JA3-style canonical string. GREASE values are included.
    pub ja3: Option<String>,
    pub ja3_hash: Option<String>,
    pub truncated: bool,
    pub quic: bool,
}

pub fn tls_version_name(version: u16) -> &'static str {
    match version {
        0x0300 => "SSL 3.0",
        0x0301 => "TLS 1.0",
        0x0302 => "TLS 1.1",
        0x0303 => "TLS 1.2",
        0x0304 => "TLS 1.3",
        _ => "unknown",
    }
}

/// True when a plausible TLS handshake record is longer than the available
/// bytes. Used to trigger re-analysis as TCP reassembly grows.
pub fn tls_record_incomplete(data: &[u8]) -> bool {
    if data.len() < 5 || data[0] != 22 {
        return false;
    }
    let declared = u16::from_be_bytes([data[3], data[4]]) as usize;
    declared > data.len() - 5
}

/// Parse a TLS record carrying a ClientHello/ServerHello.
pub fn parse_tls(data: &[u8]) -> Option<TlsInfo> {
    if !looks_like_tls_record(data) || data[0] != 22 {
        return None;
    }
    let record_version = u16::from_be_bytes([data[1], data[2]]);
    let record_len = u16::from_be_bytes([data[3], data[4]]) as usize;
    let available = data.len() - 5;
    let take = record_len.min(available);
    let body = &data[5..5 + take];
    let record_truncated = record_len > available;
    parse_handshake(body, record_version, false, record_truncated)
}

/// Parse a ClientHello carried directly in QUIC CRYPTO frame data (there is no
/// TLS record layer).
pub fn parse_quic_client_hello(data: &[u8]) -> Option<TlsInfo> {
    parse_handshake(data, 0, true, false)
}

fn parse_handshake(
    data: &[u8],
    record_version: u16,
    quic: bool,
    record_truncated: bool,
) -> Option<TlsInfo> {
    if data.len() < 4 {
        return None;
    }
    let handshake_type = data[0];
    if handshake_type != 1 && handshake_type != 2 {
        return None;
    }
    let declared = u32::from_be_bytes([0, data[1], data[2], data[3]]) as usize;
    let available = data.len() - 4;
    let body = &data[4..4 + declared.min(available)];
    let truncated = record_truncated || declared > available;

    match handshake_type {
        1 => parse_client_hello(body, record_version, quic, truncated),
        2 => parse_server_hello(body, record_version, quic, truncated),
        _ => None,
    }
}

fn parse_client_hello(
    body: &[u8],
    record_version: u16,
    quic: bool,
    truncated: bool,
) -> Option<TlsInfo> {
    let mut cur = Cursor::new(body);
    let legacy_version = cur.u16()?;
    cur.take(32)?; // random
    let session_id_len = cur.u8()?;
    cur.take(session_id_len as usize)?;

    let cipher_len = cur.u16()? as usize;
    if cipher_len % 2 != 0 {
        return None;
    }
    let cipher_bytes = cur.take(cipher_len)?;
    let cipher_suites: Vec<u16> = cipher_bytes
        .chunks_exact(2)
        .map(|c| u16::from_be_bytes([c[0], c[1]]))
        .collect();

    let compression_len = cur.u8()? as usize;
    cur.take(compression_len)?;

    let mut info = TlsInfo {
        handshake: "client_hello".to_string(),
        record_version,
        legacy_version,
        session_id_len,
        cipher_suites,
        truncated,
        quic,
        ..Default::default()
    };

    if cur.remaining() == 0 {
        // A ClientHello without extensions is legal for very old clients.
        info.grease_count = count_grease(&info.cipher_suites);
        info.ja3 = Some(ja3_string(&info));
        info.ja3_hash = info.ja3.as_ref().map(|s| md5_hex(s.as_bytes()));
        return Some(info);
    }
    let ext_len = cur.u16()? as usize;
    if ext_len > cur.remaining() {
        info.truncated = true;
    }
    let ext_body = cur.take(ext_len.min(cur.remaining()))?;
    let mut exts = Cursor::new(ext_body);
    while exts.remaining() >= 4 {
        let ext_type = exts.u16()?;
        let len = exts.u16()? as usize;
        if len > exts.remaining() {
            info.truncated = true;
            break;
        }
        let value = exts.take(len)?;
        info.extensions.push(ext_type);
        match ext_type {
            0 => info.sni = parse_sni(value),
            10 => info.supported_groups = parse_u16_vec16(value),
            11 => info.ec_point_formats = parse_u8_vec8(value),
            13 => info.signature_algorithms = parse_u16_vec16(value),
            16 => info.alpn = parse_alpn(value),
            43 => info.supported_versions = parse_u16_vec8(value),
            51 => info.key_share_groups = parse_key_share_groups(value),
            0xfe0d => info.ech_present = true,
            _ => {}
        }
    }
    if exts.remaining() != 0 {
        info.truncated = true;
    }
    info.grease_count = count_grease(&info.cipher_suites)
        + count_grease(&info.extensions)
        + count_grease(&info.supported_groups);
    info.ja3 = Some(ja3_string(&info));
    info.ja3_hash = info.ja3.as_ref().map(|s| md5_hex(s.as_bytes()));
    Some(info)
}

fn parse_server_hello(
    body: &[u8],
    record_version: u16,
    quic: bool,
    truncated: bool,
) -> Option<TlsInfo> {
    let mut cur = Cursor::new(body);
    let legacy_version = cur.u16()?;
    cur.take(32)?;
    let session_id_len = cur.u8()?;
    cur.take(session_id_len as usize)?;
    let cipher = cur.u16()?;
    cur.u8()?; // compression method
    let mut info = TlsInfo {
        handshake: "server_hello".to_string(),
        record_version,
        legacy_version,
        session_id_len,
        cipher_suites: vec![cipher],
        truncated,
        quic,
        ..Default::default()
    };
    if cur.remaining() >= 2 {
        let ext_len = cur.u16()? as usize;
        if ext_len > cur.remaining() {
            info.truncated = true;
        }
        let ext_body = cur.take(ext_len.min(cur.remaining()))?;
        let mut exts = Cursor::new(ext_body);
        while exts.remaining() >= 4 {
            let ext_type = exts.u16()?;
            let len = exts.u16()? as usize;
            if len > exts.remaining() {
                info.truncated = true;
                break;
            }
            let value = exts.take(len)?;
            info.extensions.push(ext_type);
            match ext_type {
                16 => {
                    info.alpn = parse_alpn(value);
                }
                43 => {
                    let mut v = Cursor::new(value);
                    if let Some(version) = v.u16() {
                        info.negotiated_version = Some(version);
                    }
                }
                51 => info.key_share_groups = parse_key_share_groups(value),
                _ => {}
            }
        }
        if exts.remaining() != 0 {
            info.truncated = true;
        }
    }
    info.grease_count = count_grease(&info.extensions);
    Some(info)
}

fn parse_sni(value: &[u8]) -> Option<String> {
    let mut cur = Cursor::new(value);
    let list_len = cur.u16()? as usize;
    let list = cur.take(list_len.min(cur.remaining()))?;
    let mut entries = Cursor::new(list);
    while entries.remaining() >= 3 {
        let name_type = entries.u8()?;
        let name_len = entries.u16()? as usize;
        if name_len > entries.remaining() {
            return None;
        }
        let name = entries.take(name_len)?;
        if name_type == 0 {
            let text = std::str::from_utf8(name).ok()?;
            if valid_hostname(text) {
                return Some(text.to_ascii_lowercase());
            }
            return None;
        }
    }
    None
}

fn parse_alpn(value: &[u8]) -> Vec<String> {
    let mut cur = Cursor::new(value);
    let Some(list_len) = cur.u16().map(|v| v as usize) else {
        return Vec::new();
    };
    let Some(list) = cur.take(list_len.min(cur.remaining())) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    let mut entries = Cursor::new(list);
    while entries.remaining() >= 1 && out.len() < 16 {
        let Some(len) = entries.u8() else {
            break;
        };
        let Some(name) = entries.take(len as usize) else {
            break;
        };
        if !name.is_empty() && name.len() <= 255 && name.iter().all(|b| (0x20..=0x7e).contains(b)) {
            out.push(String::from_utf8_lossy(name).into_owned());
        }
    }
    out
}

fn parse_u16_vec16(value: &[u8]) -> Vec<u16> {
    let mut cur = Cursor::new(value);
    let Some(len) = cur.u16().map(|v| v as usize) else {
        return Vec::new();
    };
    let Some(body) = cur.take(len.min(cur.remaining())) else {
        return Vec::new();
    };
    body.chunks_exact(2)
        .map(|c| u16::from_be_bytes([c[0], c[1]]))
        .collect()
}

fn parse_u16_vec8(value: &[u8]) -> Vec<u16> {
    let mut cur = Cursor::new(value);
    let Some(len) = cur.u8().map(|v| v as usize) else {
        return Vec::new();
    };
    let Some(body) = cur.take(len.min(cur.remaining())) else {
        return Vec::new();
    };
    body.chunks_exact(2)
        .map(|c| u16::from_be_bytes([c[0], c[1]]))
        .collect()
}

fn parse_u8_vec8(value: &[u8]) -> Vec<u8> {
    let mut cur = Cursor::new(value);
    let Some(len) = cur.u8().map(|v| v as usize) else {
        return Vec::new();
    };
    cur.take(len.min(cur.remaining()))
        .map(|v| v.to_vec())
        .unwrap_or_default()
}

fn parse_key_share_groups(value: &[u8]) -> Vec<u16> {
    let mut cur = Cursor::new(value);
    let Some(len) = cur.u16().map(|v| v as usize) else {
        return Vec::new();
    };
    let Some(body) = cur.take(len.min(cur.remaining())) else {
        return Vec::new();
    };
    let mut inner = Cursor::new(body);
    let mut groups = Vec::new();
    while inner.remaining() >= 4 && groups.len() < 32 {
        let Some(group) = inner.u16() else {
            break;
        };
        let Some(key_len) = inner.u16().map(|v| v as usize) else {
            break;
        };
        if inner.take(key_len).is_none() {
            break;
        }
        groups.push(group);
    }
    groups
}

fn ja3_string(info: &TlsInfo) -> String {
    let join_u16 = |values: &[u16]| {
        values
            .iter()
            .map(|v| v.to_string())
            .collect::<Vec<_>>()
            .join("-")
    };
    format!(
        "{},{},{},{},{}",
        info.legacy_version,
        join_u16(&info.cipher_suites),
        join_u16(&info.extensions),
        join_u16(&info.supported_groups),
        info.ec_point_formats
            .iter()
            .map(|v| v.to_string())
            .collect::<Vec<_>>()
            .join("-")
    )
}

fn md5_hex(data: &[u8]) -> String {
    let digest = Md5::digest(data);
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

fn is_grease(value: u16) -> bool {
    value & 0x0f0f == 0x0a0a && value >> 8 == value & 0xff
}

fn count_grease(values: &[u16]) -> usize {
    values.iter().filter(|v| is_grease(**v)).count()
}

pub fn valid_hostname(host: &str) -> bool {
    if host.is_empty() || host.len() > 253 || !host.is_ascii() {
        return false;
    }
    if host.starts_with('.') || host.ends_with('.') {
        return false;
    }
    host.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
            && !label.starts_with('-')
            && !label.ends_with('-')
    })
}

struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.pos)
    }

    fn take(&mut self, len: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(len)?;
        if end > self.data.len() {
            return None;
        }
        let out = &self.data[self.pos..end];
        self.pos = end;
        Some(out)
    }

    fn u8(&mut self) -> Option<u8> {
        Some(*self.take(1)?.first()?)
    }

    fn u16(&mut self) -> Option<u16> {
        let b = self.take(2)?;
        Some(u16::from_be_bytes([b[0], b[1]]))
    }
}

#[cfg(test)]
mod tests {
    use super::super::test_utils::client_hello;
    use super::*;

    #[test]
    fn parses_client_hello_sni_and_alpn() {
        let record = client_hello("example.com", &["h2", "http/1.1"], 0x0304);
        let info = parse_tls(&record).expect("tls");
        assert_eq!(info.handshake, "client_hello");
        assert_eq!(info.sni.as_deref(), Some("example.com"));
        assert_eq!(info.alpn, vec!["h2", "http/1.1"]);
        assert_eq!(info.supported_versions, vec![0x0304]);
        assert!(!info.ja3_hash.unwrap().is_empty());
        assert!(!info.truncated);
    }

    #[test]
    fn rejects_non_tls() {
        assert!(parse_tls(b"GET / HTTP/1.1\r\n").is_none());
    }

    #[test]
    fn malformed_lengths_do_not_panic() {
        let mut record = client_hello("example.com", &["h2"], 0x0304);
        record[3..5].copy_from_slice(&18000u16.to_be_bytes());
        let info = parse_tls(&record).expect("still recognisably TLS");
        assert!(info.truncated);
        for i in 0..record.len() {
            let _ = parse_tls(&record[..i]);
        }
    }

    #[test]
    fn valid_hostnames() {
        assert!(valid_hostname("www.example.com"));
        assert!(valid_hostname("a-b.example"));
        assert!(!valid_hostname(""));
        assert!(!valid_hostname("-bad.example"));
        assert!(!valid_hostname("bad..example"));
        assert!(!valid_hostname("exa mple.com"));
    }

    #[test]
    fn quic_handshake_parses() {
        let record = client_hello("quic.example", &["h3"], 0x0304);
        let handshake = &record[5..];
        let info = parse_quic_client_hello(handshake).expect("quic hello");
        assert!(info.quic);
        assert_eq!(info.sni.as_deref(), Some("quic.example"));
        assert_eq!(info.alpn, vec!["h3"]);
    }
}
