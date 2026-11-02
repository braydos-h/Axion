use serde::{Deserialize, Serialize};

/// Metadata is visible in a ClientHello; it does not establish protocol identity.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct TlsInfo {
    pub version: Option<String>,
    pub sni: Option<String>,
    pub alpn: Vec<String>,
    pub cipher_suites: Vec<u16>,
    pub ja3: Option<String>,
}
fn u16_at(b: &[u8], p: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*b.get(p)?, *b.get(p + 1)?]))
}
fn take<'a>(b: &'a [u8], pos: &mut usize, len: usize) -> Option<&'a [u8]> {
    let end = pos.checked_add(len)?;
    let v = b.get(*pos..end)?;
    *pos = end;
    Some(v)
}
fn list16(b: &[u8]) -> Option<Vec<u16>> {
    if !b.len().is_multiple_of(2) {
        return None;
    }
    Some(
        b.as_chunks::<2>()
            .0
            .iter()
            .map(|x| u16::from_be_bytes([x[0], x[1]]))
            .collect(),
    )
}
fn grease(x: u16) -> bool {
    x & 0x0f0f == 0x0a0a && (x >> 8) == (x & 0xff)
}
fn join(nums: &[u16]) -> String {
    nums.iter()
        .filter(|&&n| !grease(n))
        .map(u16::to_string)
        .collect::<Vec<_>>()
        .join("-")
}
fn version(v: u16) -> Option<String> {
    match v {
        0x0301 => Some("1.0"),
        0x0302 => Some("1.1"),
        0x0303 => Some("1.2"),
        0x0304 => Some("1.3"),
        _ => None,
    }
    .map(str::to_owned)
}

/// Parse complete TLS records containing a ClientHello, including handshakes split
/// over several records. Incomplete or invalid input returns None.
pub fn parse_client_hello(records: &[u8]) -> Option<TlsInfo> {
    let mut pos = 0usize;
    let mut handshake = Vec::new();
    while pos + 5 <= records.len() {
        let typ = records[pos];
        let len = u16_at(records, pos + 3)? as usize;
        let body = records.get(pos + 5..pos.checked_add(5 + len)?)?;
        if typ != 22 {
            return None;
        }
        if handshake.len() + body.len() > 65536 {
            return None;
        }
        handshake.extend_from_slice(body);
        if handshake.len() >= 4 {
            if handshake[0] != 1 {
                return None;
            }
            let n = ((handshake[1] as usize) << 16)
                | ((handshake[2] as usize) << 8)
                | handshake[3] as usize;
            if n > 65532 {
                return None;
            }
            if handshake.len() >= n + 4 {
                return parse_body(&handshake[4..n + 4]);
            }
        }
        pos += 5 + len;
    }
    None
}
fn parse_body(b: &[u8]) -> Option<TlsInfo> {
    let legacy = u16_at(b, 0)?;
    let mut pos = 34;
    let session_len = *take(b, &mut pos, 1)?.first()? as usize;
    take(b, &mut pos, session_len)?;
    let len = u16_at(b, pos)? as usize;
    pos += 2;
    let ciphers = list16(take(b, &mut pos, len)?)?;
    let comp_len = *take(b, &mut pos, 1)?.first()? as usize;
    take(b, &mut pos, comp_len)?;
    let mut result = TlsInfo {
        version: version(legacy),
        cipher_suites: ciphers.clone(),
        ..Default::default()
    };
    let mut extensions = Vec::new();
    let mut groups = Vec::new();
    let mut points = Vec::new();
    if pos < b.len() {
        let total = u16_at(b, pos)? as usize;
        pos += 2;
        let ext = take(b, &mut pos, total)?;
        let mut i = 0;
        while i < ext.len() {
            let typ = u16_at(ext, i)?;
            let n = u16_at(ext, i + 2)? as usize;
            i += 4;
            let data = take(ext, &mut i, n)?;
            extensions.push(typ);
            match typ {
                0 if data.len() >= 5 => {
                    let l = u16_at(data, 3)? as usize;
                    if data[2] == 0 {
                        result.sni = std::str::from_utf8(data.get(5..5 + l)?)
                            .ok()
                            .map(str::to_owned);
                    }
                }
                16 if data.len() >= 2 => {
                    let mut j = 2;
                    while j < data.len() {
                        let n = *take(data, &mut j, 1)?.first()? as usize;
                        let name = take(data, &mut j, n)?;
                        if let Ok(s) = std::str::from_utf8(name) {
                            result.alpn.push(s.to_owned());
                        }
                    }
                }
                10 if data.len() >= 2 => {
                    let n = u16_at(data, 0)? as usize;
                    groups = list16(data.get(2..2 + n)?)?;
                }
                11 if !data.is_empty() => {
                    let n = data[0] as usize;
                    points = data.get(1..1 + n)?.iter().map(|&v| v as u16).collect();
                }
                43 if !data.is_empty() => {
                    let n = data[0] as usize;
                    let versions = list16(data.get(1..1 + n)?)?;
                    if let Some(max) = versions.into_iter().filter(|v| !grease(*v)).max() {
                        result.version = version(max).or(result.version);
                    }
                }
                _ => {}
            }
        }
    }
    let ja3 = format!(
        "{},{},{},{},{}",
        legacy,
        join(&ciphers),
        join(&extensions),
        join(&groups),
        join(&points)
    );
    result.ja3 = Some(format!("{:x}", md5::compute(ja3.as_bytes())));
    Some(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parses_client_hello_metadata_and_ja3() {
        fn ext(buf: &mut Vec<u8>, typ: u16, value: &[u8]) {
            buf.extend(typ.to_be_bytes());
            buf.extend((value.len() as u16).to_be_bytes());
            buf.extend(value);
        }
        let mut extensions = Vec::new();
        ext(
            &mut extensions,
            0,
            &[
                0, 14, 0, 0, 11, b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'.', b'c', b'o', b'm',
            ],
        );
        ext(&mut extensions, 10, &[0, 4, 0, 29, 0, 23]);
        ext(&mut extensions, 11, &[1, 0]);
        ext(&mut extensions, 16, &[0, 3, 2, b'h', b'2']);
        ext(&mut extensions, 43, &[2, 3, 4]);
        let mut body = vec![3, 3];
        body.extend([0; 32]);
        body.extend([0, 0, 4, 0x13, 1, 0x13, 2, 1, 0]);
        body.extend((extensions.len() as u16).to_be_bytes());
        body.extend(extensions);
        let mut handshake = vec![1, 0, 0, body.len() as u8];
        handshake.extend(body);
        let mut record = vec![22, 3, 3, 0, handshake.len() as u8];
        record.extend(handshake);
        let result = parse_client_hello(&record).unwrap();
        assert_eq!(result.sni.as_deref(), Some("example.com"));
        assert_eq!(result.alpn, vec!["h2"]);
        assert_eq!(result.version.as_deref(), Some("1.3"));
        assert_eq!(
            result.ja3.as_deref(),
            Some("aa5ea15175fa394afa3d3d74845ef0ad")
        );
    }
    #[test]
    fn parses_split_records_and_rejects_truncation() {
        let mut body = vec![3, 3];
        body.extend([0; 32]);
        body.extend([0, 0, 2, 0x13, 1, 1, 0, 0, 0]);
        let mut handshake = vec![1, 0, 0, body.len() as u8];
        handshake.extend(body);
        let n = 10;
        let mut records = vec![22, 3, 3, 0, n as u8];
        records.extend(&handshake[..n]);
        records.extend([22, 3, 3, 0, (handshake.len() - n) as u8]);
        records.extend(&handshake[n..]);
        assert!(parse_client_hello(&records[..records.len() - 1]).is_none());
        let tls = parse_client_hello(&records).unwrap();
        assert_eq!(tls.cipher_suites, vec![0x1301]);
        assert!(tls.ja3.is_some());
    }
}
