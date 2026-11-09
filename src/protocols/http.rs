use serde::Serialize;

const MAX_HEADERS: usize = 64;
const MAX_HEADER_VALUE: usize = 8192;
const MAX_TARGET: usize = 4096;

#[derive(Debug, Clone, Serialize, Default)]
pub struct HttpInfo {
    pub is_request: bool,
    pub method: Option<String>,
    pub target: Option<String>,
    pub host: Option<String>,
    pub user_agent: Option<String>,
    pub version: Option<String>,
    pub status: Option<u16>,
    pub content_type: Option<String>,
    pub upgrade_websocket: bool,
    pub connect: bool,
    pub websocket: bool,
    pub header_count: usize,
    pub truncated: bool,
}

/// Parse an HTTP/1.x request or response header block.
pub fn parse_http(data: &[u8]) -> Option<HttpInfo> {
    if data.len() < 8 {
        return None;
    }
    let text = data.get(..data.len().min(64 * 1024))?;
    let mut lines = text.split(|b| *b == b'\n');
    let first = trim_cr(lines.next()?);
    if first.is_empty() {
        return None;
    }

    let mut info = HttpInfo::default();
    if first.starts_with(b"HTTP/") {
        // Response status line.
        let mut parts = first.splitn(3, |b| *b == b' ');
        let version = parts.next()?;
        if !matches!(version, b"HTTP/1.0" | b"HTTP/1.1") {
            return None;
        }
        let status = parts.next()?;
        if status.len() != 3 || !status.iter().all(u8::is_ascii_digit) {
            return None;
        }
        info.version = Some(String::from_utf8_lossy(version).into_owned());
        info.status = std::str::from_utf8(status).ok()?.parse().ok();
        info.is_request = false;
    } else {
        let mut parts = first.splitn(3, |b| *b == b' ');
        let method = parts.next()?;
        let target = parts.next()?;
        let version = parts.next()?;
        if method.is_empty()
            || method.len() > 16
            || !method.iter().all(|b| b.is_ascii_uppercase() || *b == b'-')
        {
            return None;
        }
        if !matches!(version, b"HTTP/1.0" | b"HTTP/1.1") {
            return None;
        }
        if target.is_empty() || target.len() > MAX_TARGET {
            return None;
        }
        info.is_request = true;
        info.method = Some(String::from_utf8_lossy(method).into_owned());
        info.target = Some(String::from_utf8_lossy(target).into_owned());
        info.version = Some(String::from_utf8_lossy(version).into_owned());
        info.connect = method == b"CONNECT";
        if info.connect {
            info.host = split_host_port(target);
        } else if target.starts_with(b"http://") || target.starts_with(b"https://") {
            info.host = absolute_uri_host(target);
        }
    }

    let mut complete = false;
    let mut connection_upgrade = false;
    for raw in lines.take(MAX_HEADERS) {
        let line = trim_cr(raw);
        if line.is_empty() {
            complete = true;
            break;
        }
        if line.len() > MAX_HEADER_VALUE {
            info.truncated = true;
            continue;
        }
        let Some(colon) = line.iter().position(|b| *b == b':') else {
            continue;
        };
        let name = &line[..colon];
        if name.is_empty()
            || name.len() > 64
            || !name.iter().all(|b| b.is_ascii_alphanumeric() || *b == b'-')
        {
            continue;
        }
        let value = trim_ascii(&line[colon + 1..]);
        if !value
            .iter()
            .all(|b| *b == b'\t' || (0x20..=0x7e).contains(b))
        {
            continue;
        }
        let name_lower = String::from_utf8_lossy(name).to_ascii_lowercase();
        let value_str = String::from_utf8_lossy(value);
        info.header_count += 1;
        match name_lower.as_str() {
            "host" => {
                if info.host.is_none() && value_str.len() <= 253 {
                    info.host = Some(
                        split_host_port(value)
                            .unwrap_or_else(|| value_str.trim().to_ascii_lowercase()),
                    );
                }
            }
            "user-agent" => {
                info.user_agent = Some(value_str.chars().take(256).collect());
            }
            "content-type" => {
                info.content_type = Some(value_str.chars().take(128).collect());
            }
            "upgrade" => {
                if value_str
                    .split(',')
                    .any(|v| v.trim().eq_ignore_ascii_case("websocket"))
                {
                    info.upgrade_websocket = true;
                }
            }
            "connection" => {
                if value_str
                    .split(',')
                    .any(|v| v.trim().eq_ignore_ascii_case("upgrade"))
                {
                    connection_upgrade = true;
                }
            }
            "sec-websocket-key" if info.upgrade_websocket => {
                info.websocket = true;
            }
            _ => {}
        }
    }
    if info.upgrade_websocket && connection_upgrade {
        info.websocket = true;
    }
    if !complete && info.header_count == 0 {
        return None;
    }
    if !complete {
        info.truncated = true;
    }
    Some(info)
}

fn split_host_port(value: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(value).ok()?.trim();
    if text.is_empty() || text.len() > 253 {
        return None;
    }
    let host = if let Some(rest) = text.strip_prefix('[') {
        let end = rest.find(']')?;
        &rest[..end]
    } else if let Some((h, p)) = text.rsplit_once(':') {
        if p.chars().all(|c| c.is_ascii_digit()) && text.matches(':').count() == 1 {
            h
        } else {
            text
        }
    } else {
        text
    };
    if host.is_empty() || host.len() > 253 {
        return None;
    }
    Some(host.to_ascii_lowercase())
}

fn absolute_uri_host(target: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(target).ok()?;
    let (_, rest) = text.split_once("://")?;
    let authority = rest.split(['/', '?', '#']).next()?;
    split_host_port(authority.as_bytes())
}

fn trim_cr(line: &[u8]) -> &[u8] {
    line.strip_suffix(b"\r").unwrap_or(line)
}

fn trim_ascii(mut value: &[u8]) -> &[u8] {
    while value.first().is_some_and(|b| b.is_ascii_whitespace()) {
        value = &value[1..];
    }
    while value.last().is_some_and(|b| b.is_ascii_whitespace()) {
        value = &value[..value.len() - 1];
    }
    value
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_connect_proxy_request() {
        let data = b"CONNECT www.example.com:443 HTTP/1.1\r\nHost: www.example.com:443\r\nUser-Agent: test\r\n\r\n";
        let info = parse_http(data).unwrap();
        assert!(info.connect);
        assert_eq!(info.method.as_deref(), Some("CONNECT"));
        assert_eq!(info.host.as_deref(), Some("www.example.com"));
    }

    #[test]
    fn parses_websocket() {
        let data = b"GET /chat HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n";
        let info = parse_http(data).unwrap();
        assert!(info.websocket);
        assert_eq!(info.host.as_deref(), Some("example.com"));
    }

    #[test]
    fn parses_response() {
        let info = parse_http(b"HTTP/1.1 204 No Content\r\n\r\n").unwrap();
        assert!(!info.is_request);
        assert_eq!(info.status, Some(204));
    }

    #[test]
    fn rejects_binary() {
        assert!(parse_http(&[0x16, 0x03, 0x01, 0x00, 0x00, 1, 2, 3]).is_none());
    }

    #[test]
    fn malformed_headers_ignored() {
        let info = parse_http(b"GET / HTTP/1.1\r\nBadHeader\r\nHost: example.com\r\n\r\n").unwrap();
        assert_eq!(info.host.as_deref(), Some("example.com"));
    }
}
