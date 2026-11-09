use serde::Serialize;

pub const H2_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

#[derive(Debug, Clone, Serialize, Default)]
pub struct Http2Info {
    pub preface: bool,
    pub settings_seen: bool,
    pub frame_count: usize,
    pub frame_types: Vec<u8>,
    pub grpc_hint: bool,
    pub truncated: bool,
}

/// Recognise HTTP/2 from the connection preface or a leading SETTINGS frame.
/// HPACK is not decoded; gRPC detection is a bounded literal-string hint.
pub fn parse_http2(data: &[u8]) -> Option<Http2Info> {
    let (preface, mut offset) = if data.starts_with(H2_PREFACE) {
        (true, H2_PREFACE.len())
    } else {
        (false, 0usize)
    };
    if data.len() < offset + 9 {
        return None;
    }

    let mut info = Http2Info {
        preface,
        ..Default::default()
    };
    let mut first = true;
    while offset + 9 <= data.len() && info.frame_count < 64 {
        let len =
            u32::from_be_bytes([0, data[offset], data[offset + 1], data[offset + 2]]) as usize;
        let frame_type = data[offset + 3];
        let stream_id = u32::from_be_bytes([
            data[offset + 5],
            data[offset + 6],
            data[offset + 7],
            data[offset + 8],
        ]) & 0x7fff_ffff;
        if len > 16 * 1024 * 1024 {
            return None;
        }
        if first && !preface {
            // Without the preface require the first frame to be SETTINGS
            // (type 4, stream 0, length a multiple of 6).
            if frame_type != 4 || stream_id != 0 || len % 6 != 0 {
                return None;
            }
        }
        first = false;
        if frame_type == 4 && stream_id == 0 {
            info.settings_seen = true;
        }
        info.frame_types.push(frame_type);
        info.frame_count += 1;
        if offset + 9 + len > data.len() {
            info.truncated = true;
            break;
        }
        offset += 9 + len;
    }
    if !preface && !info.settings_seen {
        return None;
    }

    let haystack = &data[..data.len().min(64 * 1024)];
    info.grpc_hint = contains(haystack, b"application/grpc");
    Some(info)
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || haystack.len() < needle.len() {
        return false;
    }
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_preface_and_settings() {
        let mut data = H2_PREFACE.to_vec();
        data.extend_from_slice(&[0, 0, 0, 4, 0, 0, 0, 0, 0]); // empty SETTINGS
        let info = parse_http2(&data).unwrap();
        assert!(info.preface);
        assert!(info.settings_seen);
    }

    #[test]
    fn detects_server_side_settings() {
        let data = [0, 0, 6, 4, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0];
        let info = parse_http2(&data).unwrap();
        assert!(!info.preface);
        assert!(info.settings_seen);
    }

    #[test]
    fn rejects_random_data() {
        assert!(parse_http2(b"GET / HTTP/1.1\r\n\r\n").is_none());
    }

    #[test]
    fn grpc_literal_hint() {
        let mut data = H2_PREFACE.to_vec();
        data.extend_from_slice(&[0, 0, 0, 4, 0, 0, 0, 0, 0]);
        data.extend_from_slice(b"content-type: application/grpc");
        assert!(parse_http2(&data).unwrap().grpc_hint);
    }
}
