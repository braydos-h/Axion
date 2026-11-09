//! Incremental protocol parsers. Each parser is pure, bounded, and returns
//! `None`/an error rather than trusting lengths from the network.

pub mod dns;
pub mod http;
pub mod http2;
pub mod plaintext_proxy;
pub mod quic;
pub mod socks;
pub mod tls;

/// Protocol parsers never examine more than this many bytes of a single
/// direction. Flow reassembly additionally caps retained bytes.
pub const MAX_INSPECT_BYTES: usize = 64 * 1024;

/// True when `data` begins with a plausible TLS record header. This is a weak
/// signal by itself; handshake parsing is required for stronger conclusions.
pub fn looks_like_tls_record(data: &[u8]) -> bool {
    if data.len() < 5 {
        return false;
    }
    let content_type = data[0];
    let version = u16::from_be_bytes([data[1], data[2]]);
    let length = u16::from_be_bytes([data[3], data[4]]) as usize;
    matches!(content_type, 20..=23)
        && (0x0300..=0x0304).contains(&version)
        && length > 0
        && length <= 18_432
}

/// Deterministic protocol fixtures used by Axion's tests, benches and example
/// tooling. This module is deliberately small and has no external I/O.
#[doc(hidden)]
pub mod test_utils {
    /// Build a minimal but structurally valid TLS ClientHello.
    pub fn client_hello(sni: &str, alpn: &[&str], version: u16) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&0x0303u16.to_be_bytes()); // legacy_version
        body.extend_from_slice(&[0x11; 32]); // random
        body.push(32);
        body.extend_from_slice(&[0x22; 32]); // session id
        body.extend_from_slice(&4u16.to_be_bytes());
        body.extend_from_slice(&[0x13, 0x01, 0x13, 0x02]); // cipher suites
        body.push(1);
        body.push(0); // null compression

        let mut exts = Vec::new();
        // SNI
        let mut sni_ext = Vec::new();
        let mut names = Vec::new();
        names.extend_from_slice(&0u8.to_be_bytes()); // host_name
        names.extend_from_slice(&(sni.len() as u16).to_be_bytes());
        names.extend_from_slice(sni.as_bytes());
        sni_ext.extend_from_slice(&(names.len() as u16).to_be_bytes());
        sni_ext.extend_from_slice(&names);
        exts.extend_from_slice(&0u16.to_be_bytes());
        exts.extend_from_slice(&(sni_ext.len() as u16).to_be_bytes());
        exts.extend_from_slice(&sni_ext);

        // supported groups
        let groups = [0x001du16, 0x0017];
        exts.extend_from_slice(&10u16.to_be_bytes());
        exts.extend_from_slice(&4u16.to_be_bytes());
        for g in groups {
            exts.extend_from_slice(&g.to_be_bytes());
        }

        // ec point formats
        exts.extend_from_slice(&11u16.to_be_bytes());
        exts.extend_from_slice(&2u16.to_be_bytes());
        exts.extend_from_slice(&[1, 0]);

        // ALPN
        let mut alpn_ext = Vec::new();
        let mut proto_list = Vec::new();
        for p in alpn {
            proto_list.push(p.len() as u8);
            proto_list.extend_from_slice(p.as_bytes());
        }
        alpn_ext.extend_from_slice(&(proto_list.len() as u16).to_be_bytes());
        alpn_ext.extend_from_slice(&proto_list);
        exts.extend_from_slice(&16u16.to_be_bytes());
        exts.extend_from_slice(&(alpn_ext.len() as u16).to_be_bytes());
        exts.extend_from_slice(&alpn_ext);

        // supported versions
        exts.extend_from_slice(&43u16.to_be_bytes());
        exts.extend_from_slice(&3u16.to_be_bytes());
        exts.push(2);
        exts.extend_from_slice(&version.to_be_bytes());

        body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
        body.extend_from_slice(&exts);

        let mut handshake = Vec::new();
        handshake.push(1);
        let len = body.len() as u32;
        handshake.extend_from_slice(&len.to_be_bytes()[1..]);
        handshake.extend_from_slice(&body);

        let mut record = Vec::new();
        record.push(22);
        record.extend_from_slice(&0x0301u16.to_be_bytes());
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);
        record
    }
}
