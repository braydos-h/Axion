use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockEncrypt, KeyInit as BlockKeyInit};
use aes::Aes128;
use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes128Gcm, Nonce};
use hkdf::Hkdf;
use serde::Serialize;
use sha2::Sha256;

use super::tls::{parse_quic_client_hello, TlsInfo};

const QUIC_V1: u32 = 0x0000_0001;
const QUIC_V2: u32 = 0x6b33_43cf;
const V1_SALT: [u8; 20] = [
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
    0xcc, 0xbb, 0x7f, 0x0a,
];
const V2_SALT: [u8; 20] = [
    0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93, 0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb,
    0xf9, 0xbd, 0x2e, 0xd9,
];

#[derive(Debug, Clone, Serialize, Default)]
pub struct QuicInfo {
    pub version: u32,
    pub version_name: String,
    pub packet_type: u8,
    pub is_initial: bool,
    pub dcid: String,
    pub scid: String,
    pub token_len: usize,
    pub decrypted: bool,
    pub frames: Vec<String>,
    pub crypto_bytes: usize,
    pub client_hello: Option<TlsInfo>,
}

/// Inspect a QUIC long-header packet. Initial packets are decrypted with the
/// publicly derivable Initial keys (RFC 9001) to extract ClientHello metadata.
/// Handshake/0-RTT/application payloads remain encrypted and are not claimed.
pub fn parse_quic(data: &[u8]) -> Option<QuicInfo> {
    if data.len() < 7 || data[0] & 0x80 == 0 || data[0] & 0x40 == 0 {
        return None;
    }
    let version = u32::from_be_bytes([data[1], data[2], data[3], data[4]]);
    if version == 0 {
        return Some(QuicInfo {
            version,
            version_name: "version-negotiation".to_string(),
            ..Default::default()
        });
    }
    let packet_type = (data[0] >> 4) & 0x03;
    let mut pos = 5usize;
    let dcid_len = *data.get(pos)? as usize;
    pos += 1;
    if dcid_len > 20 || data.len() < pos + dcid_len {
        return None;
    }
    let dcid = data[pos..pos + dcid_len].to_vec();
    pos += dcid_len;
    let scid_len = *data.get(pos)? as usize;
    pos += 1;
    if scid_len > 20 || data.len() < pos + scid_len {
        return None;
    }
    let scid = data[pos..pos + scid_len].to_vec();
    pos += scid_len;

    let is_initial = match version {
        QUIC_V2 => packet_type == 1,
        QUIC_V1 => packet_type == 0,
        _ => packet_type == 0,
    };
    let mut info = QuicInfo {
        version,
        version_name: version_name(version).to_string(),
        packet_type,
        is_initial,
        dcid: hex(&dcid),
        scid: hex(&scid),
        ..Default::default()
    };

    if !is_initial {
        return Some(info);
    }
    let token_len = read_varint(data, &mut pos)? as usize;
    if token_len > data.len().saturating_sub(pos) {
        return None;
    }
    info.token_len = token_len;
    pos += token_len;
    let length = read_varint(data, &mut pos)? as usize;
    if length == 0 || pos + length > data.len() {
        return Some(info);
    }
    let pn_offset = pos;
    let packet_end = pn_offset + length;

    let salt: &[u8] = match version {
        QUIC_V1 => &V1_SALT,
        QUIC_V2 => &V2_SALT,
        _ => return Some(info),
    };
    let keys = derive_initial_keys(salt, &dcid)?;
    let Some((plaintext, pn, pn_len)) = decrypt_initial(data, pn_offset, packet_end, &keys) else {
        return Some(info);
    };
    info.decrypted = true;
    let _ = pn;
    let frames = parse_frames(&plaintext, &mut info);
    let _ = frames;
    let _ = pn_len;
    Some(info)
}

struct InitialKeys {
    key: [u8; 16],
    iv: [u8; 12],
    hp: [u8; 16],
}

fn derive_initial_keys(salt: &[u8], dcid: &[u8]) -> Option<InitialKeys> {
    let hk = Hkdf::<Sha256>::new(Some(salt), dcid);
    let mut client_secret = [0u8; 32];
    let info = hkdf_label(b"client in", 32)?;
    hk.expand(&info, &mut client_secret).ok()?;
    let mut key = [0u8; 16];
    let mut iv = [0u8; 12];
    let mut hp = [0u8; 16];
    expand_label(&client_secret, b"quic key", &mut key)?;
    expand_label(&client_secret, b"quic iv", &mut iv)?;
    expand_label(&client_secret, b"quic hp", &mut hp)?;
    Some(InitialKeys { key, iv, hp })
}

fn expand_label(secret: &[u8], label: &[u8], out: &mut [u8]) -> Option<()> {
    let hk = Hkdf::<Sha256>::from_prk(secret).ok()?;
    let info = hkdf_label(label, out.len())?;
    hk.expand(&info, out).ok()?;
    Some(())
}

fn hkdf_label(label: &[u8], out_len: usize) -> Option<Vec<u8>> {
    if label.len() > 200 {
        return None;
    }
    let full_label_len = 6 + label.len();
    if full_label_len > u8::MAX as usize || out_len > u16::MAX as usize {
        return None;
    }
    let mut info = Vec::with_capacity(4 + full_label_len);
    info.extend_from_slice(&(out_len as u16).to_be_bytes());
    info.push(full_label_len as u8);
    info.extend_from_slice(b"tls13 ");
    info.extend_from_slice(label);
    info.push(0);
    Some(info)
}

fn decrypt_initial(
    data: &[u8],
    pn_offset: usize,
    packet_end: usize,
    keys: &InitialKeys,
) -> Option<(Vec<u8>, u64, usize)> {
    if pn_offset + 20 > data.len() || pn_offset + 20 > packet_end {
        return None;
    }
    let sample = &data[pn_offset + 4..pn_offset + 20];
    let hp_cipher = Aes128::new_from_slice(&keys.hp).ok()?;
    let mut block = GenericArray::clone_from_slice(sample);
    hp_cipher.encrypt_block(&mut block);
    let mask = block;
    let first = data[0] ^ (mask[0] & 0x0f);
    let pn_len = ((first & 0x03) + 1) as usize;
    if pn_offset + pn_len > packet_end {
        return None;
    }
    let mut header = data[..pn_offset + pn_len].to_vec();
    header[0] = first;
    let mut pn = 0u64;
    for i in 0..pn_len {
        let byte = data[pn_offset + i] ^ mask[1 + i];
        header[pn_offset + i] = byte;
        pn = (pn << 8) | byte as u64;
    }
    let mut nonce = keys.iv;
    for i in 0..8 {
        nonce[11 - i] ^= (pn >> (8 * i)) as u8;
    }
    let cipher = Aes128Gcm::new_from_slice(&keys.key).ok()?;
    let payload = &data[pn_offset + pn_len..packet_end];
    let plaintext = cipher
        .decrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: payload,
                aad: &header,
            },
        )
        .ok()?;
    Some((plaintext, pn, pn_len))
}

fn parse_frames(buf: &[u8], info: &mut QuicInfo) -> Vec<String> {
    let mut pos = 0usize;
    let mut frames = Vec::new();
    let mut crypto_parts: Vec<(u64, Vec<u8>)> = Vec::new();
    let mut guard = 0;
    while pos < buf.len() && guard < 256 {
        guard += 1;
        let Some(frame_type) = read_varint(buf, &mut pos) else {
            break;
        };
        match frame_type {
            0x00 => continue, // padding
            0x01 => frames.push("ping".to_string()),
            0x02 | 0x03 => {
                if skip_ack(buf, &mut pos, frame_type == 0x03).is_none() {
                    break;
                }
                frames.push("ack".to_string());
            }
            0x04 => {
                if skip_varints(buf, &mut pos, 3).is_none() {
                    break;
                }
                frames.push("reset_stream".to_string());
            }
            0x05 => {
                if skip_varints(buf, &mut pos, 2).is_none() {
                    break;
                }
                frames.push("stop_sending".to_string());
            }
            0x06 => {
                let Some(offset) = read_varint(buf, &mut pos) else {
                    break;
                };
                let Some(len) = read_varint(buf, &mut pos).and_then(to_usize) else {
                    break;
                };
                if len > buf.len().saturating_sub(pos) {
                    break;
                }
                crypto_parts.push((offset, buf[pos..pos + len].to_vec()));
                info.crypto_bytes += len;
                pos += len;
                frames.push("crypto".to_string());
            }
            0x07 => {
                let Some(len) = read_varint(buf, &mut pos).and_then(to_usize) else {
                    break;
                };
                if len > buf.len().saturating_sub(pos) {
                    break;
                }
                pos += len;
                frames.push("new_token".to_string());
            }
            0x08..=0x0f => {
                let Some(_stream_id) = read_varint(buf, &mut pos) else {
                    break;
                };
                if frame_type & 0x04 != 0 && read_varint(buf, &mut pos).is_none() {
                    break;
                }
                if frame_type & 0x02 != 0 {
                    let Some(len) = read_varint(buf, &mut pos).and_then(to_usize) else {
                        break;
                    };
                    if len > buf.len().saturating_sub(pos) {
                        break;
                    }
                    pos += len;
                } else {
                    pos = buf.len();
                }
                frames.push("stream".to_string());
            }
            0x10 => {
                if skip_varints(buf, &mut pos, 2).is_none() {
                    break;
                }
                let Some(len) = buf.get(pos).copied() else {
                    break;
                };
                pos += 1;
                if len as usize + 16 > buf.len().saturating_sub(pos) {
                    break;
                }
                pos += len as usize + 16;
                frames.push("new_connection_id".to_string());
            }
            0x11 => {
                if read_varint(buf, &mut pos).is_none() {
                    break;
                }
                frames.push("retire_connection_id".to_string());
            }
            0x12 | 0x13 => {
                if buf.len().saturating_sub(pos) < 8 {
                    break;
                }
                pos += 8;
                frames.push("path_validation".to_string());
            }
            0x14 => {
                if skip_varints(buf, &mut pos, 2).is_none() {
                    break;
                }
                let Some(len) = read_varint(buf, &mut pos).and_then(to_usize) else {
                    break;
                };
                if len > buf.len().saturating_sub(pos) {
                    break;
                }
                frames.push("connection_close".to_string());
                break;
            }
            0x1e => frames.push("handshake_done".to_string()),
            0x30 | 0x31 => {
                if frame_type & 1 != 0 {
                    let Some(len) = read_varint(buf, &mut pos).and_then(to_usize) else {
                        break;
                    };
                    if len > buf.len().saturating_sub(pos) {
                        break;
                    }
                    pos += len;
                } else {
                    pos = buf.len();
                }
                frames.push("datagram".to_string());
            }
            _ => break,
        }
    }
    crypto_parts.sort_by_key(|(offset, _)| *offset);
    let mut crypto = Vec::new();
    for (offset, part) in crypto_parts {
        let offset = offset as usize;
        if offset == crypto.len() {
            crypto.extend_from_slice(&part);
        } else if offset < crypto.len() {
            let skip = crypto.len() - offset;
            if skip < part.len() {
                crypto.extend_from_slice(&part[skip..]);
            }
        } else {
            break;
        }
        if crypto.len() > super::MAX_INSPECT_BYTES {
            break;
        }
    }
    if !crypto.is_empty() {
        info.client_hello = parse_quic_client_hello(&crypto);
        if info.client_hello.is_some() {
            frames.push("tls_client_hello".to_string());
        }
    }
    info.frames = frames.clone();
    frames
}

fn skip_ack(buf: &[u8], pos: &mut usize, ecn: bool) -> Option<()> {
    let _largest = read_varint(buf, pos)?;
    let _delay = read_varint(buf, pos)?;
    let range_count = read_varint(buf, pos)?;
    if range_count > 1024 {
        return None;
    }
    let _first_range = read_varint(buf, pos)?;
    for _ in 0..range_count {
        let _gap = read_varint(buf, pos)?;
        let _len = read_varint(buf, pos)?;
    }
    if ecn {
        skip_varints(buf, pos, 3)?;
    }
    Some(())
}

fn skip_varints(buf: &[u8], pos: &mut usize, count: usize) -> Option<()> {
    for _ in 0..count {
        read_varint(buf, pos)?;
    }
    Some(())
}

pub fn read_varint(buf: &[u8], pos: &mut usize) -> Option<u64> {
    let first = *buf.get(*pos)?;
    let prefix = first >> 6;
    let len = 1usize << prefix;
    if *pos + len > buf.len() {
        return None;
    }
    let mut value = (first & 0x3f) as u64;
    for i in 1..len {
        value = (value << 8) | buf[*pos + i] as u64;
    }
    *pos += len;
    Some(value)
}

fn to_usize(value: u64) -> Option<usize> {
    usize::try_from(value).ok()
}

fn version_name(version: u32) -> &'static str {
    match version {
        QUIC_V1 => "quic-v1",
        QUIC_V2 => "quic-v2",
        0xff00_001d => "quic-draft-29",
        0xff00_0020 => "quic-draft-32",
        0xface_b001 => "quic-draft-ietf",
        _ => "quic-unknown",
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocols::test_utils::client_hello;

    #[test]
    fn rejects_tcp_tls() {
        let tls = client_hello("example.com", &["h2"], 0x0304);
        assert!(parse_quic(&tls).is_none());
    }

    #[test]
    fn varints() {
        let mut pos = 0;
        assert_eq!(read_varint(&[0x25], &mut pos), Some(0x25));
        let mut pos = 0;
        assert_eq!(read_varint(&[0x7b, 0xbd], &mut pos), Some(15293));
        let mut pos = 0;
        assert_eq!(read_varint(&[0x40, 0x25], &mut pos), Some(37));
    }

    #[test]
    fn parses_encrypted_initial() {
        let record = client_hello("quic.example", &["h3"], 0x0304);
        let handshake = &record[5..];
        let dcid = [1u8, 2, 3, 4, 5, 6, 7, 8];
        let packet = build_initial(&dcid, handshake);
        let info = parse_quic(&packet).expect("quic initial");
        assert!(info.is_initial);
        assert!(info.decrypted);
        assert_eq!(info.dcid, "0102030405060708");
        let hello = info.client_hello.expect("hello");
        assert_eq!(hello.sni.as_deref(), Some("quic.example"));
    }

    fn build_initial(dcid: &[u8], handshake: &[u8]) -> Vec<u8> {
        let keys = derive_initial_keys(&V1_SALT, dcid).unwrap();
        let mut frames = Vec::new();
        frames.push(0x06); // CRYPTO
        push_varint(0, &mut frames); // offset
        push_varint(handshake.len() as u64, &mut frames);
        frames.extend_from_slice(handshake);
        // Pad to the minimum Initial size for a realistic sample.
        frames.resize(frames.len().max(1200), 0);

        let pn: u64 = 0;
        let mut nonce = keys.iv;
        for i in 0..8 {
            nonce[11 - i] ^= (pn >> (8 * i)) as u8;
        }
        let mut header = Vec::new();
        header.push(0xc3); // long header, fixed bit, Initial, 4-byte PN
        header.extend_from_slice(&QUIC_V1.to_be_bytes());
        header.push(dcid.len() as u8);
        header.extend_from_slice(dcid);
        header.push(0);
        push_varint(0, &mut header); // token length
        push_varint(4 + frames.len() as u64 + 16, &mut header); // length includes tag
        let pn_offset = header.len();
        header.extend_from_slice(&pn.to_be_bytes()[4..]);
        let cipher = Aes128Gcm::new_from_slice(&keys.key).unwrap();
        let ciphertext = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &frames,
                    aad: &header,
                },
            )
            .unwrap();
        let mut packet = header;
        packet.extend_from_slice(&ciphertext);
        // Header protection.
        let sample = &packet[pn_offset + 4..pn_offset + 20];
        let hp_cipher = Aes128::new_from_slice(&keys.hp).unwrap();
        let mut block = GenericArray::clone_from_slice(sample);
        hp_cipher.encrypt_block(&mut block);
        let mask = block;
        packet[0] ^= mask[0] & 0x0f;
        for i in 0..4 {
            packet[pn_offset + i] ^= mask[1 + i];
        }
        packet
    }

    fn push_varint(value: u64, out: &mut Vec<u8>) {
        if value < 64 {
            out.push(value as u8);
        } else if value < 16384 {
            out.extend_from_slice(&((value as u16) | 0x4000).to_be_bytes());
        } else if value < 1_073_741_824 {
            out.extend_from_slice(&((value as u32) | 0x8000_0000).to_be_bytes());
        } else {
            out.extend_from_slice(&(value | 0xc000_0000_0000_0000).to_be_bytes());
        }
    }
}
