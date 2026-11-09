use serde::Serialize;

#[derive(Debug, Clone, Serialize, Default)]
pub struct DnsQuestion {
    pub name: String,
    pub qtype: u16,
    pub qclass: u16,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct DnsInfo {
    pub id: u16,
    pub is_response: bool,
    pub opcode: u8,
    pub rcode: u8,
    pub questions: Vec<DnsQuestion>,
    pub answers: Vec<String>,
    pub truncated: bool,
    pub tcp: bool,
}

pub fn dns_type_name(qtype: u16) -> &'static str {
    match qtype {
        1 => "A",
        2 => "NS",
        5 => "CNAME",
        6 => "SOA",
        12 => "PTR",
        15 => "MX",
        16 => "TXT",
        28 => "AAAA",
        33 => "SRV",
        43 => "DS",
        46 => "RRSIG",
        64 => "SVCB",
        65 => "HTTPS",
        255 => "ANY",
        _ => "TYPE",
    }
}

/// Parse a DNS message. `tcp` requires the two-byte DNS-over-TCP length prefix.
pub fn parse_dns(data: &[u8], tcp: bool) -> Option<DnsInfo> {
    let message = if tcp {
        if data.len() < 2 {
            return None;
        }
        let prefix = u16::from_be_bytes([data[0], data[1]]) as usize;
        if prefix < 12 || prefix > data.len() - 2 {
            return None;
        }
        &data[2..2 + prefix]
    } else {
        data
    };
    if message.len() < 12 || message.len() > 65535 {
        return None;
    }
    let id = u16::from_be_bytes([message[0], message[1]]);
    let flags = u16::from_be_bytes([message[2], message[3]]);
    let is_response = flags & 0x8000 != 0;
    let opcode = ((flags >> 11) & 0x0f) as u8;
    let rcode = (flags & 0x0f) as u8;
    if opcode > 5 || rcode > 10 || flags & 0x0040 != 0 {
        return None;
    }
    let qdcount = u16::from_be_bytes([message[4], message[5]]);
    let ancount = u16::from_be_bytes([message[6], message[7]]);
    if qdcount > 32 || ancount > 128 {
        return None;
    }
    let mut pos = 12usize;
    let mut info = DnsInfo {
        id,
        is_response,
        opcode,
        rcode,
        tcp,
        truncated: flags & 0x0200 != 0,
        ..Default::default()
    };
    for _ in 0..qdcount {
        let name = read_name(message, &mut pos, 0)?;
        if pos + 4 > message.len() {
            return None;
        }
        let qtype = u16::from_be_bytes([message[pos], message[pos + 1]]);
        let qclass = u16::from_be_bytes([message[pos + 2], message[pos + 3]]);
        pos += 4;
        if name.is_empty() || name.len() > 253 {
            return None;
        }
        info.questions.push(DnsQuestion {
            name,
            qtype,
            qclass,
        });
    }
    // Skip authority/additional records: only answer names/addresses are useful
    // to the classifier and bounded parsing keeps the hot path predictable.
    for _ in 0..ancount.min(32) {
        let name = read_name(message, &mut pos, 0)?;
        if pos + 10 > message.len() {
            break;
        }
        let rtype = u16::from_be_bytes([message[pos], message[pos + 1]]);
        let rdlen = u16::from_be_bytes([message[pos + 8], message[pos + 9]]) as usize;
        pos += 10;
        if pos + rdlen > message.len() {
            info.truncated = true;
            break;
        }
        let rdata = &message[pos..pos + rdlen];
        match rtype {
            1 if rdlen == 4 => info.answers.push(format!(
                "{}.{}.{}.{}",
                rdata[0], rdata[1], rdata[2], rdata[3]
            )),
            28 if rdlen == 16 => {
                let mut octets = [0u8; 16];
                octets.copy_from_slice(rdata);
                info.answers
                    .push(std::net::Ipv6Addr::from(octets).to_string());
            }
            2 | 5 | 12 => {
                let mut p = pos;
                if let Some(target) = read_name(message, &mut p, 0) {
                    info.answers.push(target);
                }
            }
            _ => {}
        }
        pos += rdlen;
        let _ = name;
    }
    // qdcount must be at least one for a useful classification, and a response
    // without questions is suspicious but still valid DNS.
    if info.questions.is_empty() && !is_response {
        return None;
    }
    Some(info)
}

fn read_name(packet: &[u8], pos: &mut usize, depth: usize) -> Option<String> {
    if depth > 16 {
        return None;
    }
    let mut cursor = *pos;
    let mut labels: Vec<String> = Vec::new();
    let mut jumped = false;
    let mut jumps = 0;
    let mut total_len = 0usize;
    loop {
        let byte = *packet.get(cursor)?;
        if byte == 0 {
            if !jumped {
                *pos = cursor + 1;
            }
            break;
        }
        if byte & 0xc0 == 0xc0 {
            let next = *packet.get(cursor + 1)?;
            let pointer = (((byte & 0x3f) as usize) << 8) | next as usize;
            if !jumped {
                *pos = cursor + 2;
                jumped = true;
            }
            if pointer >= packet.len() || jumps > 16 {
                return None;
            }
            jumps += 1;
            cursor = pointer;
            continue;
        }
        if byte & 0xc0 != 0 {
            return None;
        }
        let len = byte as usize;
        if len == 0 || len > 63 || cursor + 1 + len > packet.len() {
            return None;
        }
        let label = &packet[cursor + 1..cursor + 1 + len];
        if !label.iter().all(|b| (0x21..=0x7e).contains(b)) {
            return None;
        }
        let text = String::from_utf8_lossy(label).to_ascii_lowercase();
        total_len += text.len() + 1;
        if total_len > 253 || labels.len() >= 127 {
            return None;
        }
        labels.push(text);
        cursor += 1 + len;
    }
    if labels.is_empty() {
        Some(".".to_string())
    } else {
        Some(labels.join("."))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn query() -> Vec<u8> {
        let mut msg = Vec::new();
        msg.extend_from_slice(&0x1234u16.to_be_bytes());
        msg.extend_from_slice(&0x0100u16.to_be_bytes()); // RD
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&0u16.to_be_bytes());
        msg.extend_from_slice(&0u16.to_be_bytes());
        for label in ["www", "example", "com"] {
            msg.push(label.len() as u8);
            msg.extend_from_slice(label.as_bytes());
        }
        msg.push(0);
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&1u16.to_be_bytes());
        // Answer with pointer to offset 12, A record 93.184.216.34.
        msg.extend_from_slice(&[0xc0, 0x0c]);
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&300u32.to_be_bytes());
        msg.extend_from_slice(&4u16.to_be_bytes());
        msg.extend_from_slice(&[93, 184, 216, 34]);
        msg
    }

    #[test]
    fn parses_query_with_answer_pointer() {
        let info = parse_dns(&query(), false).unwrap();
        assert_eq!(info.questions[0].name, "www.example.com");
        assert_eq!(info.questions[0].qtype, 1);
        assert_eq!(info.answers, vec!["93.184.216.34"]);
    }

    #[test]
    fn parses_tcp_prefix() {
        let msg = query();
        let mut framed = Vec::new();
        framed.extend_from_slice(&(msg.len() as u16).to_be_bytes());
        framed.extend_from_slice(&msg);
        let info = parse_dns(&framed, true).unwrap();
        assert!(info.tcp);
        assert_eq!(info.questions[0].name, "www.example.com");
    }

    #[test]
    fn rejects_pointer_loop() {
        let mut msg = vec![0u8; 12];
        msg[4..6].copy_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1]); // self pointer
        assert!(parse_dns(&msg, false).is_none());
    }

    #[test]
    fn rejects_random() {
        assert!(parse_dns(&[1, 2, 3, 4, 5, 6], false).is_none());
    }
}
