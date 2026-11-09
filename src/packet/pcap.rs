//! Streaming readers for classic pcap and pcapng captures.
//!
//! Parsing is bounded to 2 MiB per record/block. Corrupt lengths, truncated
//! records and unknown link types produce errors instead of unbounded reads.

use std::fs::File;
use std::io::{self, BufReader, Read};
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const MAX_RECORD: usize = 2 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkType {
    Ethernet,
    RawIp,
    LinuxSll,
    LinuxSll2,
    Null,
    Loop,
}

impl LinkType {
    pub fn from_u32(value: u32) -> Option<Self> {
        match value {
            0 => Some(Self::Null),
            1 => Some(Self::Ethernet),
            101 | 12 | 228 => Some(Self::RawIp),
            108 => Some(Self::Loop),
            113 => Some(Self::LinuxSll),
            276 => Some(Self::LinuxSll2),
            _ => None,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            LinkType::Ethernet => "ethernet",
            LinkType::RawIp => "raw-ip",
            LinkType::LinuxSll => "linux-sll",
            LinkType::LinuxSll2 => "linux-sll2",
            LinkType::Null => "null",
            LinkType::Loop => "loop",
        }
    }
}

#[derive(Debug)]
pub struct PcapRecord {
    pub timestamp: Option<SystemTime>,
    pub data: Vec<u8>,
    pub original_len: u32,
    pub link_type: LinkType,
}

#[derive(Debug, Clone, Copy)]
enum Endian {
    Little,
    Big,
}

impl Endian {
    fn u16(self, b: [u8; 2]) -> u16 {
        match self {
            Endian::Little => u16::from_le_bytes(b),
            Endian::Big => u16::from_be_bytes(b),
        }
    }

    fn u32(self, b: [u8; 4]) -> u32 {
        match self {
            Endian::Little => u32::from_le_bytes(b),
            Endian::Big => u32::from_be_bytes(b),
        }
    }

    fn u64(self, b: [u8; 8]) -> u64 {
        match self {
            Endian::Little => u64::from_le_bytes(b),
            Endian::Big => u64::from_be_bytes(b),
        }
    }
}

struct Classic {
    endian: Endian,
    nanos: bool,
    link_type: LinkType,
}

struct Interface {
    link_type: Option<LinkType>,
    tsresol: u64,
    tsresol_pow2: bool,
    tsoffset: i64,
}

struct Ng {
    endian: Endian,
    interfaces: Vec<Interface>,
    in_section: bool,
}

enum Mode {
    Classic(Classic),
    Ng(Ng),
}

pub struct PcapReader<R: Read> {
    reader: R,
    mode: Mode,
    finished: bool,
}

impl PcapReader<BufReader<File>> {
    pub fn open(path: &Path) -> io::Result<Self> {
        let file = File::open(path)?;
        Self::new(BufReader::with_capacity(256 * 1024, file))
    }
}

impl<R: Read> PcapReader<R> {
    pub fn new(mut reader: R) -> io::Result<Self> {
        let mut magic = [0u8; 4];
        read_exact(&mut reader, &mut magic)?;
        let mode = match magic {
            [0xa1, 0xb2, 0xc3, 0xd4] | [0xa1, 0xb2, 0x3c, 0x4d] => {
                let nanos = magic == [0xa1, 0xb2, 0x3c, 0x4d];
                let link = read_classic_header(&mut reader, Endian::Big)?;
                Mode::Classic(Classic {
                    endian: Endian::Big,
                    nanos,
                    link_type: link,
                })
            }
            [0xd4, 0xc3, 0xb2, 0xa1] | [0x4d, 0x3c, 0xb2, 0xa1] => {
                let nanos = magic == [0x4d, 0x3c, 0xb2, 0xa1];
                let link = read_classic_header(&mut reader, Endian::Little)?;
                Mode::Classic(Classic {
                    endian: Endian::Little,
                    nanos,
                    link_type: link,
                })
            }
            [0x0a, 0x0d, 0x0d, 0x0a] => {
                // pcapng: read version/length and byte-order magic.
                let mut rest = [0u8; 8];
                read_exact(&mut reader, &mut rest)?;
                let endian = match [rest[4], rest[5], rest[6], rest[7]] {
                    [0x1a, 0x2b, 0x3c, 0x4d] => Endian::Big,
                    [0x4d, 0x3c, 0x2b, 0x1a] => Endian::Little,
                    _ => {
                        return Err(invalid("invalid pcapng byte-order magic"));
                    }
                };
                let total = endian.u32([rest[0], rest[1], rest[2], rest[3]]) as usize;
                if !(28..=MAX_RECORD).contains(&total) {
                    return Err(invalid("pcapng section header length out of range"));
                }
                // We have consumed type + length + BOM. Discard the rest.
                skip(&mut reader, total.saturating_sub(12))?;
                Mode::Ng(Ng {
                    endian,
                    interfaces: Vec::new(),
                    in_section: true,
                })
            }
            _ => return Err(invalid("unrecognised capture magic")),
        };
        Ok(Self {
            reader,
            mode,
            finished: false,
        })
    }

    pub fn next_record(&mut self) -> io::Result<Option<PcapRecord>> {
        if self.finished {
            return Ok(None);
        }
        let result = match &mut self.mode {
            Mode::Classic(classic) => next_classic(&mut self.reader, classic),
            Mode::Ng(ng) => next_ng(&mut self.reader, ng),
        };
        if matches!(result, Ok(None)) {
            self.finished = true;
        }
        result
    }
}

fn next_classic<R: Read>(reader: &mut R, c: &Classic) -> io::Result<Option<PcapRecord>> {
    let mut header = [0u8; 16];
    if !read_exact_or_eof(reader, &mut header)? {
        return Ok(None);
    }
    let secs = c.endian.u32([header[0], header[1], header[2], header[3]]);
    let frac = c.endian.u32([header[4], header[5], header[6], header[7]]);
    let incl = c.endian.u32([header[8], header[9], header[10], header[11]]) as usize;
    let orig = c
        .endian
        .u32([header[12], header[13], header[14], header[15]]);
    if incl > MAX_RECORD {
        return Err(invalid("pcap record length exceeds limit"));
    }
    let mut data = vec![0u8; incl];
    read_exact(reader, &mut data)?;
    let nanos = if c.nanos {
        frac.min(999_999_999)
    } else {
        frac.saturating_mul(1000).min(999_999_999)
    };
    Ok(Some(PcapRecord {
        timestamp: Some(UNIX_EPOCH + Duration::new(secs as u64, nanos)),
        data,
        original_len: orig,
        link_type: c.link_type,
    }))
}

fn next_ng<R: Read>(reader: &mut R, ng: &mut Ng) -> io::Result<Option<PcapRecord>> {
    loop {
        let mut header = [0u8; 8];
        if !read_exact_or_eof(reader, &mut header)? {
            return Ok(None);
        }
        let is_shb = header[0..4] == [0x0a, 0x0d, 0x0d, 0x0a];
        let total;
        if is_shb {
            let mut bom = [0u8; 4];
            read_exact(reader, &mut bom)?;
            ng.endian = match bom {
                [0x1a, 0x2b, 0x3c, 0x4d] => Endian::Big,
                [0x4d, 0x3c, 0x2b, 0x1a] => Endian::Little,
                _ => return Err(invalid("pcapng section byte-order magic")),
            };
            total = ng.endian.u32([header[4], header[5], header[6], header[7]]) as usize;
            if !(28..=MAX_RECORD).contains(&total) {
                return Err(invalid("pcapng section length out of range"));
            }
            let remaining = total - 16; // already read 12, plus 4 trailer
            skip(reader, remaining)?;
            let mut trailer = [0u8; 4];
            read_exact(reader, &mut trailer)?;
            if ng.endian.u32(trailer) as usize != total {
                return Err(invalid("pcapng section trailer mismatch"));
            }
            ng.interfaces.clear();
            ng.in_section = true;
            continue;
        }

        if !ng.in_section {
            return Err(invalid("pcapng block outside a section"));
        }
        total = ng.endian.u32([header[4], header[5], header[6], header[7]]) as usize;
        if !(12..=MAX_RECORD).contains(&total) {
            return Err(invalid("pcapng block length out of range"));
        }
        let body_len = total - 12;
        let mut body = vec![0u8; body_len];
        read_exact(reader, &mut body)?;
        let mut trailer = [0u8; 4];
        read_exact(reader, &mut trailer)?;
        if ng.endian.u32(trailer) as usize != total {
            return Err(invalid("pcapng block trailer mismatch"));
        }
        let block_type = ng.endian.u32([header[0], header[1], header[2], header[3]]);
        match block_type {
            1 => {
                if body.len() < 8 {
                    return Err(invalid("short pcapng interface block"));
                }
                let link_raw = ng.endian.u16([body[0], body[1]]) as u32;
                let mut iface = Interface {
                    link_type: LinkType::from_u32(link_raw),
                    tsresol: 1_000_000,
                    tsresol_pow2: false,
                    tsoffset: 0,
                };
                parse_iface_options(ng.endian, &body[8..], &mut iface);
                ng.interfaces.push(iface);
            }
            3 => {
                // Simple packet block: no timestamp, interface 0.
                if body.len() < 4 {
                    return Err(invalid("short pcapng simple packet block"));
                }
                let orig = ng.endian.u32([body[0], body[1], body[2], body[3]]);
                let Some(iface) = ng.interfaces.first() else {
                    continue;
                };
                let Some(link_type) = iface.link_type else {
                    continue;
                };
                let caplen = (body.len() - 4).min(orig as usize);
                let data = body[4..4 + caplen].to_vec();
                return Ok(Some(PcapRecord {
                    timestamp: None,
                    data,
                    original_len: orig,
                    link_type,
                }));
            }
            6 => {
                if body.len() < 20 {
                    return Err(invalid("short pcapng enhanced packet block"));
                }
                let iface_id = ng.endian.u32([body[0], body[1], body[2], body[3]]) as usize;
                let ts_high = ng.endian.u32([body[4], body[5], body[6], body[7]]) as u64;
                let ts_low = ng.endian.u32([body[8], body[9], body[10], body[11]]) as u64;
                let caplen = ng.endian.u32([body[12], body[13], body[14], body[15]]) as usize;
                let orig = ng.endian.u32([body[16], body[17], body[18], body[19]]);
                if caplen > body.len() - 20 {
                    return Err(invalid("pcapng packet length exceeds block"));
                }
                let Some(iface) = ng.interfaces.get(iface_id) else {
                    continue;
                };
                let Some(link_type) = iface.link_type else {
                    continue;
                };
                let timestamp = Some(unix_time(
                    (ts_high << 32) | ts_low,
                    iface.tsresol,
                    iface.tsresol_pow2,
                    iface.tsoffset,
                ));
                return Ok(Some(PcapRecord {
                    timestamp,
                    data: body[20..20 + caplen].to_vec(),
                    original_len: orig,
                    link_type,
                }));
            }
            _ => continue,
        }
    }
}
fn read_classic_header<R: Read>(reader: &mut R, endian: Endian) -> io::Result<LinkType> {
    let mut rest = [0u8; 20];
    read_exact(reader, &mut rest)?;
    let major = endian.u16([rest[0], rest[1]]);
    let minor = endian.u16([rest[2], rest[3]]);
    if major != 2 || minor != 4 {
        return Err(invalid("unsupported pcap version"));
    }
    let snap = endian.u32([rest[12], rest[13], rest[14], rest[15]]);
    if snap == 0 || snap > MAX_RECORD as u32 {
        return Err(invalid("pcap snaplen out of range"));
    }
    let link = endian.u32([rest[16], rest[17], rest[18], rest[19]]);
    LinkType::from_u32(link).ok_or_else(|| invalid("unsupported pcap link type"))
}

fn parse_iface_options(endian: Endian, mut opts: &[u8], iface: &mut Interface) {
    while opts.len() >= 4 {
        let code = endian.u16([opts[0], opts[1]]);
        let len = endian.u16([opts[2], opts[3]]) as usize;
        opts = &opts[4..];
        if code == 0 || len > opts.len() {
            break;
        }
        let value = &opts[..len];
        match code {
            9 if !value.is_empty() => {
                let v = value[0];
                if v & 0x80 != 0 {
                    iface.tsresol_pow2 = true;
                    iface.tsresol = 1u64 << (v & 0x7f).min(30);
                } else {
                    iface.tsresol_pow2 = false;
                    iface.tsresol = 10u64.checked_pow(v as u32).unwrap_or(1_000_000);
                }
            }
            14 if value.len() >= 8 => {
                iface.tsoffset = i64::try_from(endian.u64([
                    value[0], value[1], value[2], value[3], value[4], value[5], value[6], value[7],
                ]))
                .unwrap_or(i64::MAX);
            }
            _ => {}
        }
        let padded = (len + 3) & !3;
        if padded >= opts.len() {
            break;
        }
        opts = &opts[padded..];
    }
}

fn unix_time(value: u64, resol: u64, pow2: bool, offset: i64) -> SystemTime {
    let (secs, nanos) = if pow2 {
        let shift = resol.trailing_zeros().min(30);
        let s = value >> shift;
        let rem = value & ((1u64 << shift) - 1);
        let n = ((rem as u128 * 1_000_000_000u128) >> shift) as u32;
        (s, n)
    } else {
        let r = resol.max(1);
        (
            (value / r),
            ((value % r) as u128 * 1_000_000_000u128 / r as u128) as u32,
        )
    };
    let secs = i64::try_from(secs).unwrap_or(i64::MAX);
    let Some(secs) = secs.checked_add(offset) else {
        return UNIX_EPOCH;
    };
    if secs < 0 {
        UNIX_EPOCH
    } else {
        UNIX_EPOCH
            .checked_add(Duration::new(secs as u64, nanos.min(999_999_999)))
            .unwrap_or(UNIX_EPOCH)
    }
}

fn read_exact<R: Read>(reader: &mut R, buf: &mut [u8]) -> io::Result<()> {
    reader.read_exact(buf)
}

fn read_exact_or_eof<R: Read>(reader: &mut R, buf: &mut [u8]) -> io::Result<bool> {
    let mut read = 0;
    while read < buf.len() {
        match reader.read(&mut buf[read..]) {
            Ok(0) if read == 0 => return Ok(false),
            Ok(0) => return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "short read")),
            Ok(n) => read += n,
            Err(ref e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(true)
}

fn skip<R: Read>(reader: &mut R, mut bytes: usize) -> io::Result<()> {
    let mut buf = [0u8; 8192];
    while bytes > 0 {
        let take = bytes.min(buf.len());
        read_exact(reader, &mut buf[..take])?;
        bytes -= take;
    }
    Ok(())
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn classic_pcap(le: bool) -> Vec<u8> {
        let mut out = Vec::new();
        if le {
            out.extend_from_slice(&0xa1b2c3d4u32.to_le_bytes());
        } else {
            out.extend_from_slice(&0xa1b2c3d4u32.to_be_bytes());
        }
        let append16 = |v: u16, out: &mut Vec<u8>| {
            out.extend_from_slice(&if le { v.to_le_bytes() } else { v.to_be_bytes() });
        };
        let append32 = |v: u32, out: &mut Vec<u8>| {
            out.extend_from_slice(&if le { v.to_le_bytes() } else { v.to_be_bytes() });
        };
        append16(2, &mut out);
        append16(4, &mut out);
        append32(0, &mut out);
        append32(0, &mut out);
        append32(65535, &mut out);
        append32(1, &mut out);
        append32(100, &mut out);
        append32(500, &mut out);
        append32(4, &mut out);
        append32(4, &mut out);
        out.extend_from_slice(b"test");
        out
    }

    #[test]
    fn reads_classic_little_endian() {
        let mut reader = PcapReader::new(Cursor::new(classic_pcap(true))).unwrap();
        let rec = reader.next_record().unwrap().unwrap();
        assert_eq!(rec.data, b"test");
        assert_eq!(rec.original_len, 4);
        assert!(reader.next_record().unwrap().is_none());
    }

    #[test]
    fn reads_classic_big_endian() {
        let mut reader = PcapReader::new(Cursor::new(classic_pcap(false))).unwrap();
        let rec = reader.next_record().unwrap().unwrap();
        assert_eq!(rec.data, b"test");
    }

    #[test]
    fn rejects_absurd_record_length() {
        let mut bytes = classic_pcap(true);
        // Record header starts at 24; incl_len at +8.
        bytes[32..36].copy_from_slice(&(u32::MAX).to_le_bytes());
        let mut reader = PcapReader::new(Cursor::new(bytes)).unwrap();
        assert!(reader.next_record().is_err());
    }
}
