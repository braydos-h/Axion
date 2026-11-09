//! Minimal, dependency-free NFQUEUE netlink client used for inline verdicts.
//!
//! The queue is bound with NFQA_CFG_F_FAIL_OPEN when configured. Packets are
//! parsed at L3 (the kernel strips the Ethernet header for NFQUEUE). Verdicts
//! are batched into netlink datagrams for throughput.

use std::io;
use std::os::fd::RawFd;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::packet;

const NETLINK_NETFILTER: libc::c_int = 12;
const NFNL_SUBSYS_QUEUE: u16 = 3;
const NFQNL_MSG_PACKET: u16 = 0;
const NFQNL_MSG_VERDICT: u16 = 1;
const NFQNL_MSG_CONFIG: u16 = 2;
const NFQNL_CFG_CMD_BIND: u8 = 1;
const NFQNL_CFG_CMD_UNBIND: u8 = 2;
const NFQNL_COPY_PACKET: u8 = 2;
const NFQA_PACKET_HDR: u16 = 1;
const NFQA_TIMESTAMP: u16 = 3;
const NFQA_PAYLOAD: u16 = 9;
const NFQA_CFG_CMD: u16 = 1;
const NFQA_CFG_PARAMS: u16 = 2;
const NFQA_CFG_QUEUE_MAXLEN: u16 = 3;
const NFQA_CFG_MASK: u16 = 4;
const NFQA_CFG_FLAGS: u16 = 5;
const NFQA_CFG_F_FAIL_OPEN: u32 = 1;
const NLM_F_REQUEST: u16 = 0x0001;
const NLM_F_ACK: u16 = 0x0004;
const NLMSG_ERROR: u16 = 2;
const NF_ACCEPT: u32 = 1;
const NF_DROP: u32 = 0;
const RECV_BUFFER: usize = 256 * 1024;
const VERDICT_TIMEOUT_MS: i64 = 500;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Accept,
    Drop,
}

impl Verdict {
    fn value(self) -> u32 {
        match self {
            Verdict::Accept => NF_ACCEPT,
            Verdict::Drop => NF_DROP,
        }
    }
}

#[derive(Debug)]
pub struct QueuePacket {
    pub id: u32,
    pub payload: Vec<u8>,
    pub timestamp: Option<SystemTime>,
    pub hook: u8,
    pub hw_protocol: u16,
}

pub struct NfQueue {
    fd: RawFd,
    queue_num: u16,
    seq: u32,
    recv_buf: Vec<u8>,
    fail_open: bool,
}

impl NfQueue {
    pub fn open(
        queue_num: u16,
        queue_max_len: u32,
        copy_range: u32,
        fail_open: bool,
    ) -> io::Result<Self> {
        // SAFETY: standard netlink socket creation with constant arguments.
        let fd = unsafe {
            libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                NETLINK_NETFILTER,
            )
        };
        if fd < 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "open NETLINK_NETFILTER socket failed (CAP_NET_ADMIN/root required): {}",
                    io::Error::last_os_error()
                ),
            ));
        }

        let mut queue = Self {
            fd,
            queue_num,
            seq: 1,
            recv_buf: vec![0u8; RECV_BUFFER],
            fail_open,
        };
        queue.configure(queue_max_len, copy_range)?;
        Ok(queue)
    }

    fn configure(&mut self, queue_max_len: u32, copy_range: u32) -> io::Result<()> {
        // Bind address. nl_pid=0 asks the kernel to assign a port ID.
        // SAFETY: sockaddr_nl is POD and fully initialised.
        let mut addr: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        addr.nl_family = libc::AF_NETLINK as u16;
        // SAFETY: valid address/length for bind.
        let rc = unsafe {
            libc::bind(
                self.fd,
                &addr as *const libc::sockaddr_nl as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
            )
        };
        if rc < 0 {
            return Err(io::Error::other(format!(
                "bind netlink socket failed: {}",
                io::Error::last_os_error()
            )));
        }

        let rcvbuf: i32 = 4 * 1024 * 1024;
        // SAFETY: valid int option.
        unsafe {
            libc::setsockopt(
                self.fd,
                libc::SOL_SOCKET,
                libc::SO_RCVBUF,
                &rcvbuf as *const i32 as *const libc::c_void,
                std::mem::size_of::<i32>() as libc::socklen_t,
            );
        }
        let timeout = libc::timeval {
            tv_sec: 0,
            tv_usec: VERDICT_TIMEOUT_MS * 1000,
        };
        // SAFETY: valid timeval for SO_RCVTIMEO.
        unsafe {
            libc::setsockopt(
                self.fd,
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                &timeout as *const libc::timeval as *const libc::c_void,
                std::mem::size_of::<libc::timeval>() as libc::socklen_t,
            );
        }

        // Bind this userspace client to the queue.
        let mut cmd = Vec::new();
        cmd.extend_from_slice(&[NFQNL_CFG_CMD_BIND, 0]);
        cmd.extend_from_slice(&0u16.to_be_bytes()); // pf = AF_UNSPEC
        let mut attrs = Vec::new();
        put_attr(&mut attrs, NFQA_CFG_CMD, &cmd);
        self.config(attrs)?;

        // Maximum queued packets.
        let mut attrs = Vec::new();
        put_attr(
            &mut attrs,
            NFQA_CFG_QUEUE_MAXLEN,
            &queue_max_len.to_be_bytes(),
        );
        self.config(attrs)?;

        // Copy mode: full packets up to copy_range.
        let mut params = Vec::with_capacity(5);
        params.extend_from_slice(&copy_range.to_be_bytes());
        params.push(NFQNL_COPY_PACKET);
        let mut attrs = Vec::new();
        put_attr(&mut attrs, NFQA_CFG_PARAMS, &params);
        self.config(attrs)?;

        // Fail-open flag. The mask/flags attributes are network byte order.
        let mask = NFQA_CFG_F_FAIL_OPEN;
        let flags = if self.fail_open {
            NFQA_CFG_F_FAIL_OPEN
        } else {
            0
        };
        let mut attrs = Vec::new();
        put_attr(&mut attrs, NFQA_CFG_MASK, &mask.to_be_bytes());
        put_attr(&mut attrs, NFQA_CFG_FLAGS, &flags.to_be_bytes());
        self.config(attrs)?;
        Ok(())
    }

    fn config(&mut self, attrs: Vec<u8>) -> io::Result<()> {
        let seq = self.next_seq();
        let mut msg = Vec::with_capacity(16 + 4 + attrs.len());
        msg.resize(16, 0); // nlmsghdr placeholder
        msg.extend_from_slice(&[libc::AF_UNSPEC as u8, 0]);
        msg.extend_from_slice(&self.queue_num.to_be_bytes());
        msg.extend_from_slice(&attrs);
        fill_nlmsg(
            &mut msg,
            (NFNL_SUBSYS_QUEUE << 8) | NFQNL_MSG_CONFIG,
            NLM_F_REQUEST | NLM_F_ACK,
            seq,
        );
        self.send_raw(&msg)?;
        self.wait_ack(seq)
    }

    fn next_seq(&mut self) -> u32 {
        let seq = self.seq;
        self.seq = self.seq.wrapping_add(1).max(1);
        seq
    }

    fn send_raw(&self, msg: &[u8]) -> io::Result<()> {
        // SAFETY: sockaddr_nl is POD and zeroed. Dest is the kernel (pid 0).
        let mut addr: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        addr.nl_family = libc::AF_NETLINK as u16;
        // SAFETY: valid buffer and address for sendto.
        let sent = unsafe {
            libc::sendto(
                self.fd,
                msg.as_ptr() as *const libc::c_void,
                msg.len(),
                0,
                &addr as *const libc::sockaddr_nl as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
            )
        };
        if sent < 0 {
            return Err(io::Error::last_os_error());
        }
        if sent as usize != msg.len() {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "short netlink send",
            ));
        }
        Ok(())
    }

    fn wait_ack(&mut self, seq: u32) -> io::Result<()> {
        for _ in 0..20 {
            // SAFETY: recv into a valid owned buffer.
            let n = unsafe {
                libc::recv(
                    self.fd,
                    self.recv_buf.as_mut_ptr() as *mut libc::c_void,
                    self.recv_buf.len(),
                    0,
                )
            };
            if n < 0 {
                let err = io::Error::last_os_error();
                if matches!(err.kind(), io::ErrorKind::Interrupted) {
                    continue;
                }
                return Err(err);
            }
            let data = &self.recv_buf[..n as usize];
            let mut offset = 0usize;
            while offset + 16 <= data.len() {
                let len = u32::from_ne_bytes(data[offset..offset + 4].try_into().unwrap()) as usize;
                if len < 16 || offset + len > data.len() {
                    break;
                }
                let msg_type = u16::from_ne_bytes(data[offset + 4..offset + 6].try_into().unwrap());
                let msg_seq = u32::from_ne_bytes(data[offset + 8..offset + 12].try_into().unwrap());
                if msg_type == NLMSG_ERROR && msg_seq == seq {
                    if len < 20 {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "short netlink ack",
                        ));
                    }
                    let code =
                        i32::from_ne_bytes(data[offset + 16..offset + 20].try_into().unwrap());
                    if code == 0 {
                        return Ok(());
                    }
                    return Err(io::Error::from_raw_os_error(-code));
                }
                offset += align4(len);
            }
        }
        Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "timed out waiting for nfnetlink ack",
        ))
    }

    /// Receive up to `max` queued packets. Returns an empty vector on timeout.
    pub fn recv_batch(&mut self, max: usize) -> io::Result<Vec<QueuePacket>> {
        let mut out = Vec::new();
        let mut first = true;
        while out.len() < max {
            // Block only for the first datagram (SO_RCVTIMEO bounds shutdown
            // latency); drain the rest of the available queue non-blocking so
            // verdicts can be batched without adding a timeout per packet.
            let flags = if first { 0 } else { libc::MSG_DONTWAIT };
            // SAFETY: recv into a valid owned buffer.
            let n = unsafe {
                libc::recv(
                    self.fd,
                    self.recv_buf.as_mut_ptr() as *mut libc::c_void,
                    self.recv_buf.len(),
                    flags,
                )
            };
            if n < 0 {
                let err = io::Error::last_os_error();
                return match err.kind() {
                    io::ErrorKind::WouldBlock
                    | io::ErrorKind::TimedOut
                    | io::ErrorKind::Interrupted => Ok(out),
                    _ => Err(err),
                };
            }
            first = false;
            if n == 0 {
                break;
            }
            let data = &self.recv_buf[..n as usize];
            let mut offset = 0usize;
            while offset + 16 <= data.len() {
                let len = u32::from_ne_bytes(data[offset..offset + 4].try_into().unwrap()) as usize;
                if len < 16 || offset + len > data.len() {
                    break;
                }
                let msg_type = u16::from_ne_bytes(data[offset + 4..offset + 6].try_into().unwrap());
                if msg_type == NLMSG_ERROR {
                    if len >= 20 {
                        let code =
                            i32::from_ne_bytes(data[offset + 16..offset + 20].try_into().unwrap());
                        if code != 0 {
                            return Err(io::Error::from_raw_os_error(-code));
                        }
                    }
                } else if msg_type == (NFNL_SUBSYS_QUEUE << 8) | NFQNL_MSG_PACKET {
                    if let Some(packet) = parse_packet(&data[offset..offset + len]) {
                        out.push(packet);
                    }
                }
                offset += align4(len);
            }
        }
        Ok(out)
    }

    pub fn send_verdicts(&mut self, verdicts: &[(u32, Verdict)]) -> io::Result<()> {
        if verdicts.is_empty() {
            return Ok(());
        }
        let mut msg = Vec::with_capacity(verdicts.len() * 32);
        let seq = self.next_seq();
        for (id, verdict) in verdicts {
            let start = msg.len();
            msg.resize(start + 16, 0); // nlmsghdr
            msg.extend_from_slice(&[libc::AF_UNSPEC as u8, 0]);
            msg.extend_from_slice(&self.queue_num.to_be_bytes());
            msg.extend_from_slice(&verdict.value().to_be_bytes());
            msg.extend_from_slice(&id.to_be_bytes());
            fill_nlmsg(
                &mut msg[start..],
                (NFNL_SUBSYS_QUEUE << 8) | NFQNL_MSG_VERDICT,
                NLM_F_REQUEST,
                seq,
            );
            let len = msg.len() - start;
            let aligned = align4(len);
            if aligned > len {
                msg.resize(start + aligned, 0);
            }
        }
        self.send_raw(&msg)
    }

    pub fn queue_num(&self) -> u16 {
        self.queue_num
    }

    pub fn fail_open(&self) -> bool {
        self.fail_open
    }

    pub fn unbind(&mut self) {
        let mut cmd = Vec::new();
        cmd.extend_from_slice(&[NFQNL_CFG_CMD_UNBIND, 0]);
        cmd.extend_from_slice(&0u16.to_be_bytes());
        let mut attrs = Vec::new();
        put_attr(&mut attrs, NFQA_CFG_CMD, &cmd);
        let _ = self.config(attrs);
    }
}

impl Drop for NfQueue {
    fn drop(&mut self) {
        let _ = self.queue_num;
        // SAFETY: fd is owned by this object and closed exactly once.
        unsafe {
            libc::close(self.fd);
        }
    }
}

fn parse_packet(msg: &[u8]) -> Option<QueuePacket> {
    // nlmsghdr (16) + nfgenmsg (4)
    if msg.len() < 20 {
        return None;
    }
    let mut attrs = &msg[20..];
    let mut id = None;
    let mut payload = None;
    let mut timestamp = None;
    let mut hook = 0;
    let mut hw_protocol = 0;
    while attrs.len() >= 4 {
        let alen = u16::from_ne_bytes([attrs[0], attrs[1]]) as usize;
        let atype = u16::from_ne_bytes([attrs[2], attrs[3]]) & 0x3fff;
        if alen < 4 || alen > attrs.len() {
            break;
        }
        let value = &attrs[4..alen];
        match atype {
            NFQA_PACKET_HDR if value.len() >= 8 => {
                id = Some(u32::from_be_bytes([value[0], value[1], value[2], value[3]]));
                hw_protocol = u16::from_be_bytes([value[4], value[5]]);
                hook = value[6];
            }
            NFQA_TIMESTAMP if value.len() >= 16 => {
                let sec = u64::from_be_bytes(value[0..8].try_into().ok()?);
                let usec = u64::from_be_bytes(value[8..16].try_into().ok()?);
                timestamp =
                    UNIX_EPOCH.checked_add(Duration::new(sec, (usec.min(999_999) * 1000) as u32));
            }
            NFQA_PAYLOAD => payload = Some(value.to_vec()),
            _ => {}
        }
        let padded = align4(alen);
        if padded > attrs.len() {
            break;
        }
        attrs = &attrs[padded..];
    }
    Some(QueuePacket {
        id: id?,
        payload: payload?,
        timestamp,
        hook,
        hw_protocol,
    })
}

fn put_attr(out: &mut Vec<u8>, kind: u16, value: &[u8]) {
    let len = 4 + value.len();
    out.extend_from_slice(&(len as u16).to_ne_bytes());
    out.extend_from_slice(&kind.to_ne_bytes());
    out.extend_from_slice(value);
    while out.len() % 4 != 0 {
        out.push(0);
    }
}

fn fill_nlmsg(msg: &mut [u8], kind: u16, flags: u16, seq: u32) {
    let len = msg.len() as u32;
    msg[0..4].copy_from_slice(&len.to_ne_bytes());
    msg[4..6].copy_from_slice(&kind.to_ne_bytes());
    msg[6..8].copy_from_slice(&flags.to_ne_bytes());
    msg[8..12].copy_from_slice(&seq.to_ne_bytes());
    msg[12..16].copy_from_slice(&0u32.to_ne_bytes());
}

fn align4(value: usize) -> usize {
    (value + 3) & !3
}

/// Parse and classify an NFQUEUE payload as a raw L3 packet. Exposed for tests.
pub fn parse_queue_payload(payload: &[u8]) -> packet::ParseOutcome<'_> {
    packet::parse_l3(payload, None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attribute_alignment() {
        let mut out = Vec::new();
        put_attr(&mut out, 1, &[1, 2, 3]);
        assert_eq!(out.len(), 8);
        put_attr(&mut out, 2, &[4, 5, 6, 7, 8]);
        assert_eq!(out.len(), 20);
    }

    #[test]
    fn builds_verdict_batch_shape() {
        // Build one verdict message in the same layout used by send_verdicts.
        let mut msg = vec![0u8; 16 + 4 + 8];
        fill_nlmsg(&mut msg, 0x301, NLM_F_REQUEST, 7);
        assert_eq!(&msg[0..4], &(msg.len() as u32).to_ne_bytes());
        assert_eq!(
            u16::from_ne_bytes(msg[4..6].try_into().unwrap()),
            (NFNL_SUBSYS_QUEUE << 8) | NFQNL_MSG_VERDICT
        );
    }

    #[test]
    fn parses_queue_packet_attributes() {
        let mut attrs = Vec::new();
        let mut hdr = Vec::new();
        hdr.extend_from_slice(&42u32.to_be_bytes());
        hdr.extend_from_slice(&0x0800u16.to_be_bytes());
        hdr.push(1);
        hdr.push(0);
        put_attr(&mut attrs, NFQA_PACKET_HDR, &hdr);
        let payload = [
            0x45u8, 0, 0, 20, 0, 0, 0, 0, 64, 1, 0, 0, 192, 0, 2, 1, 198, 51, 100, 1,
        ];
        put_attr(&mut attrs, NFQA_PAYLOAD, &payload);
        let mut msg = vec![0u8; 20];
        msg.extend_from_slice(&attrs);
        fill_nlmsg(&mut msg, 0x300, 0, 1);
        let packet = parse_packet(&msg).expect("packet");
        assert_eq!(packet.id, 42);
        assert_eq!(packet.hook, 1);
        assert_eq!(packet.payload, payload);
    }

    #[test]
    fn rejects_short_message() {
        assert!(parse_packet(&[0u8; 16]).is_none());
    }
}
