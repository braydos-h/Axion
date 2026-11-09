//! Native Linux AF_PACKET capture with recvmmsg batching.
//!
//! Requires CAP_NET_RAW (or root). This is a passive, tap-style backend: it
//! observes frames and cannot enforce policy. Inline enforcement uses NFQUEUE.

use std::ffi::CString;
use std::io;
use std::os::fd::RawFd;
use std::time::SystemTime;

use super::{BufferPool, CapturedFrame, FrameSource};
use crate::config::Config;
use crate::packet::LinkType;

const ETH_P_ALL: u16 = 0x0003;
const SOL_PACKET: libc::c_int = 263;
const PACKET_ADD_MEMBERSHIP: libc::c_int = 1;
const PACKET_MR_PROMISC: libc::c_ushort = 1;
const PACKET_IGNORE_OUTGOING: libc::c_int = 23;

pub struct AfPacketSource {
    fd: RawFd,
    ifindex: i32,
    batch_size: usize,
    name: String,
    snaplen: usize,
}

impl AfPacketSource {
    pub fn open(config: &Config) -> io::Result<Self> {
        let interface = CString::new(config.capture.interface.as_str())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "interface contains NUL"))?;
        // SAFETY: if_nametoindex does not dereference user memory beyond the
        // NUL-terminated C string, which is alive for the call.
        let ifindex = unsafe { libc::if_nametoindex(interface.as_ptr()) };
        if ifindex == 0 {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!(
                    "interface {:?} not found: {}",
                    config.capture.interface,
                    io::Error::last_os_error()
                ),
            ));
        }
        let ifindex = ifindex as i32;

        // SAFETY: standard socket(2) call with constant arguments.
        let fd = unsafe {
            libc::socket(
                libc::AF_PACKET,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                ETH_P_ALL.to_be() as i32,
            )
        };
        if fd < 0 {
            return Err(io::Error::new(
                io::Error::last_os_error().kind(),
                format!(
                    "open AF_PACKET socket failed (CAP_NET_RAW or root required): {}",
                    io::Error::last_os_error()
                ),
            ));
        }
        let source = Self {
            fd,
            ifindex,
            batch_size: config.capture.batch_size.clamp(1, 1024),
            snaplen: config.capture.snaplen.clamp(64, 65_535),
            name: format!("af_packet:{}", config.capture.interface),
        };
        source.configure(config)?;
        Ok(source)
    }

    fn configure(&self, config: &Config) -> io::Result<()> {
        // Bind to the interface and the full EtherType range.
        // SAFETY: sockaddr_ll is a plain-old-data struct; zeroed and fully
        // initialised before use.
        let mut addr: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
        addr.sll_family = libc::AF_PACKET as u16;
        addr.sll_protocol = ETH_P_ALL.to_be();
        addr.sll_ifindex = self.ifindex;
        // SAFETY: addr is properly initialised and sized for bind.
        let rc = unsafe {
            libc::bind(
                self.fd,
                &addr as *const libc::sockaddr_ll as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
            )
        };
        if rc < 0 {
            return Err(io::Error::other(format!(
                "bind AF_PACKET to interface failed: {}",
                io::Error::last_os_error()
            )));
        }

        let rcvbuf = config.capture.buffer_bytes.min(i32::MAX as usize) as i32;
        // SAFETY: setsockopt receives a valid int pointer and length.
        let rc = unsafe {
            libc::setsockopt(
                self.fd,
                libc::SOL_SOCKET,
                libc::SO_RCVBUF,
                &rcvbuf as *const i32 as *const libc::c_void,
                std::mem::size_of::<i32>() as libc::socklen_t,
            )
        };
        if rc < 0 {
            tracing::debug!(error = %io::Error::last_os_error(), "could not set AF_PACKET receive buffer");
        }

        if config.capture.promiscuous {
            let mreq = libc::packet_mreq {
                mr_ifindex: self.ifindex,
                mr_type: PACKET_MR_PROMISC,
                mr_alen: 0,
                mr_address: [0; 8],
            };
            // SAFETY: packet_mreq is valid for SOL_PACKET membership options.
            let rc = unsafe {
                libc::setsockopt(
                    self.fd,
                    SOL_PACKET,
                    PACKET_ADD_MEMBERSHIP,
                    &mreq as *const libc::packet_mreq as *const libc::c_void,
                    std::mem::size_of::<libc::packet_mreq>() as libc::socklen_t,
                )
            };
            if rc < 0 {
                tracing::warn!(error = %io::Error::last_os_error(), "promiscuous mode unavailable");
            }
        }

        if !config.capture.include_outgoing {
            let one: i32 = 1;
            // SAFETY: valid int option for AF_PACKET.
            let rc = unsafe {
                libc::setsockopt(
                    self.fd,
                    SOL_PACKET,
                    PACKET_IGNORE_OUTGOING,
                    &one as *const i32 as *const libc::c_void,
                    std::mem::size_of::<i32>() as libc::socklen_t,
                )
            };
            if rc < 0 {
                tracing::warn!(error = %io::Error::last_os_error(), "PACKET_IGNORE_OUTGOING unavailable");
            }
        }

        let timeout = libc::timeval {
            tv_sec: 0,
            tv_usec: 500_000,
        };
        // SAFETY: timeval is valid for SO_RCVTIMEO.
        let rc = unsafe {
            libc::setsockopt(
                self.fd,
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                &timeout as *const libc::timeval as *const libc::c_void,
                std::mem::size_of::<libc::timeval>() as libc::socklen_t,
            )
        };
        if rc < 0 {
            return Err(io::Error::other(format!(
                "set AF_PACKET timeout failed: {}",
                io::Error::last_os_error()
            )));
        }
        Ok(())
    }
}

impl FrameSource for AfPacketSource {
    fn next_batch(
        &mut self,
        pool: &BufferPool,
        max: usize,
    ) -> io::Result<Option<Vec<CapturedFrame>>> {
        let n = max.clamp(1, self.batch_size);
        let mut buffers: Vec<Vec<u8>> = (0..n).map(|_| pool.acquire()).collect();
        let mut iovecs: Vec<libc::iovec> = buffers
            .iter_mut()
            .map(|buf| libc::iovec {
                iov_base: buf.as_mut_ptr() as *mut libc::c_void,
                iov_len: buf.len(),
            })
            .collect();
        // Keep the raw pointers valid for the duration of recvmmsg.
        let mut msgs: Vec<libc::mmsghdr> = (0..n)
            .map(|i| {
                // SAFETY: mmsghdr is POD; zero initialisation followed by
                // assignment of the iovec pointer and length.
                let mut msg: libc::mmsghdr = unsafe { std::mem::zeroed() };
                msg.msg_hdr.msg_iov = &mut iovecs[i] as *mut libc::iovec;
                msg.msg_hdr.msg_iovlen = 1;
                msg
            })
            .collect();

        // SAFETY: msgs contains `n` valid entries and iovecs/buffers outlive
        // the call for the full duration.
        let received = unsafe {
            libc::recvmmsg(
                self.fd,
                msgs.as_mut_ptr(),
                n as libc::c_uint,
                0,
                std::ptr::null_mut(),
            )
        };
        if received < 0 {
            let err = io::Error::last_os_error();
            for buf in buffers.drain(..) {
                pool.release(buf);
            }
            return match err.kind() {
                io::ErrorKind::WouldBlock
                | io::ErrorKind::TimedOut
                | io::ErrorKind::Interrupted => Ok(Some(Vec::new())),
                _ => Err(err),
            };
        }
        let received = received as usize;
        let lengths: Vec<usize> = msgs
            .iter()
            .take(received)
            .map(|m| (m.msg_len as usize).min(self.snaplen))
            .collect();
        drop(msgs);
        drop(iovecs);

        let timestamp = SystemTime::now();
        let mut frames = Vec::with_capacity(received);
        for (i, mut buf) in buffers.drain(..).enumerate() {
            if i < received {
                buf.truncate(lengths[i]);
                frames.push(CapturedFrame {
                    data: buf,
                    timestamp: Some(timestamp),
                    link_type: LinkType::Ethernet,
                });
            } else {
                pool.release(buf);
            }
        }
        Ok(Some(frames))
    }

    fn name(&self) -> &str {
        &self.name
    }
}

impl Drop for AfPacketSource {
    fn drop(&mut self) {
        // SAFETY: fd is owned by this struct and closed exactly once.
        unsafe {
            libc::close(self.fd);
        }
    }
}
