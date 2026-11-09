//! Optional libpcap capture backend.
//!
//! libpcap is loaded dynamically at runtime (`libpcap.so.1`), so building Axion
//! does not require libpcap headers or a C toolchain. If the library or
//! permission is unavailable, AF_PACKET remains the native default.

use std::ffi::{c_char, c_int, c_void, CStr, CString};
use std::io;
use std::time::{Duration, UNIX_EPOCH};

use libloading::Library;

use super::{BufferPool, CapturedFrame, FrameSource};
use crate::config::Config;
use crate::packet::LinkType;

#[repr(C)]
struct PcapPkthdr {
    ts: libc::timeval,
    caplen: u32,
    len: u32,
}

type PcapOpenLive = unsafe extern "C" fn(
    device: *const c_char,
    snaplen: c_int,
    promisc: c_int,
    to_ms: c_int,
    errbuf: *mut c_char,
) -> *mut c_void;
type PcapNextEx = unsafe extern "C" fn(*mut c_void, *mut *mut PcapPkthdr, *mut *const u8) -> c_int;
type PcapDatalink = unsafe extern "C" fn(*mut c_void) -> c_int;
type PcapClose = unsafe extern "C" fn(*mut c_void);
type PcapGetErr = unsafe extern "C" fn(*mut c_void) -> *const c_char;

pub struct LibpcapSource {
    _lib: Library,
    handle: *mut c_void,
    next_ex: PcapNextEx,
    close: PcapClose,
    geterr: PcapGetErr,
    link_type: LinkType,
    name: String,
    snaplen: usize,
}

// The capture handle is used from one capture thread only. The raw pointer is
// not shared; FrameSource is moved into that thread by CapturePipeline.
unsafe impl Send for LibpcapSource {}

impl LibpcapSource {
    pub fn open(config: &Config) -> io::Result<Self> {
        let lib = ["libpcap.so.1", "libpcap.so.0.8", "libpcap.so"]
            .iter()
            .find_map(|name| {
                // SAFETY: loading a system shared library. Symbols are resolved
                // below and remain valid while `lib` is alive in this struct.
                unsafe { Library::new(name).ok() }
            })
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotFound,
                    "libpcap.so not found; install libpcap or use backend = \"af_packet\"",
                )
            })?;

        // SAFETY: symbol names are NUL-terminated and the signatures match
        // libpcap's public ABI.
        let open: PcapOpenLive = unsafe {
            *lib.get::<PcapOpenLive>(b"pcap_open_live\0")
                .map_err(|e| io::Error::other(format!("pcap_open_live missing: {e}")))?
        };
        // SAFETY: as above.
        let next_ex: PcapNextEx = unsafe {
            *lib.get::<PcapNextEx>(b"pcap_next_ex\0")
                .map_err(|e| io::Error::other(format!("pcap_next_ex missing: {e}")))?
        };
        // SAFETY: as above.
        let datalink: PcapDatalink = unsafe {
            *lib.get::<PcapDatalink>(b"pcap_datalink\0")
                .map_err(|e| io::Error::other(format!("pcap_datalink missing: {e}")))?
        };
        // SAFETY: as above.
        let close: PcapClose = unsafe {
            *lib.get::<PcapClose>(b"pcap_close\0")
                .map_err(|e| io::Error::other(format!("pcap_close missing: {e}")))?
        };
        // SAFETY: as above.
        let geterr: PcapGetErr = unsafe {
            *lib.get::<PcapGetErr>(b"pcap_geterr\0")
                .map_err(|e| io::Error::other(format!("pcap_geterr missing: {e}")))?
        };

        let device = CString::new(config.capture.interface.as_str())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "interface contains NUL"))?;
        let mut errbuf = [0 as c_char; 256];
        // SAFETY: errbuf is 256 writable bytes as required by libpcap.
        let handle = unsafe {
            open(
                device.as_ptr(),
                config.capture.snaplen.min(65_535) as c_int,
                if config.capture.promiscuous { 1 } else { 0 },
                500,
                errbuf.as_mut_ptr(),
            )
        };
        if handle.is_null() {
            // SAFETY: libpcap guarantees a NUL-terminated errbuf on failure.
            let message = unsafe { CStr::from_ptr(errbuf.as_ptr()) }
                .to_string_lossy()
                .into_owned();
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("pcap_open_live failed: {message}"),
            ));
        }

        // SAFETY: handle was returned by pcap_open_live.
        let dlt = unsafe { datalink(handle) } as u32;
        let Some(link_type) = LinkType::from_u32(dlt) else {
            // SAFETY: handle is valid and owned here.
            unsafe { close(handle) };
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!("libpcap returned unsupported datalink type {dlt}"),
            ));
        };
        Ok(Self {
            _lib: lib,
            handle,
            next_ex,
            close,
            geterr,
            link_type,
            name: format!("libpcap:{}", config.capture.interface),
            snaplen: config.capture.snaplen.clamp(64, 65_535),
        })
    }

    fn error_string(&self) -> String {
        // SAFETY: handle is valid for the lifetime of self.
        let ptr = unsafe { (self.geterr)(self.handle) };
        if ptr.is_null() {
            "unknown libpcap error".to_string()
        } else {
            // SAFETY: libpcap returns a NUL-terminated string.
            unsafe { CStr::from_ptr(ptr) }
                .to_string_lossy()
                .into_owned()
        }
    }
}

impl FrameSource for LibpcapSource {
    fn next_batch(
        &mut self,
        pool: &BufferPool,
        max: usize,
    ) -> io::Result<Option<Vec<CapturedFrame>>> {
        let mut frames = Vec::with_capacity(max.min(64));
        for _ in 0..max {
            let mut header: *mut PcapPkthdr = std::ptr::null_mut();
            let mut data: *const u8 = std::ptr::null();
            // SAFETY: pointers are valid out-parameters for pcap_next_ex.
            let rc = unsafe { (self.next_ex)(self.handle, &mut header, &mut data) };
            match rc {
                1 => {
                    if header.is_null() || data.is_null() {
                        return Err(io::Error::other("libpcap returned a null packet"));
                    }
                    // SAFETY: for rc=1 libpcap filled the header/data pointers.
                    let hdr = unsafe { &*header };
                    let caplen = (hdr.caplen as usize).min(self.snaplen);
                    // SAFETY: caplen bytes are valid for the captured packet.
                    let bytes = unsafe { std::slice::from_raw_parts(data, caplen) };
                    let mut buf = pool.acquire();
                    buf.clear();
                    buf.extend_from_slice(bytes);
                    let secs = hdr.ts.tv_sec.max(0) as u64;
                    let usec = hdr.ts.tv_usec.clamp(0, 999_999) as u32;
                    frames.push(CapturedFrame {
                        data: buf,
                        timestamp: Some(UNIX_EPOCH + Duration::new(secs, usec * 1000)),
                        link_type: self.link_type,
                    });
                }
                0 => break, // live timeout
                -2 => {
                    if frames.is_empty() {
                        return Ok(None);
                    }
                    break;
                }
                _ => {
                    return Err(io::Error::other(after_error(self.error_string())));
                }
            }
        }
        Ok(Some(frames))
    }

    fn name(&self) -> &str {
        &self.name
    }
}

fn after_error(message: String) -> String {
    format!("libpcap read error: {message}")
}

impl Drop for LibpcapSource {
    fn drop(&mut self) {
        if !self.handle.is_null() {
            // SAFETY: handle is owned by this struct and closed once.
            unsafe { (self.close)(self.handle) };
            self.handle = std::ptr::null_mut();
        }
    }
}
