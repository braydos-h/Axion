//! Packet capture backends and the bounded multi-worker processing pipeline.

pub mod af_packet;
pub mod libpcap;

use std::io;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, SystemTime};

use crossbeam_channel::{bounded, RecvTimeoutError};
use parking_lot::Mutex;

use crate::config::{CaptureBackend, Config};
use crate::engine::Engine;
use crate::packet::{LinkType, PcapReader};

#[derive(Debug)]
pub struct CapturedFrame {
    pub data: Vec<u8>,
    pub timestamp: Option<SystemTime>,
    pub link_type: LinkType,
}

pub trait FrameSource: Send {
    /// Returns `None` at end-of-file for offline sources. A live source may
    /// return an empty batch on timeout.
    fn next_batch(
        &mut self,
        pool: &BufferPool,
        max: usize,
    ) -> io::Result<Option<Vec<CapturedFrame>>>;

    fn name(&self) -> &str;
}

/// Reusable packet buffers. The pool itself is bounded; the bounded channel
/// between capture and workers bounds in-flight memory independently.
pub struct BufferPool {
    buffers: Mutex<Vec<Vec<u8>>>,
    max_buffers: usize,
    snaplen: usize,
}

impl BufferPool {
    pub fn new(max_buffers: usize, snaplen: usize) -> Self {
        Self {
            buffers: Mutex::new(Vec::new()),
            max_buffers: max_buffers.max(1),
            snaplen: snaplen.clamp(64, 65_535),
        }
    }

    pub fn acquire(&self) -> Vec<u8> {
        let mut buffers = self.buffers.lock();
        if let Some(mut buf) = buffers.pop() {
            buf.clear();
            buf.resize(self.snaplen, 0);
            return buf;
        }
        vec![0u8; self.snaplen]
    }

    pub fn release(&self, mut buf: Vec<u8>) {
        buf.clear();
        let mut buffers = self.buffers.lock();
        if buffers.len() < self.max_buffers {
            buffers.push(buf);
        }
    }

    pub fn snaplen(&self) -> usize {
        self.snaplen
    }
}

pub struct OfflinePcapSource {
    name: String,
    reader: PcapReader<std::io::BufReader<std::fs::File>>,
}

impl OfflinePcapSource {
    pub fn open(path: &Path) -> io::Result<Self> {
        Ok(Self {
            name: format!("pcap:{}", path.display()),
            reader: PcapReader::open(path)?,
        })
    }
}

impl FrameSource for OfflinePcapSource {
    fn next_batch(
        &mut self,
        pool: &BufferPool,
        max: usize,
    ) -> io::Result<Option<Vec<CapturedFrame>>> {
        let mut frames = Vec::with_capacity(max.min(64));
        for _ in 0..max {
            match self.reader.next_record()? {
                Some(record) => {
                    let mut buf = pool.acquire();
                    buf.clear();
                    let take = record.data.len().min(pool.snaplen());
                    buf.extend_from_slice(&record.data[..take]);
                    frames.push(CapturedFrame {
                        data: buf,
                        timestamp: record.timestamp,
                        link_type: record.link_type,
                    });
                }
                None => break,
            }
        }
        if frames.is_empty() {
            Ok(None)
        } else {
            Ok(Some(frames))
        }
    }

    fn name(&self) -> &str {
        &self.name
    }
}

pub fn open_source(config: &Config) -> io::Result<Box<dyn FrameSource>> {
    if let Some(path) = &config.capture.pcap_file {
        return Ok(Box::new(OfflinePcapSource::open(path)?));
    }
    match config.capture.backend {
        CaptureBackend::None => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "capture backend is disabled",
        )),
        CaptureBackend::AfPacket => Ok(Box::new(af_packet::AfPacketSource::open(config)?)),
        CaptureBackend::Libpcap => Ok(Box::new(libpcap::LibpcapSource::open(config)?)),
        CaptureBackend::Auto => match af_packet::AfPacketSource::open(config) {
            Ok(source) => Ok(Box::new(source)),
            Err(af_err) => match libpcap::LibpcapSource::open(config) {
                Ok(source) => Ok(Box::new(source)),
                Err(pcap_err) => Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!("no usable capture backend: AF_PACKET: {af_err}; libpcap: {pcap_err}"),
                )),
            },
        },
    }
}

pub struct CapturePipeline {
    running: Arc<AtomicBool>,
    capture_thread: Option<JoinHandle<()>>,
    workers: Vec<JoinHandle<()>>,
    worker_count: usize,
    source_name: String,
    capture_drops: Arc<AtomicU64>,
    finished: Arc<AtomicBool>,
}

impl CapturePipeline {
    pub fn start(engine: Arc<Engine>, config: &Config) -> io::Result<Self> {
        let source = open_source(config)?;
        let source_name = source.name().to_string();
        let worker_count = config.effective_worker_threads();
        let queue_capacity = config.capture.queue_capacity.max(worker_count * 16);
        let batch_size = config.capture.batch_size;
        let pool = Arc::new(BufferPool::new(
            (batch_size * worker_count * 2).clamp(64, 4096),
            config.capture.snaplen,
        ));
        let running = Arc::new(AtomicBool::new(true));
        let capture_drops = Arc::new(AtomicU64::new(0));
        let finished = Arc::new(AtomicBool::new(false));
        let (tx, rx) = bounded::<CapturedFrame>(queue_capacity);

        let mut workers = Vec::with_capacity(worker_count);
        for _ in 0..worker_count {
            let rx = rx.clone();
            let engine = Arc::clone(&engine);
            let pool = Arc::clone(&pool);
            let running = Arc::clone(&running);
            workers.push(
                std::thread::Builder::new()
                    .name("axion-worker".to_string())
                    .spawn(move || {
                        while running.load(Ordering::Relaxed) {
                            match rx.recv_timeout(Duration::from_millis(100)) {
                                Ok(frame) => {
                                    engine.process_link_frame(
                                        frame.link_type,
                                        &frame.data,
                                        frame.timestamp,
                                    );
                                    pool.release(frame.data);
                                }
                                Err(RecvTimeoutError::Timeout) => continue,
                                Err(RecvTimeoutError::Disconnected) => break,
                            }
                        }
                        // Drain anything already queued, then release buffers.
                        while let Ok(frame) = rx.try_recv() {
                            engine.process_link_frame(
                                frame.link_type,
                                &frame.data,
                                frame.timestamp,
                            );
                            pool.release(frame.data);
                        }
                    })
                    .map_err(io::Error::other)?,
            );
        }

        let capture_running = Arc::clone(&running);
        let capture_pool = Arc::clone(&pool);
        let capture_engine = Arc::clone(&engine);
        let capture_drops_thread = Arc::clone(&capture_drops);
        let capture_finished = Arc::clone(&finished);
        let mut source = source;
        let capture_thread = std::thread::Builder::new()
            .name("axion-capture".to_string())
            .spawn(move || {
                let mut source_name = source.name().to_string();
                loop {
                    if !capture_running.load(Ordering::Relaxed) {
                        break;
                    }
                    match source.next_batch(&capture_pool, batch_size) {
                        Ok(Some(frames)) => {
                            for frame in frames {
                                match tx.send_timeout(frame, Duration::from_millis(100)) {
                                    Ok(()) => {}
                                    Err(crossbeam_channel::SendTimeoutError::Timeout(frame)) => {
                                        capture_drops_thread.fetch_add(1, Ordering::Relaxed);
                                        capture_engine.telemetry().metrics.record_capture_drop();
                                        capture_pool.release(frame.data);
                                    }
                                    Err(crossbeam_channel::SendTimeoutError::Disconnected(frame)) => {
                                        capture_pool.release(frame.data);
                                        return;
                                    }
                                }
                            }
                        }
                        Ok(None) => {
                            tracing::info!(source = %source_name, "capture source reached end of input");
                            break;
                        }
                        Err(err) => {
                            tracing::error!(source = %source_name, error = %err, "capture read error");
                            // A persistent permission/interface error should
                            // stop capture rather than spin.
                            break;
                        }
                    }
                }
                drop(tx);
                source_name.push_str(" (stopped)");
                capture_finished.store(true, Ordering::Relaxed);
            })
            .map_err(io::Error::other)?;

        tracing::info!(
            source = %source_name,
            workers = worker_count,
            queue = queue_capacity,
            "capture pipeline started"
        );
        Ok(Self {
            running,
            capture_thread: Some(capture_thread),
            workers,
            worker_count,
            source_name,
            capture_drops,
            finished,
        })
    }

    pub fn shutdown(&mut self) {
        self.running.store(false, Ordering::Relaxed);
        if let Some(handle) = self.capture_thread.take() {
            let _ = handle.join();
        }
        for worker in self.workers.drain(..) {
            let _ = worker.join();
        }
    }

    pub fn worker_count(&self) -> usize {
        self.worker_count
    }

    pub fn source_name(&self) -> &str {
        &self.source_name
    }

    pub fn capture_drops(&self) -> u64 {
        self.capture_drops.load(Ordering::Relaxed)
    }

    /// True once a finite source (pcap file) or a failed live source ended.
    pub fn finished(&self) -> bool {
        self.finished.load(Ordering::Relaxed)
    }
}

impl Drop for CapturePipeline {
    fn drop(&mut self) {
        self.shutdown();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn buffer_pool_reuses_buffers() {
        let pool = BufferPool::new(4, 128);
        let buf = pool.acquire();
        assert_eq!(buf.len(), 128);
        let ptr = buf.as_ptr();
        pool.release(buf);
        let buf2 = pool.acquire();
        assert_eq!(buf2.len(), 128);
        assert_eq!(buf2.as_ptr(), ptr);
    }

    #[test]
    fn buffer_pool_is_bounded() {
        let pool = BufferPool::new(2, 64);
        pool.release(vec![0; 64]);
        pool.release(vec![0; 64]);
        pool.release(vec![0; 64]);
        assert_eq!(pool.buffers.lock().len(), 2);
    }
}
