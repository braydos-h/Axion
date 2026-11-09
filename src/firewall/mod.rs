//! Inline enforcement backend. NFQUEUE supports ACCEPT and DROP directly;
//! REJECT is deliberately enforced as DROP (the kernel-side rule can provide
//! TCP reset/ICMP reject semantics if required).

pub mod nfqueue;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::Duration;

use crate::engine::Engine;
use nfqueue::{NfQueue, Verdict};

pub struct EnforcementHandle {
    shutdown: Arc<AtomicBool>,
    running: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
    queue_num: u16,
}

pub fn spawn(
    engine: Arc<Engine>,
    mut queue: NfQueue,
    shutdown: Arc<AtomicBool>,
    batch_size: usize,
) -> std::io::Result<EnforcementHandle> {
    let queue_num = queue.queue_num();
    let worker_shutdown = Arc::clone(&shutdown);
    let running = Arc::new(AtomicBool::new(true));
    let worker_running = Arc::clone(&running);
    let thread = std::thread::Builder::new()
        .name("axion-nfqueue".to_string())
        .spawn(move || {
            tracing::info!(
                queue = queue_num,
                fail_open = queue.fail_open(),
                "NFQUEUE enforcement loop started"
            );
            loop {
                if worker_shutdown.load(Ordering::Relaxed) {
                    break;
                }
                match queue.recv_batch(batch_size) {
                    Ok(packets) => {
                        if packets.is_empty() {
                            continue;
                        }
                        let mut verdicts = Vec::with_capacity(packets.len());
                        for packet in packets {
                            let result = engine.process_l3_frame(&packet.payload, packet.timestamp);
                            verdicts.push((
                                packet.id,
                                if result.blocked {
                                    Verdict::Drop
                                } else {
                                    Verdict::Accept
                                },
                            ));
                        }
                        if let Err(err) = queue.send_verdicts(&verdicts) {
                            engine.telemetry().metrics.record_enforcement_error();
                            tracing::error!(
                                error = %err,
                                queue = queue_num,
                                "failed to send NFQUEUE verdicts"
                            );
                            std::thread::sleep(Duration::from_millis(50));
                        }
                    }
                    Err(err) => {
                        engine.telemetry().metrics.record_enforcement_error();
                        tracing::error!(
                            error = %err,
                            queue = queue_num,
                            fail_open = queue.fail_open(),
                            "NFQUEUE receive error"
                        );
                        if err.kind() == std::io::ErrorKind::PermissionDenied
                            || err.raw_os_error() == Some(libc::EBADF)
                        {
                            engine.set_backend("nfqueue-failed");
                            worker_running.store(false, Ordering::Relaxed);
                            break;
                        }
                        std::thread::sleep(Duration::from_millis(100));
                    }
                }
            }
            queue.unbind();
            worker_running.store(false, Ordering::Relaxed);
            engine.set_backend("nfqueue-stopped");
            tracing::info!(queue = queue_num, "NFQUEUE enforcement loop stopped");
        })
        .map_err(std::io::Error::other)?;

    Ok(EnforcementHandle {
        shutdown,
        running,
        thread: Some(thread),
        queue_num,
    })
}

impl EnforcementHandle {
    pub fn queue_num(&self) -> u16 {
        self.queue_num
    }

    /// False once the verdict loop has exited unexpectedly or after shutdown.
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::Relaxed) && self.thread.is_some()
    }

    pub fn stop(mut self) {
        self.shutdown.store(true, Ordering::Relaxed);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

impl Drop for EnforcementHandle {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Relaxed);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}
