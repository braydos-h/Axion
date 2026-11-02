//! Passive libpcap capture. No injection or traffic modification APIs are used.
use crate::{
    packet::{self, Packet},
    state::AppState,
};
use serde::Serialize;
use std::net::{IpAddr, UdpSocket};
use std::sync::{
    atomic::{AtomicBool, AtomicU64, Ordering},
    Arc,
};
use tokio::sync::mpsc;
use tokio::sync::{oneshot, Mutex};

#[derive(Clone, Debug, Serialize)]
pub struct Interface {
    pub name: String,
    pub description: Option<String>,
    pub addresses: Vec<IpAddr>,
    pub loopback: bool,
    pub up: bool,
    pub running: bool,
    pub wireless: bool,
}

pub fn interface_details() -> Result<Vec<Interface>, String> {
    pcap::Device::list()
        .map(|devices| {
            devices
                .into_iter()
                .map(|d| Interface {
                    name: d.name,
                    description: d.desc,
                    addresses: d.addresses.into_iter().map(|a| a.addr).collect(),
                    loopback: d.flags.is_loopback(),
                    up: d.flags.is_up(),
                    running: d.flags.is_running(),
                    wireless: d.flags.is_wireless(),
                })
                .collect()
        })
        .map_err(|e| format!("Cannot enumerate capture interfaces: {e}"))
}
pub fn interfaces() -> Result<Vec<String>, String> {
    Ok(interface_details()?.into_iter().map(|d| d.name).collect())
}

// UDP connect selects a route locally; it does not transmit a packet.
fn route_address() -> Option<IpAddr> {
    let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect("192.0.2.1:9").ok()?;
    Some(socket.local_addr().ok()?.ip())
}

pub fn choose_interface(devices: &[Interface], route: Option<IpAddr>) -> Result<String, String> {
    if let Some(route) = route {
        let matches: Vec<_> = devices
            .iter()
            .filter(|d| d.addresses.contains(&route) && !d.loopback)
            .collect();
        if matches.len() == 1 {
            return Ok(matches[0].name.clone());
        }
    }
    let candidates: Vec<_> = devices
        .iter()
        .filter(|d| !d.loopback && d.up && d.running && !d.addresses.is_empty())
        .collect();
    match candidates.as_slice() {
        [device] => Ok(device.name.clone()),
        [] => Err("No active capture interface found. Select an interface manually or use demo/replay mode.".into()),
        _ => Err("Multiple capture interfaces are suitable. Select one in the dashboard or with --interface.".into()),
    }
}
pub fn auto_interface() -> Result<String, String> {
    choose_interface(&interface_details()?, route_address())
}

/// Serializes lifecycle operations and owns the currently running live source.
pub struct Manager {
    worker: Mutex<Option<(Arc<AtomicBool>, tokio::task::JoinHandle<()>)>>,
    tx: mpsc::Sender<Packet>,
    dropped: Arc<AtomicU64>,
    raw_packets: Arc<AtomicU64>,
    raw_bytes: Arc<AtomicU64>,
    #[cfg(test)]
    fake: bool,
}
impl Manager {
    pub fn new(
        tx: mpsc::Sender<Packet>,
        dropped: Arc<AtomicU64>,
        raw_packets: Arc<AtomicU64>,
        raw_bytes: Arc<AtomicU64>,
    ) -> Self {
        Self {
            worker: Mutex::new(None),
            tx,
            dropped,
            raw_packets,
            raw_bytes,
            #[cfg(test)]
            fake: false,
        }
    }
    pub async fn start(&self, state: AppState, requested: String) -> Result<(), String> {
        let mut worker = self.worker.lock().await;
        if let Some((_, handle)) = worker.as_ref() {
            if !handle.is_finished() {
                return Err("Capture is already running".into());
            }
        }
        if let Some((_, handle)) = worker.take() {
            let _ = handle.await;
        }
        #[cfg(test)]
        let fake = self.fake;
        #[cfg(not(test))]
        let fake = false;
        let interface = if fake {
            if requested == "missing" {
                return Err("Interface not found".into());
            }
            requested
        } else {
            tokio::task::spawn_blocking(move || {
                if requested == "auto" || requested.is_empty() {
                    auto_interface()
                } else if interfaces()?.contains(&requested) {
                    Ok(requested)
                } else {
                    Err(format!("Capture interface '{requested}' was not found"))
                }
            })
            .await
            .map_err(|e| format!("Interface discovery failed: {e}"))??
        };
        let stop = Arc::new(AtomicBool::new(false));
        let worker_stop = stop.clone();
        let name = interface.clone();
        let tx = self.tx.clone();
        let dropped = self.dropped.clone();
        let packets = self.raw_packets.clone();
        let bytes = self.raw_bytes.clone();
        let (ready_tx, ready_rx) = oneshot::channel();
        let (published_tx, published_rx) = oneshot::channel();
        let source_state = state.clone();
        let handle = tokio::spawn(async move {
            let result = if fake {
                let _ = ready_tx.send(Ok(()));
                while !worker_stop.load(Ordering::Relaxed) {
                    tokio::time::sleep(std::time::Duration::from_millis(1)).await;
                }
                Ok(Ok(()))
            } else {
                tokio::task::spawn_blocking(move || {
                    live_inner(
                        &name,
                        tx,
                        worker_stop,
                        dropped,
                        packets,
                        bytes,
                        Some(ready_tx),
                    )
                })
                .await
            };
            let _ = published_rx.await;
            let error = match result {
                Ok(Ok(())) => None,
                Ok(Err(e)) => Some(e),
                Err(e) => Some(format!("Capture task failed: {e}")),
            };
            let mut inner = source_state.inner.write().await;
            inner.status.capture_running = false;
            inner.status.last_error = error;
            let status = inner.status.clone();
            drop(inner);
            source_state.emit("status", &status);
        });
        match ready_rx.await {
            Ok(Ok(())) => {
                let mut inner = state.inner.write().await;
                inner.status.capture_running = true;
                inner.status.interface = interface;
                inner.status.mode = "live".into();
                inner.status.last_error = None;
                let status = inner.status.clone();
                drop(inner);
                state.emit("status", &status);
                *worker = Some((stop, handle));
                let _ = published_tx.send(());
                Ok(())
            }
            Ok(Err(e)) => {
                let _ = published_tx.send(());
                let _ = handle.await;
                Err(e)
            }
            Err(_) => {
                let _ = published_tx.send(());
                let _ = handle.await;
                Err("Capture worker stopped during startup".into())
            }
        }
    }
    pub async fn stop(&self, state: AppState) -> Result<(), String> {
        let mut worker = self.worker.lock().await;
        if let Some((stop, handle)) = worker.take() {
            stop.store(true, Ordering::Relaxed);
            handle
                .await
                .map_err(|e| format!("Capture task failed: {e}"))?;
        }
        let mut inner = state.inner.write().await;
        inner.status.capture_running = false;
        let status = inner.status.clone();
        drop(inner);
        state.emit("status", &status);
        Ok(())
    }
    pub async fn restart(&self, state: AppState, interface: String) -> Result<(), String> {
        // Callers serialize lifecycle requests through AppState::capture_control.
        self.stop(state.clone()).await?;
        self.start(state, interface).await
    }
}
fn timestamp(header: &pcap::PacketHeader) -> u64 {
    let sec = u64::try_from(header.ts.tv_sec).unwrap_or(0);
    let usec = u64::try_from(header.ts.tv_usec).unwrap_or(0);
    sec.saturating_mul(1000).saturating_add(usec / 1000)
}
/// Run on a blocking worker. Nonblocking reads permit shutdown even on an idle interface.
pub fn live(
    interface: &str,
    tx: mpsc::Sender<Packet>,
    shutdown: Arc<AtomicBool>,
    dropped: Arc<AtomicU64>,
    raw_packets: Arc<AtomicU64>,
    raw_bytes: Arc<AtomicU64>,
) -> Result<(), String> {
    live_inner(
        interface,
        tx,
        shutdown,
        dropped,
        raw_packets,
        raw_bytes,
        None,
    )
}
fn live_inner(
    interface: &str,
    tx: mpsc::Sender<Packet>,
    shutdown: Arc<AtomicBool>,
    dropped: Arc<AtomicU64>,
    raw_packets: Arc<AtomicU64>,
    raw_bytes: Arc<AtomicU64>,
    ready: Option<oneshot::Sender<Result<(), String>>>,
) -> Result<(), String> {
    let opened = (|| {
        pcap::Capture::from_device(interface).map_err(|e| format!("Cannot select interface '{interface}': {e}"))?
            .promisc(false).snaplen(65535).timeout(250).open().map_err(|e| format!("Cannot open interface '{interface}': {e}. Check capture permissions and libpcap installation."))?
            .setnonblock().map_err(|e| format!("Cannot configure nonblocking capture on '{interface}': {e}"))
    })();
    let mut cap = match opened {
        Ok(cap) => {
            if let Some(ready) = ready {
                let _ = ready.send(Ok(()));
            }
            cap
        }
        Err(error) => {
            if let Some(ready) = ready {
                let _ = ready.send(Err(error.clone()));
            }
            return Err(error);
        }
    };
    let linktype = cap.get_datalink().0;
    let mut last_interface_check = std::time::Instant::now();
    while !shutdown.load(Ordering::Relaxed) {
        if last_interface_check.elapsed() >= std::time::Duration::from_secs(5) {
            if !interfaces()?.iter().any(|name| name == interface) {
                return Err(format!("Capture interface '{interface}' disappeared. Select another interface and restart capture."));
            }
            last_interface_check = std::time::Instant::now();
        }
        match cap.next_packet() {
            Ok(packet) => {
                raw_packets.fetch_add(1, Ordering::Relaxed);
                raw_bytes.fetch_add(u64::from(packet.header.len), Ordering::Relaxed);
                if let Some(event) = packet::parse(
                    packet.data,
                    packet.header.len,
                    timestamp(packet.header),
                    linktype,
                ) {
                    if tx.try_send(event).is_err() {
                        dropped.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
            Err(pcap::Error::TimeoutExpired) => {
                std::thread::sleep(std::time::Duration::from_millis(10))
            }
            Err(e) => return Err(format!("Capture failed: {e}")),
        }
    }
    Ok(())
}
/// Offline replay uses backpressure so a fixture is not silently lost to a full queue.
pub fn replay(
    path: &str,
    tx: mpsc::Sender<Packet>,
    shutdown: Arc<AtomicBool>,
    _dropped: Arc<AtomicU64>,
    raw_packets: Arc<AtomicU64>,
    raw_bytes: Arc<AtomicU64>,
) -> Result<(), String> {
    let mut cap =
        pcap::Capture::from_file(path).map_err(|e| format!("Cannot open capture '{path}': {e}"))?;
    let linktype = cap.get_datalink().0;
    while !shutdown.load(Ordering::Relaxed) {
        match cap.next_packet() {
            Ok(packet) => {
                raw_packets.fetch_add(1, Ordering::Relaxed);
                raw_bytes.fetch_add(u64::from(packet.header.len), Ordering::Relaxed);
                if let Some(event) = packet::parse(
                    packet.data,
                    packet.header.len,
                    timestamp(packet.header),
                    linktype,
                ) {
                    if tx.blocking_send(event).is_err() {
                        break;
                    }
                }
            }
            Err(pcap::Error::NoMorePackets) => break,
            Err(e) => return Err(format!("Cannot read capture '{path}': {e}")),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn device(name: &str, ip: &str, loopback: bool) -> Interface {
        Interface {
            name: name.into(),
            description: None,
            addresses: vec![ip.parse().unwrap()],
            loopback,
            up: true,
            running: true,
            wireless: false,
        }
    }
    #[test]
    fn selection_prefers_route_and_reports_ambiguity() {
        let devices = vec![
            device("vpn", "10.1.0.2", false),
            device("wifi", "192.168.1.2", false),
            device("loop", "127.0.0.1", true),
        ];
        assert_eq!(
            choose_interface(&devices, Some("10.1.0.2".parse().unwrap())).unwrap(),
            "vpn"
        );
        assert!(choose_interface(&devices, None)
            .unwrap_err()
            .contains("Multiple"));
        assert_eq!(choose_interface(&devices[1..], None).unwrap(), "wifi");
        assert!(choose_interface(&devices[2..], None).is_err());
    }
    #[tokio::test]
    async fn lifecycle_rejects_missing_interface_and_stop_is_idempotent() {
        let (tx, _rx) = mpsc::channel(8);
        let manager = Manager::new(
            tx,
            Arc::new(AtomicU64::new(0)),
            Arc::new(AtomicU64::new(0)),
            Arc::new(AtomicU64::new(0)),
        );
        let state = AppState::new(crate::state::Status {
            capture_running: false,
            ai_status: "disabled".into(),
            interface: "".into(),
            mode: "live".into(),
            ai_enabled: false,
            last_error: None,
        });
        let mut events = state.events.subscribe();
        assert!(manager
            .start(state.clone(), "axion-interface-that-does-not-exist".into())
            .await
            .is_err());
        manager.stop(state.clone()).await.unwrap();
        manager.stop(state.clone()).await.unwrap();
        assert!(!state.inner.read().await.status.capture_running);
        assert_eq!(events.try_recv().unwrap().kind, "status");
    }
    #[tokio::test]
    async fn lifecycle_starts_restarts_switches_and_stops_without_duplicate_workers() {
        let (tx, _rx) = mpsc::channel(8);
        let mut manager = Manager::new(
            tx,
            Arc::new(AtomicU64::new(0)),
            Arc::new(AtomicU64::new(0)),
            Arc::new(AtomicU64::new(0)),
        );
        manager.fake = true;
        let state = AppState::new(crate::state::Status {
            capture_running: false,
            ai_status: "disabled".into(),
            interface: "".into(),
            mode: "live".into(),
            ai_enabled: false,
            last_error: None,
        });
        let mut events = state.events.subscribe();
        manager.start(state.clone(), "first".into()).await.unwrap();
        assert!(state.inner.read().await.status.capture_running);
        assert!(manager.start(state.clone(), "second".into()).await.is_err());
        manager
            .restart(state.clone(), "second".into())
            .await
            .unwrap();
        assert_eq!(state.inner.read().await.status.interface, "second");
        assert!(state.inner.read().await.status.capture_running);
        manager.stop(state.clone()).await.unwrap();
        assert!(!state.inner.read().await.status.capture_running);
        let statuses: Vec<_> = std::iter::from_fn(|| events.try_recv().ok()).collect();
        assert!(statuses.iter().any(|e| e.data["capture_running"] == true));
        assert!(statuses.iter().any(|e| e.data["capture_running"] == false));
        assert!(manager
            .start(state.clone(), "missing".into())
            .await
            .is_err());
    }
    /// Generates a deterministic little-endian Ethernet PCAP without external tools.
    #[test]
    fn replay_generated_pcap() {
        let mut packet = Vec::new();
        etherparse::PacketBuilder::ethernet2([1; 6], [2; 6])
            .ipv4([10, 0, 0, 1], [10, 0, 0, 2], 64)
            .tcp(1234, 443, 42, 1024)
            .syn()
            .write(&mut packet, &[])
            .unwrap();
        let path = std::env::temp_dir().join(format!("axion-replay-{}.pcap", std::process::id()));
        let mut file = std::fs::File::create(&path).unwrap();
        file.write_all(&0xa1b2c3d4u32.to_le_bytes()).unwrap();
        file.write_all(&2u16.to_le_bytes()).unwrap();
        file.write_all(&4u16.to_le_bytes()).unwrap();
        file.write_all(&0i32.to_le_bytes()).unwrap();
        file.write_all(&0u32.to_le_bytes()).unwrap();
        file.write_all(&65535u32.to_le_bytes()).unwrap();
        file.write_all(&1u32.to_le_bytes()).unwrap();
        file.write_all(&1234u32.to_le_bytes()).unwrap();
        file.write_all(&500_000u32.to_le_bytes()).unwrap();
        file.write_all(&(packet.len() as u32).to_le_bytes())
            .unwrap();
        file.write_all(&(packet.len() as u32).to_le_bytes())
            .unwrap();
        file.write_all(&packet).unwrap();
        drop(file);
        let (tx, mut rx) = mpsc::channel(2);
        let raw_packets = Arc::new(AtomicU64::new(0));
        let raw_bytes = Arc::new(AtomicU64::new(0));
        replay(
            path.to_str().unwrap(),
            tx,
            Arc::new(AtomicBool::new(false)),
            Arc::new(AtomicU64::new(0)),
            raw_packets.clone(),
            raw_bytes.clone(),
        )
        .unwrap();
        assert_eq!(raw_packets.load(Ordering::Relaxed), 1);
        assert_eq!(raw_bytes.load(Ordering::Relaxed), packet.len() as u64);
        let event = rx.try_recv().unwrap();
        assert_eq!(event.timestamp_ms, 1_234_500);
        assert_eq!(event.src.port(), 1234);
        assert_eq!(event.dst.port(), 443);
        std::fs::remove_file(path).unwrap();
    }
}
