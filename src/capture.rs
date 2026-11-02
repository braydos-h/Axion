//! Passive libpcap capture. No injection or traffic modification APIs are used.
use crate::packet::{self, Packet};
use std::sync::{
    atomic::{AtomicBool, AtomicU64, Ordering},
    Arc,
};
use tokio::sync::mpsc;

pub fn interfaces() -> Result<Vec<String>, String> {
    pcap::Device::list()
        .map(|devices| devices.into_iter().map(|d| d.name).collect())
        .map_err(|e| format!("Cannot enumerate capture interfaces: {e}"))
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
    if !interfaces()?.iter().any(|name| name == interface) {
        return Err(format!(
            "Capture interface '{interface}' was not found; run 'axion interfaces'"
        ));
    }
    let mut cap = pcap::Capture::from_device(interface).map_err(|e| format!("Cannot select interface '{interface}': {e}"))?
        .promisc(false).snaplen(65535).timeout(250).open().map_err(|e| format!("Cannot open interface '{interface}': {e}. Check capture permissions and libpcap installation."))?
        .setnonblock().map_err(|e| format!("Cannot configure nonblocking capture on '{interface}': {e}"))?;
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
