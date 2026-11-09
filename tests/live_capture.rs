//! Privileged capture/enforcement smoke tests.
//!
//! Run explicitly: `sudo -E cargo test --test live_capture -- --ignored --nocapture`.
//! Tests skip cleanly when the kernel or capabilities are unavailable.

#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires CAP_NET_RAW/root"]
fn af_packet_loopback_captures_udp() {
    use std::net::UdpSocket;
    use std::time::{Duration, Instant};

    use axion::capture::af_packet::AfPacketSource;
    use axion::capture::{BufferPool, FrameSource};
    use axion::config::Config;

    let receiver = UdpSocket::bind("127.0.0.1:0").expect("bind receiver");
    receiver
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let target = receiver.local_addr().unwrap();
    let mut config = Config::default();
    config.capture.interface = "lo".to_string();
    config.capture.snaplen = 2048;
    config.capture.batch_size = 8;
    config.capture.promiscuous = false;
    let mut source = match AfPacketSource::open(&config) {
        Ok(source) => source,
        Err(err)
            if matches!(
                err.kind(),
                std::io::ErrorKind::PermissionDenied | std::io::ErrorKind::NotFound
            ) =>
        {
            eprintln!("SKIP: AF_PACKET unavailable: {err}");
            return;
        }
        Err(err) => panic!("AF_PACKET open failed: {err}"),
    };
    let pool = BufferPool::new(32, 2048);
    let sender = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(150));
        let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        sock.send_to(b"axion-live-capture", target).unwrap();
        let mut buf = [0u8; 64];
        let _ = receiver.recv_from(&mut buf);
    });

    let deadline = Instant::now() + Duration::from_secs(4);
    let mut captured = 0usize;
    while Instant::now() < deadline && captured == 0 {
        let frames = source.next_batch(&pool, 8).expect("capture batch");
        captured = frames.map(|f| f.len()).unwrap_or(0);
    }
    sender.join().unwrap();
    assert!(captured > 0, "AF_PACKET captured no loopback frames");
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires CAP_NET_RAW/root and libpcap.so"]
fn libpcap_loopback_captures_udp() {
    use std::net::UdpSocket;
    use std::time::{Duration, Instant};

    use axion::capture::libpcap::LibpcapSource;
    use axion::capture::{BufferPool, FrameSource};
    use axion::config::Config;

    let receiver = UdpSocket::bind("127.0.0.1:0").expect("bind receiver");
    receiver
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let target = receiver.local_addr().unwrap();
    let mut config = Config::default();
    config.capture.interface = "lo".to_string();
    config.capture.snaplen = 2048;
    config.capture.promiscuous = false;
    let mut source = match LibpcapSource::open(&config) {
        Ok(source) => source,
        Err(err)
            if matches!(
                err.kind(),
                std::io::ErrorKind::PermissionDenied | std::io::ErrorKind::NotFound
            ) =>
        {
            eprintln!("SKIP: libpcap unavailable: {err}");
            return;
        }
        Err(err) => panic!("libpcap open failed: {err}"),
    };
    let pool = BufferPool::new(32, 2048);
    let sender = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(150));
        let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        sock.send_to(b"axion-libpcap-capture", target).unwrap();
        let mut buf = [0u8; 64];
        let _ = receiver.recv_from(&mut buf);
    });
    let deadline = Instant::now() + Duration::from_secs(4);
    let mut captured = 0usize;
    while Instant::now() < deadline && captured == 0 {
        captured = source
            .next_batch(&pool, 8)
            .expect("libpcap batch")
            .map(|f| f.len())
            .unwrap_or(0);
    }
    sender.join().unwrap();
    assert!(captured > 0, "libpcap captured no loopback frames");
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires CAP_NET_ADMIN/root and nfnetlink_queue"]
fn nfqueue_bind_unbind_roundtrip() {
    use axion::firewall::nfqueue::NfQueue;

    match NfQueue::open(65_000, 64, 65_535, true) {
        Ok(mut queue) => {
            assert!(queue.fail_open());
            queue.unbind();
            eprintln!("NFQUEUE bind/unbind succeeded");
        }
        Err(err)
            if matches!(
                err.kind(),
                std::io::ErrorKind::PermissionDenied
                    | std::io::ErrorKind::NotFound
                    | std::io::ErrorKind::Unsupported
            ) || matches!(
                err.raw_os_error(),
                Some(libc::ENOENT)
                    | Some(libc::ENOPROTOOPT)
                    | Some(libc::EOPNOTSUPP)
                    | Some(libc::ENODEV)
            ) =>
        {
            eprintln!("SKIP: NFQUEUE unavailable: {err}");
        }
        Err(err) => panic!("NFQUEUE bind failed: {err}"),
    }
}
