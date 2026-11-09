//! Real inline-enforcement test. Requires root, nfnetlink_queue and nftables.
//!
//! Run with:
//!   sudo -E cargo test --test enforcement -- --ignored --nocapture
//!
//! The test creates a uniquely named inet table that queues only two loopback
//! ports, verifies an allowed TCP handshake and a dropped SYN, then removes the
//! table even on failure.

#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires root, nftables and nfnetlink_queue"]
fn nfqueue_allows_and_drops_real_tcp() {
    use std::io::Write;
    use std::net::{TcpListener, TcpStream};
    use std::process::{Command, Stdio};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::time::Duration;

    use axion::config::{Action, Config, MatchConfig, Mode, RuleConfig};
    use axion::engine::Engine;
    use axion::firewall::{self, nfqueue::NfQueue};
    use axion::rules::RuleStore;
    use axion::telemetry::Telemetry;

    // SAFETY: geteuid has no preconditions and does not dereference pointers.
    if unsafe { libc::geteuid() } != 0 {
        eprintln!("SKIP: enforcement test requires root");
        return;
    }
    if Command::new("nft").arg("--version").output().is_err() {
        eprintln!("SKIP: nft is not installed");
        return;
    }

    let allowed = TcpListener::bind("127.0.0.1:0").unwrap();
    let allowed_port = allowed.local_addr().unwrap().port();
    let blocked = TcpListener::bind("127.0.0.1:0").unwrap();
    let blocked_port = blocked.local_addr().unwrap().port();
    drop(blocked);
    let queue_num = 65_001u16;
    let table = format!("axion_test_{}", std::process::id());

    let mut config = Config::default();
    config.general.mode = Mode::Enforce;
    config.firewall.bypass_cidrs.clear();
    config.firewall.bypass_tcp_ports.clear();
    config.rules = vec![RuleConfig {
        name: "drop-test-port".into(),
        priority: 100,
        action: Action::Drop,
        enabled: true,
        log: true,
        matcher: MatchConfig {
            ports: vec![blocked_port],
            min_confidence: 0.0,
            ..Default::default()
        },
        ..Default::default()
    }];
    let telemetry = Arc::new(Telemetry::new(10, 500, 64));
    let rules = RuleStore::new("enforcement-test.toml".into(), &config).unwrap();

    let queue = match NfQueue::open(queue_num, 128, 65_535, false) {
        Ok(queue) => queue,
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
            return;
        }
        Err(err) => panic!("NFQUEUE bind failed unexpectedly: {err}"),
    };
    let engine = Engine::new(Arc::new(config), rules, telemetry, true, "nfqueue").expect("engine");
    let shutdown = Arc::new(AtomicBool::new(false));
    let enforcement = firewall::spawn(Arc::clone(&engine), queue, Arc::clone(&shutdown), 16)
        .expect("enforcement thread");

    struct TableGuard {
        name: String,
    }
    impl Drop for TableGuard {
        fn drop(&mut self) {
            let _ = Command::new("nft")
                .args(["delete", "table", "inet", &self.name])
                .output();
        }
    }

    let script = format!(
        "add table inet {table}\n\
         add chain inet {table} output {{ type filter hook output priority 0; policy accept; }}\n\
         add rule inet {table} output tcp dport {{ {allowed_port}, {blocked_port} }} queue num {queue_num}\n"
    );
    let mut child = Command::new("nft")
        .arg("-f")
        .arg("-")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn nft");
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(script.as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
        if stderr.contains("Operation not permitted")
            || stderr.contains("Permission denied")
            || stderr.contains("No such file")
        {
            eprintln!("SKIP: could not install nftables test rules: {stderr}");
            shutdown.store(true, Ordering::Relaxed);
            enforcement.stop();
            return;
        }
        panic!("nftables test rule installation failed: {stderr}");
    }
    let _guard = TableGuard { name: table };

    // Allowed connection must complete through the NFQUEUE ACCEPT verdict.
    let accept_thread = std::thread::spawn(move || {
        let (mut stream, _) = allowed.accept().expect("accept allowed");
        let mut buf = [0u8; 4];
        use std::io::Read;
        let _ = stream.read(&mut buf);
    });
    let allowed_conn = TcpStream::connect_timeout(
        &format!("127.0.0.1:{allowed_port}").parse().unwrap(),
        Duration::from_secs(2),
    );
    assert!(
        allowed_conn.is_ok(),
        "ALLOW verdict failed: {allowed_conn:?}"
    );
    allowed_conn.unwrap().write_all(b"ping").unwrap();
    accept_thread.join().unwrap();

    // Blocked port: SYN is dropped, so a normal closed-port RST must not occur.
    let blocked_conn = TcpStream::connect_timeout(
        &format!("127.0.0.1:{blocked_port}").parse().unwrap(),
        Duration::from_millis(800),
    );
    assert!(
        blocked_conn.is_err(),
        "DROP rule did not stop the TCP handshake"
    );

    let snapshot = engine.telemetry().metrics.snapshot(engine.active_flows());
    eprintln!(
        "enforcement test: packets={} dropped={} blocked_flows={} enforcement_errors={}",
        snapshot.packets_total,
        snapshot.dropped_packets,
        snapshot.blocked_flows,
        snapshot.enforcement_errors
    );
    assert!(snapshot.dropped_packets > 0, "no packets were dropped");
    assert_eq!(snapshot.enforcement_errors, 0);

    drop(_guard);
    shutdown.store(true, Ordering::Relaxed);
    enforcement.stop();
}
