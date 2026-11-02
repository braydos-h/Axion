use axion::{
    ai::ClefClient,
    api, capture,
    config::{Cli, Command},
    detection::{self, Classification},
    flow::{Flow, FlowTable},
    packet::{Packet, Protocol},
    state::{AppState, FlowView, Status},
};
use clap::Parser;
use std::{
    collections::HashSet,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc,
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::sync::mpsc;
use tracing::{error, info, warn};

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(u128::from(u64::MAX)) as u64
}
fn enabled() -> bool {
    std::env::var("AXION_AI_ENABLED")
        .map(|v| v.eq_ignore_ascii_case("true") || v == "1")
        .unwrap_or(true)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "axion=info".into()),
        )
        .init();
    let cli = Cli::parse();
    if matches!(cli.command, Command::Interfaces) {
        for name in capture::interfaces().map_err(anyhow::Error::msg)? {
            println!("{name}");
        }
        return Ok(());
    }
    anyhow::ensure!(
        cli.max_flows > 0 && cli.max_flows <= 1_000_000,
        "--max-flows must be between 1 and 1000000"
    );
    anyhow::ensure!(
        cli.flow_timeout_seconds > 0,
        "--flow-timeout-seconds must be positive"
    );
    let (mode, interface) = match &cli.command {
        Command::Capture { interface } => {
            anyhow::ensure!(
                capture::interfaces()
                    .map_err(anyhow::Error::msg)?
                    .contains(interface),
                "Interface '{interface}' not found; run 'axion interfaces'"
            );
            ("live", interface.clone())
        }
        Command::Replay { file } => ("replay", file.display().to_string()),
        Command::Demo => ("demo — simulated traffic", "simulated".to_string()),
        Command::Interfaces => unreachable!(),
    };
    let ai_client = match ClefClient::from_env() {
        Ok(client) => client,
        Err(e) => {
            warn!("Cloud AI configuration: {e}");
            None
        }
    };
    let ai_enabled = enabled() && !matches!(cli.command, Command::Demo);
    let mut state = AppState::new(Status {
        capture_running: true,
        ai_status: if !ai_enabled { "disabled" } else { "offline" }.into(),
        ai_enabled,
        interface,
        mode: mode.into(),
        last_error: None,
    });
    let mut allowed_hosts = vec![cli.web_host.to_ascii_lowercase()];
    if cli.web_host == "127.0.0.1" || cli.web_host == "localhost" || cli.web_host == "::1" {
        allowed_hosts.extend(["localhost".into(), "127.0.0.1".into(), "::1".into()]);
    }
    state.allowed_hosts = Arc::new(allowed_hosts);
    if ai_client.is_none() && ai_enabled {
        warn!("Cloud AI unavailable: configure Cloudflare account and token");
    }
    let (packet_tx, packet_rx) = mpsc::channel(4096);
    let (ai_tx, ai_rx) = mpsc::channel(128);
    let shutdown = state.shutdown.clone();
    let raw_packets = Arc::new(AtomicU64::new(0));
    let raw_bytes = Arc::new(AtomicU64::new(0));
    let dropped = Arc::new(AtomicU64::new(0));
    tokio::spawn(analysis_worker(state.clone(), ai_client, ai_rx));
    tokio::spawn(flow_worker(
        state.clone(),
        packet_rx,
        ai_tx,
        (dropped.clone(), raw_packets.clone(), raw_bytes.clone()),
        cli.max_flows,
        cli.flow_timeout_seconds.saturating_mul(1000),
        mode == "live",
    ));
    let source_state = state.clone();
    let source_shutdown = shutdown.clone();
    let source_dropped = dropped.clone();
    let source_packets = raw_packets.clone();
    let source_bytes = raw_bytes.clone();
    let source_command = cli.command;
    tokio::spawn(async move {
        let result = match source_command {
            Command::Capture { interface } => {
                tokio::task::spawn_blocking(move || {
                    capture::live(
                        &interface,
                        packet_tx,
                        source_shutdown,
                        source_dropped,
                        source_packets,
                        source_bytes,
                    )
                })
                .await
            }
            Command::Replay { file } => {
                tokio::task::spawn_blocking(move || {
                    capture::replay(
                        &file.to_string_lossy(),
                        packet_tx,
                        source_shutdown,
                        source_dropped,
                        source_packets,
                        source_bytes,
                    )
                })
                .await
            }
            Command::Demo => {
                demo(packet_tx, source_shutdown, source_packets, source_bytes).await;
                Ok(Ok(()))
            }
            Command::Interfaces => unreachable!(),
        };
        let failure = match result {
            Ok(Ok(())) => {
                info!("Capture source stopped");
                None
            }
            Ok(Err(e)) => {
                error!("{e}");
                Some(e)
            }
            Err(e) => {
                let message = format!("Capture task failed: {e}");
                error!("{message}");
                Some(message)
            }
        };
        let mut inner = source_state.inner.write().await;
        inner.status.capture_running = false;
        inner.status.last_error = failure;
        let status = inner.status.clone();
        drop(inner);
        source_state.emit("status", &status);
    });
    let listener = tokio::net::TcpListener::bind((cli.web_host.as_str(), cli.web_port)).await?;
    info!(
        "Dashboard listening on http://{}:{} ({mode})",
        cli.web_host, cli.web_port
    );
    let stop = shutdown.clone();
    axum::serve(listener, api::router(state))
        .with_graceful_shutdown(async move {
            if let Err(error) = tokio::signal::ctrl_c().await {
                error!("Cannot listen for Ctrl+C: {error}");
            }
            stop.store(true, Ordering::Relaxed);
        })
        .await?;
    Ok(())
}

async fn flow_worker(
    state: AppState,
    mut packets: mpsc::Receiver<Packet>,
    ai_tx: mpsc::Sender<Flow>,
    counters: (Arc<AtomicU64>, Arc<AtomicU64>, Arc<AtomicU64>),
    max_flows: usize,
    timeout_ms: u64,
    live: bool,
) {
    let (dropped, raw_packets, raw_bytes) = counters;
    let mut table = FlowTable::new(max_flows, timeout_ms);
    let mut changed = HashSet::new();
    let mut interval = tokio::time::interval(Duration::from_secs(1));
    let mut last_packets = 0;
    let mut last_expire = 0;
    let mut source_closed = false;
    loop {
        tokio::select! {
            packet = packets.recv(), if !source_closed => match packet {
                Some(packet) => {
                    let timestamp = packet.timestamp_ms;
                    if !live && timestamp.saturating_sub(last_expire) >= 1000 { table.expire(timestamp); last_expire = timestamp; }
                    let flow = table.ingest(packet);
                    let mut inner = state.inner.write().await;
                    let previous = inner.flows.remove(&flow.id);
                    let mut local = detection::classify(&flow);
                    let (ai, mut ai_status, last_analysis_ms) = match previous {
                        Some(old) => { local.ai_requested = old.local.ai_requested; (old.ai, old.ai_status, old.last_analysis_ms) },
                        None => (None, "not requested".to_string(), None),
                    };
                    if inner.status.ai_enabled && inner.status.mode != "demo — simulated traffic" && !local.ai_requested && local.classification == Classification::SuspiciousEncryptedTunnel {
                        match ai_tx.try_send(flow.clone()) {
                            Ok(()) => { local.ai_requested = true; ai_status = "queued".into(); },
                            Err(_) => { inner.stats.dropped_analysis_events += 1; },
                        }
                    }
                    changed.insert(flow.id);
                    inner.flows.insert(flow.id, FlowView { flow, local, ai, ai_status, last_analysis_ms });
                    // Bound retained views even during high churn between cleanup ticks.
                    if inner.flows.len() > max_flows {
                        if let Some(id) = inner.flows.iter().min_by_key(|(_, v)| v.flow.last_seen_ms).map(|(id, _)| *id) { inner.flows.remove(&id); changed.remove(&id); }
                    }
                }
                None => { source_closed = true; }
            },
            _ = interval.tick() => {
                if live { table.expire(now_ms()); }
                let active: HashSet<_> = table.snapshots().into_iter().map(|flow| flow.id).collect();
                let mut inner = state.inner.write().await;
                inner.flows.retain(|id, _| active.contains(id));
                inner.stats.packets_captured = raw_packets.load(Ordering::Relaxed);
                inner.stats.total_bytes = raw_bytes.load(Ordering::Relaxed);
                inner.stats.active_flows = table.len();
                inner.stats.dropped_capture_events = dropped.load(Ordering::Relaxed);
                inner.stats.packets_per_second = inner.stats.packets_captured.saturating_sub(last_packets);
                last_packets = inner.stats.packets_captured;
                inner.stats.suspicious_flows = inner.flows.values().filter(|v| v.local.classification == Classification::SuspiciousEncryptedTunnel).count();
                let stats = inner.stats.clone();
                let updates: Vec<_> = changed.drain().filter_map(|id| inner.flows.get(&id).cloned()).collect();
                drop(inner);
                state.emit("stats", &stats);
                for view in updates { state.emit("flow", &view); }
            }
        }
    }
}

async fn analysis_worker(
    state: AppState,
    client: Option<ClefClient>,
    mut rx: mpsc::Receiver<Flow>,
) {
    while let Some(flow) = rx.recv().await {
        let enabled = state.inner.read().await.status.ai_enabled;
        let result = if enabled {
            match &client {
                Some(client) => {
                    let request = client.classify(&flow);
                    tokio::pin!(request);
                    loop {
                        tokio::select! {
                            result = &mut request => break result,
                            _ = tokio::time::sleep(Duration::from_millis(250)) => {
                                if !state.inner.read().await.status.ai_enabled || state.shutdown.load(Ordering::Relaxed) {
                                    break Err("Cloud AI disabled".into());
                                }
                            }
                        }
                    }
                }
                None => Err("Cloud AI credentials are unavailable".into()),
            }
        } else {
            Err("Cloud AI disabled".into())
        };
        let mut inner = state.inner.write().await;
        let current_enabled = inner.status.ai_enabled;
        let success = result.is_ok();
        if success {
            inner.stats.ai_classified_flows += 1;
        }
        inner.status.ai_status = if !current_enabled {
            "disabled"
        } else if success {
            "online"
        } else {
            "offline"
        }
        .into();
        let view = if let Some(view) = inner.flows.get_mut(&flow.id) {
            match result {
                Ok(answer) => {
                    view.ai = Some(answer);
                    view.ai_status = "complete".into();
                    view.last_analysis_ms = Some(now_ms());
                }
                Err(e) => {
                    warn!("Cloud AI analysis: {e}");
                    view.ai_status = if current_enabled { "error" } else { "disabled" }.into();
                }
            }
            Some(view.clone())
        } else {
            None
        };
        let status = inner.status.clone();
        drop(inner);
        if let Some(view) = view {
            state.emit("flow", &view);
        }
        state.emit("status", &status);
    }
}

async fn demo(
    tx: mpsc::Sender<Packet>,
    shutdown: Arc<AtomicBool>,
    raw_packets: Arc<AtomicU64>,
    raw_bytes: Arc<AtomicU64>,
) {
    let endpoints = [
        ("192.0.2.10:52100", "198.51.100.4:443"),
        ("192.0.2.10:52101", "203.0.113.8:53"),
    ];
    let mut tick = tokio::time::interval(Duration::from_millis(300));
    let mut n = 0_u64;
    while !shutdown.load(Ordering::Relaxed) {
        tick.tick().await;
        let index = n as usize % endpoints.len();
        let (src, dst) = endpoints[index];
        let reverse = n % 4 >= 2;
        let packet = Packet {
            timestamp_ms: now_ms(),
            src: if reverse { dst } else { src }.parse().unwrap(),
            dst: if reverse { src } else { dst }.parse().unwrap(),
            protocol: if index == 0 {
                Protocol::Tcp
            } else {
                Protocol::Udp
            },
            wire_len: 80 + (n % 12) as u32 * 90,
            tcp_seq: if index == 0 { Some(n as u32) } else { None },
            tcp_flags: 0,
            payload: Vec::new(),
        };
        raw_packets.fetch_add(1, Ordering::Relaxed);
        raw_bytes.fetch_add(u64::from(packet.wire_len), Ordering::Relaxed);
        if tx.send(packet).await.is_err() {
            break;
        }
        n += 1;
    }
}
