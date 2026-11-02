use axion::{
    ai::ClefClient,
    api, capture,
    config::{Cli, Command, Settings},
    detection::{self, Classification},
    flow::{Flow, FlowTable},
    packet::{Packet, Protocol},
    server,
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

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();
    let cli = Cli::parse();
    if matches!(cli.command, Some(Command::Interfaces)) {
        for interface in capture::interface_details().map_err(anyhow::Error::msg)? {
            println!("{}", serde_json::to_string(&interface)?);
        }
        return Ok(());
    }
    let settings = cli.resolve(
        Settings::load().map_err(|e| anyhow::anyhow!("Cannot load configuration: {e}"))?,
    )?;
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(&settings.log_filter)),
        )
        .init();
    let explicit_capture = matches!(cli.command, Some(Command::Capture { .. }));
    let command = cli.command.unwrap_or(Command::Capture {
        interface: if settings.auto_interface {
            "auto".into()
        } else {
            settings
                .preferred_interface
                .clone()
                .unwrap_or_else(|| "auto".into())
        },
    });
    let (mode, interface) = match &command {
        Command::Capture { interface } => ("live", interface.clone()),
        Command::Replay { file } => ("replay", file.display().to_string()),
        Command::Demo => ("demo — simulated traffic", "simulated".into()),
        Command::Interfaces => unreachable!(),
    };
    let ai_client = match ClefClient::from_env() {
        Ok(client) => client,
        Err(e) => {
            warn!("Cloud AI configuration: {e}");
            None
        }
    };
    let ai_enabled = settings.ai_enabled && !matches!(command, Command::Demo);
    if ai_client.is_none() && ai_enabled {
        warn!("Cloud AI unavailable: configure Cloudflare account and token");
    }
    let mut state = AppState::new(Status {
        capture_running: false,
        ai_status: if !ai_enabled { "disabled" } else { "offline" }.into(),
        ai_enabled,
        interface: interface.clone(),
        mode: mode.into(),
        last_error: None,
    });
    *state.settings.write().await = settings.clone();
    state.active_settings = Arc::new(settings.clone());
    let mut allowed_hosts = vec![settings
        .web_host
        .trim_matches(['[', ']'])
        .to_ascii_lowercase()];
    if ["127.0.0.1", "localhost", "::1"].contains(&settings.web_host.as_str()) {
        allowed_hosts.extend(["localhost".into(), "127.0.0.1".into(), "::1".into()]);
    }
    state.allowed_hosts = Arc::new(allowed_hosts);
    let (packet_tx, packet_rx) = mpsc::channel(4096);
    let (ai_tx, ai_rx) = mpsc::channel(128);
    let raw_packets = Arc::new(AtomicU64::new(0));
    let raw_bytes = Arc::new(AtomicU64::new(0));
    let dropped = Arc::new(AtomicU64::new(0));
    let manager = Arc::new(capture::Manager::new(
        packet_tx.clone(),
        dropped.clone(),
        raw_packets.clone(),
        raw_bytes.clone(),
    ));
    if mode == "live" {
        state.capture = Some(manager.clone());
    }
    tokio::spawn(analysis_worker(state.clone(), ai_client, ai_rx));
    tokio::spawn(flow_worker(
        state.clone(),
        packet_rx,
        ai_tx,
        (dropped.clone(), raw_packets.clone(), raw_bytes.clone()),
        settings.max_flows,
        settings.flow_timeout_seconds.saturating_mul(1000),
        mode == "live",
    ));

    let listener = server::bind(&settings.web_host, settings.web_port, settings.strict_port)
        .await
        .map_err(|e| {
            anyhow::anyhow!(
                "Cannot bind dashboard to {}:{}: {e}",
                settings.web_host,
                settings.web_port
            )
        })?;
    let address = listener.local_addr()?;
    let url = server::url(address);
    println!("Axion dashboard: {url}");
    info!("Dashboard listening on {url} ({mode})");
    if settings.open_browser {
        if let Err(e) = server::open_browser(&url) {
            warn!("Could not open browser: {e}");
        }
    }

    match command {
        Command::Capture { interface } if settings.start_capture || explicit_capture => {
            let capture_state = state.clone();
            let manager = manager.clone();
            tokio::spawn(async move {
                let _guard = capture_state.capture_control.lock().await;
                let chosen = if interface == "auto" {
                    capture::auto_interface()
                } else {
                    Ok(interface)
                };
                let result = match chosen {
                    Ok(name) => manager.start(capture_state.clone(), name).await,
                    Err(e) => Err(e),
                };
                if let Err(e) = result {
                    warn!("Live capture unavailable: {e}. The dashboard remains available; use demo or replay without capture privileges.");
                    let mut inner = capture_state.inner.write().await;
                    inner.status.last_error = Some(e);
                    let status = inner.status.clone();
                    drop(inner);
                    capture_state.emit("status", &status);
                }
            });
        }
        Command::Replay { file } => {
            let source_state = state.clone();
            let shutdown = state.shutdown.clone();
            tokio::spawn(async move {
                {
                    let mut inner = source_state.inner.write().await;
                    inner.status.capture_running = true;
                    let status = inner.status.clone();
                    drop(inner);
                    source_state.emit("status", &status);
                }
                let result = tokio::task::spawn_blocking(move || {
                    capture::replay(
                        &file.to_string_lossy(),
                        packet_tx,
                        shutdown,
                        dropped,
                        raw_packets,
                        raw_bytes,
                    )
                })
                .await;
                let failure = match result {
                    Ok(Ok(())) => None,
                    Ok(Err(e)) => Some(e),
                    Err(e) => Some(format!("Replay task failed: {e}")),
                };
                let mut inner = source_state.inner.write().await;
                inner.status.capture_running = false;
                inner.status.last_error = failure;
                let status = inner.status.clone();
                drop(inner);
                source_state.emit("status", &status);
            });
        }
        Command::Demo => {
            let source_state = state.clone();
            let shutdown = state.shutdown.clone();
            tokio::spawn(async move {
                {
                    let mut inner = source_state.inner.write().await;
                    inner.status.capture_running = true;
                    let status = inner.status.clone();
                    drop(inner);
                    source_state.emit("status", &status);
                }
                demo(packet_tx, shutdown, raw_packets, raw_bytes).await;
                let mut inner = source_state.inner.write().await;
                inner.status.capture_running = false;
                let status = inner.status.clone();
                drop(inner);
                source_state.emit("status", &status);
            });
        }
        _ => {}
    }
    let shutdown = state.shutdown.clone();
    axum::serve(listener, api::router(state.clone()))
        .with_graceful_shutdown(async move {
            if let Err(e) = tokio::signal::ctrl_c().await {
                error!("Cannot listen for Ctrl+C: {e}");
            }
            shutdown.store(true, Ordering::Relaxed);
        })
        .await?;
    {
        let _guard = state.capture_control.lock().await;
        manager
            .stop(state.clone())
            .await
            .map_err(anyhow::Error::msg)?;
    }
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
                inner.stats.tcp_flows = inner.flows.values().filter(|v| v.flow.protocol == Protocol::Tcp).count();
                inner.stats.udp_flows = inner.flows.values().filter(|v| v.flow.protocol == Protocol::Udp).count();
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
