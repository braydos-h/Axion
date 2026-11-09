use std::collections::BTreeSet;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use clap::{ArgAction, Parser, Subcommand};
use serde::Serialize;
use serde_json::Value;
use tracing_subscriber::EnvFilter;

use axion::api;
use axion::capture::CapturePipeline;
use axion::config::{Config, Mode, EXAMPLE_CONFIG};
use axion::engine::Engine;
use axion::firewall::{self, nfqueue::NfQueue};
use axion::packet::PcapReader;
use axion::rules::{RuleStore, Rules};
use axion::telemetry::Telemetry;

#[derive(Parser)]
#[command(
    name = "axion",
    version,
    about = "Axion: Rust-native deep packet inspection and network enforcement",
    long_about = "Axion classifies network traffic from observable packet metadata, detects proxy/obfuscation heuristics, evaluates policy rules and can enforce decisions through Linux NFQUEUE. Passive capture is monitoring only."
)]
struct Cli {
    /// Configuration file (defaults: $AXION_CONFIG, ./axion.toml, /etc/axion/axion.toml)
    #[arg(long, global = true, env = "AXION_CONFIG", value_name = "FILE")]
    config: Option<PathBuf>,

    /// Increase log verbosity (-v for debug, -vv for trace)
    #[arg(short, long, global = true, action = ArgAction::Count)]
    verbose: u8,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Start capture, the inspection pipeline and the management API
    Start(StartArgs),
    /// Query a running Axion management API
    Status(StatusArgs),
    /// Manage or validate policy rules
    Rules {
        #[command(subcommand)]
        command: RulesCommand,
    },
    /// Analyze a pcap/pcapng file offline
    Inspect(InspectArgs),
    /// Print or check configuration
    Config {
        #[command(subcommand)]
        command: ConfigCommand,
    },
}

#[derive(clap::Args)]
struct StartArgs {
    /// Capture interface (overrides config)
    #[arg(short, long)]
    interface: Option<String>,
    /// monitor or enforce
    #[arg(long)]
    mode: Option<String>,
    /// Evaluate policy but accept every packet
    #[arg(long)]
    dry_run: bool,
    /// Use NFQUEUE inline mode even in monitor mode (enables runtime switching)
    #[arg(long)]
    inline: bool,
    /// Disable the management API
    #[arg(long)]
    no_api: bool,
}

#[derive(clap::Args)]
struct StatusArgs {
    /// Management API address (defaults to api.bind)
    #[arg(long)]
    api: Option<SocketAddr>,
    /// Management bearer token
    #[arg(long)]
    token: Option<String>,
    /// Print raw JSON
    #[arg(long)]
    json: bool,
}

#[derive(Subcommand)]
enum RulesCommand {
    /// List active rules through the management API
    List {
        #[arg(long)]
        api: Option<SocketAddr>,
        #[arg(long)]
        token: Option<String>,
        #[arg(long)]
        json: bool,
    },
    /// Hot-reload rules from the configured file
    Reload {
        #[arg(long)]
        api: Option<SocketAddr>,
        #[arg(long)]
        token: Option<String>,
    },
    /// Validate the configuration and compile all rules without a running daemon
    Validate,
}

#[derive(clap::Args)]
struct InspectArgs {
    /// pcap or pcapng file to analyze
    #[arg(long, value_name = "FILE")]
    pcap: PathBuf,
    /// Print a JSON report
    #[arg(long)]
    json: bool,
    /// Number of flows/events to print
    #[arg(long, default_value_t = 20)]
    limit: usize,
}

#[derive(Subcommand)]
enum ConfigCommand {
    /// Print the documented example configuration
    Example,
    /// Validate a configuration file
    Check,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let path = config_path(cli.config.as_deref());

    match cli.command {
        Command::Start(args) => {
            let config = load_config(&path)?;
            init_logging(&config.general.log_level, cli.verbose);
            if !path.exists() {
                tracing::warn!(
                    path = %path.display(),
                    "configuration file not found; using built-in defaults"
                );
            }
            run_start(args, config, path).await
        }
        Command::Status(args) => {
            init_logging("warn", cli.verbose);
            run_status(args, &path)
        }
        Command::Rules { command } => {
            init_logging("warn", cli.verbose);
            run_rules(command, &path)
        }
        Command::Inspect(args) => {
            let config = load_config(&path)?;
            init_logging("warn", cli.verbose);
            run_inspect(args, config, path)
        }
        Command::Config { command } => {
            init_logging("warn", cli.verbose);
            match command {
                ConfigCommand::Example => {
                    print!("{EXAMPLE_CONFIG}");
                    Ok(())
                }
                ConfigCommand::Check => {
                    let config = load_config(&path)?;
                    Rules::from_config(&config)?;
                    println!(
                        "configuration valid: {} rules, {} flows max, mode {}",
                        config.rules.len(),
                        config.general.max_flows,
                        config.general.mode
                    );
                    Ok(())
                }
            }
        }
    }
}

fn config_path(explicit: Option<&Path>) -> PathBuf {
    if let Some(path) = explicit {
        return path.to_path_buf();
    }
    if let Ok(path) = std::env::var("AXION_CONFIG") {
        if !path.is_empty() {
            return PathBuf::from(path);
        }
    }
    let cwd = PathBuf::from("axion.toml");
    if cwd.exists() {
        return cwd;
    }
    let etc = PathBuf::from(axion::config::DEFAULT_CONFIG_PATH);
    if etc.exists() {
        return etc;
    }
    cwd
}

fn load_config(path: &Path) -> Result<Config> {
    Config::load_optional(path).with_context(|| format!("load configuration {}", path.display()))
}

fn init_logging(level: &str, verbose: u8) {
    let default = if verbose >= 2 {
        "trace"
    } else if verbose == 1 {
        "debug"
    } else {
        level
    };
    let filter = EnvFilter::try_from_default_env()
        .or_else(|_| EnvFilter::try_new(default))
        .unwrap_or_else(|_| EnvFilter::new("info"));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .try_init();
}

async fn run_start(args: StartArgs, mut config: Config, path: PathBuf) -> Result<()> {
    let interface_override = args.interface.clone();
    if let Some(interface) = args.interface {
        config.capture.interface = interface;
    }
    if let Some(mode) = args.mode {
        config.general.mode = match mode.as_str() {
            "monitor" => Mode::Monitor,
            "enforce" => Mode::Enforce,
            other => bail!("unknown mode {other:?}; expected monitor or enforce"),
        };
    }
    if args.dry_run {
        config.general.dry_run = true;
    }
    if args.no_api {
        config.api.enabled = false;
    }
    let inline = args.inline || config.general.mode == Mode::Enforce;
    if inline && config.capture.pcap_file.is_some() {
        bail!("inline NFQUEUE mode cannot replay a pcap file; use `axion inspect`");
    }
    config.validate()?;

    let queue = if inline {
        let q = NfQueue::open(
            config.firewall.queue_num,
            config.firewall.queue_max_len,
            65_535,
            config.firewall.fail_open,
        )
        .with_context(|| {
            format!(
                "could not bind NFQUEUE {} (need CAP_NET_ADMIN/root and nfnetlink_queue). \
                 Install a queue rule, for example: nft add rule inet filter forward tcp dport 443 queue num {}",
                config.firewall.queue_num, config.firewall.queue_num
            )
        })?;
        tracing::info!(
            queue = config.firewall.queue_num,
            fail_open = config.firewall.fail_open,
            "NFQUEUE inline backend ready"
        );
        Some(q)
    } else {
        None
    };
    let can_enforce = queue.is_some();
    if config.general.mode == Mode::Enforce && !can_enforce {
        bail!("enforce mode requires the NFQUEUE inline backend");
    }
    if let Some(interface) = interface_override.as_deref() {
        if inline {
            tracing::warn!(
                interface,
                "interface is ignored in inline NFQUEUE mode; queue rules define the traffic path"
            );
        }
    }

    let config = Arc::new(config);
    let telemetry = Arc::new(Telemetry::new(
        config.telemetry.history_seconds,
        config.telemetry.sample_interval_ms,
        config.general.event_capacity,
    ));
    let rules = RuleStore::new(path.clone(), &config)?;
    let engine = Engine::new(
        Arc::clone(&config),
        rules,
        Arc::clone(&telemetry),
        can_enforce,
        if can_enforce { "nfqueue" } else { "none" },
    )?;

    let shutdown = Arc::new(AtomicBool::new(false));
    let mut enforcement = if let Some(queue) = queue {
        let queue_num = queue.queue_num();
        let handle = firewall::spawn(
            Arc::clone(&engine),
            queue,
            Arc::clone(&shutdown),
            config.firewall.batch_size,
        )?;
        engine.set_backend("nfqueue");
        engine.set_capture_info(format!("nfqueue:queue{queue_num}"), 1);
        Some(handle)
    } else {
        None
    };

    let mut pipeline = if enforcement.is_none()
        && !(config.capture.backend == axion::config::CaptureBackend::None
            && config.capture.pcap_file.is_none())
    {
        let p = CapturePipeline::start(Arc::clone(&engine), &config)
            .with_context(|| "start packet capture (CAP_NET_RAW/root may be required)")?;
        engine.set_capture_info(p.source_name().to_string(), p.worker_count());
        engine.set_backend(backend_from_source(p.source_name()));
        Some(p)
    } else {
        if enforcement.is_none() {
            engine.set_capture_info("none", 0);
            engine.set_backend("none");
        }
        None
    };

    let (api_shutdown, api_rx) = tokio::sync::oneshot::channel();
    let api_handle = if config.api.enabled {
        Some(
            api::serve(Arc::clone(&engine), &config.api, api_rx)
                .await
                .with_context(|| format!("start management API on {}", config.api.bind))?,
        )
    } else {
        drop(api_rx);
        None
    };
    if config.api.enabled && config.api.token.is_none() {
        tracing::warn!(
            bind = %config.api.bind,
            "management API has no token; rely on loopback binding or configure api.token"
        );
    }

    tracing::info!(
        version = env!("CARGO_PKG_VERSION"),
        mode = %engine.mode(),
        can_enforce = engine.can_enforce(),
        backend = %engine.backend(),
        capture = %engine.capture_source(),
        workers = engine.capture_workers(),
        config = %path.display(),
        "Axion started"
    );
    if !engine.can_enforce() {
        tracing::info!("passive monitoring only: Axion will never block packets in this mode");
    }

    let rules_for_hup = Arc::clone(engine.rules());
    let hup = tokio::spawn(async move {
        #[cfg(unix)]
        {
            use tokio::signal::unix::{signal, SignalKind};
            let mut sig = match signal(SignalKind::hangup()) {
                Ok(sig) => sig,
                Err(err) => {
                    tracing::warn!(error = %err, "cannot register SIGHUP handler");
                    return;
                }
            };
            loop {
                if sig.recv().await.is_none() {
                    break;
                }
                let store = Arc::clone(&rules_for_hup);
                match tokio::task::spawn_blocking(move || store.reload()).await {
                    Ok(Ok(count)) => tracing::info!(rules = count, "SIGHUP: rules reloaded"),
                    Ok(Err(err)) => {
                        tracing::error!(error = %format!("{err:#}"), "SIGHUP: rule reload failed; keeping previous policy")
                    }
                    Err(err) => tracing::error!(error = %err, "SIGHUP: reload task failed"),
                }
            }
        }
    });

    #[cfg(unix)]
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let ctrl_c = tokio::signal::ctrl_c();
    tokio::pin!(ctrl_c);
    let mut maintenance = tokio::time::interval(Duration::from_millis(
        config.telemetry.sample_interval_ms.max(100),
    ));
    maintenance.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            _ = &mut ctrl_c => {
                tracing::info!("shutdown signal received");
                break;
            }
            _ = term.recv() => {
                tracing::info!("SIGTERM received");
                break;
            }
            _ = maintenance.tick() => {
                engine.maintenance();
                if pipeline.as_ref().is_some_and(|p| p.finished()) {
                    tracing::info!("capture source finished; shutting down");
                    break;
                }
                if enforcement.as_ref().is_some_and(|e| !e.is_running()) {
                    tracing::error!(
                        "NFQUEUE enforcement loop stopped unexpectedly; shutting down for supervisor/kernel fail policy"
                    );
                    break;
                }
            }
        }
    }

    // Stop accepting management requests first, then inline verdicts, then
    // capture. The order keeps the dashboard responsive during a short drain.
    if let Some(handle) = api_handle {
        let _ = api_shutdown.send(());
        if tokio::time::timeout(Duration::from_secs(3), handle.wait())
            .await
            .is_err()
        {
            tracing::warn!("management API did not drain within 3s");
        }
    } else {
        let _ = api_shutdown.send(());
    }
    shutdown.store(true, Ordering::Relaxed);
    if let Some(enforcement) = enforcement.take() {
        enforcement.stop();
    }
    if let Some(mut pipeline) = pipeline.take() {
        pipeline.shutdown();
    }
    hup.abort();
    engine.maintenance();
    tracing::info!("Axion stopped");
    Ok(())
}

fn backend_from_source(source: &str) -> &'static str {
    if source.starts_with("af_packet") {
        "af_packet"
    } else if source.starts_with("libpcap") {
        "libpcap"
    } else if source.starts_with("pcap:") {
        "pcap-replay"
    } else {
        "unknown"
    }
}

fn run_status(args: StatusArgs, path: &Path) -> Result<()> {
    let config = load_config(path)?;
    let addr = api_addr(&config, args.api);
    let token = args.token.or_else(|| config.api.token.clone());
    let (status, body) = http_call(addr, "GET", "/api/status", token.as_deref(), None)?;
    if status != 200 {
        bail!(
            "Axion API returned HTTP {status}: {}",
            api_error_message(&body)
        );
    }
    if args.json {
        println!("{}", pretty_json(&body)?);
        return Ok(());
    }
    let value: Value = serde_json::from_str(&body).context("parse status JSON")?;
    println!(
        "Axion {}  mode={}  backend={}  enforcement={}",
        value["version"].as_str().unwrap_or("?"),
        value["mode"].as_str().unwrap_or("?"),
        value["backend"].as_str().unwrap_or("?"),
        if value["enforcement_active"].as_bool().unwrap_or(false) {
            "ACTIVE"
        } else {
            "off"
        }
    );
    println!(
        "  capture={}  workers={}  active_flows={}  rules={}",
        value["capture_source"].as_str().unwrap_or("?"),
        value["capture_workers"].as_u64().unwrap_or(0),
        value["active_flows"].as_u64().unwrap_or(0),
        value["rules"]["compiled"].as_u64().unwrap_or(0)
    );
    let m = &value["metrics"];
    println!(
        "  uptime={}s packets={} bytes={} pps={:.0} bps={:.0}",
        m["uptime_seconds"].as_u64().unwrap_or(0),
        m["packets_total"].as_u64().unwrap_or(0),
        m["bytes_total"].as_u64().unwrap_or(0),
        m["pps"].as_f64().unwrap_or(0.0),
        m["bps"].as_f64().unwrap_or(0.0)
    );
    println!(
        "  blocked_flows={} dropped_packets={} detections={} parse_errors={} capture_drops={}",
        m["blocked_flows"].as_u64().unwrap_or(0),
        m["dropped_packets"].as_u64().unwrap_or(0),
        m["detections_total"].as_u64().unwrap_or(0),
        m["parse_errors"].as_u64().unwrap_or(0),
        m["capture_drops"].as_u64().unwrap_or(0)
    );
    println!(
        "  cpu={:.1}% rss={} KiB",
        m["cpu_percent"].as_f64().unwrap_or(0.0),
        m["memory_bytes"].as_u64().unwrap_or(0) / 1024
    );
    if let Some(protocols) = m["protocols"].as_object() {
        let mut entries: Vec<_> = protocols.iter().collect();
        entries.sort_by_key(|(_, count)| std::cmp::Reverse(count.as_u64().unwrap_or(0)));
        let summary = entries
            .iter()
            .take(10)
            .map(|(name, count)| format!("{name}={}", count.as_u64().unwrap_or(0)))
            .collect::<Vec<_>>()
            .join(" ");
        println!("  protocols: {summary}");
    }
    Ok(())
}

fn run_rules(command: RulesCommand, path: &Path) -> Result<()> {
    let config = load_config(path)?;
    match command {
        RulesCommand::List { api, token, json } => {
            let addr = api_addr(&config, api);
            let token = token.or_else(|| config.api.token.clone());
            let (status, body) = http_call(addr, "GET", "/api/rules", token.as_deref(), None)?;
            if status != 200 {
                bail!(
                    "Axion API returned HTTP {status}: {}",
                    api_error_message(&body)
                );
            }
            if json {
                println!("{}", pretty_json(&body)?);
                return Ok(());
            }
            let value: Value = serde_json::from_str(&body)?;
            let rules = value["rules"].as_array().cloned().unwrap_or_default();
            println!(
                "{} rules compiled (allowlist {}, blocklist {}), default={}",
                value["compiled_count"].as_u64().unwrap_or(0),
                value["allowlist_cidrs"]
                    .as_array()
                    .map(|v| v.len())
                    .unwrap_or(0),
                value["blocklist_cidrs"]
                    .as_array()
                    .map(|v| v.len())
                    .unwrap_or(0),
                value["default_action"].as_str().unwrap_or("?")
            );
            for rule in rules {
                let matcher = rule.get("match").cloned().unwrap_or(Value::Null);
                let summary = matcher_summary(&matcher);
                println!(
                    "  [{}] {} action={} enabled={} {}",
                    rule["priority"].as_i64().unwrap_or(0),
                    rule["name"].as_str().unwrap_or("?"),
                    rule["action"].as_str().unwrap_or("?"),
                    rule["enabled"].as_bool().unwrap_or(false),
                    summary
                );
            }
            Ok(())
        }
        RulesCommand::Reload { api, token } => {
            let addr = api_addr(&config, api);
            let token = token.or_else(|| config.api.token.clone());
            let (status, body) = http_call(
                addr,
                "POST",
                "/api/rules/reload",
                token.as_deref(),
                Some("{}"),
            )?;
            if status != 200 {
                bail!(
                    "rule reload failed (HTTP {status}): {}",
                    api_error_message(&body)
                );
            }
            println!("{}", pretty_json(&body)?);
            Ok(())
        }
        RulesCommand::Validate => {
            let rules = Rules::from_config(&config)?;
            println!(
                "configuration valid: {} compiled rules, {} allowlist CIDRs, {} blocklist CIDRs",
                rules.rule_count(),
                rules.allowlist_len(),
                rules.blocklist_len()
            );
            Ok(())
        }
    }
}

fn matcher_summary(matcher: &Value) -> String {
    let Some(object) = matcher.as_object() else {
        return String::new();
    };
    let mut parts = Vec::new();
    for (key, value) in object {
        let rendered = match value {
            Value::Array(items) if !items.is_empty() => items
                .iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect::<Vec<_>>()
                .join(","),
            Value::String(text) if !text.is_empty() => text.clone(),
            Value::Number(number) if number.as_f64().unwrap_or(0.0) != 0.0 => number.to_string(),
            _ => continue,
        };
        if !rendered.is_empty() {
            parts.push(format!("{key}={rendered}"));
        }
    }
    if parts.is_empty() {
        String::new()
    } else {
        format!("({})", parts.join(" "))
    }
}

#[derive(Serialize)]
struct InspectReport {
    pcap: String,
    records: u64,
    link_types: Vec<String>,
    metrics: axion::telemetry::MetricsSnapshot,
    flows: Vec<axion::flow::FlowSnapshot>,
    events: Vec<axion::telemetry::DetectionEvent>,
}

fn run_inspect(args: InspectArgs, mut config: Config, path: PathBuf) -> Result<()> {
    if !args.pcap.exists() {
        bail!("pcap file {} does not exist", args.pcap.display());
    }
    // Offline analysis is always monitor-only.
    config.general.mode = Mode::Monitor;
    config.general.dry_run = true;
    config.api.enabled = false;
    let config = Arc::new(config);
    let telemetry = Arc::new(Telemetry::new(
        config.telemetry.history_seconds,
        config.telemetry.sample_interval_ms,
        config.general.event_capacity,
    ));
    let rules = RuleStore::new(path.clone(), &config)?;
    let engine = Engine::new(
        Arc::clone(&config),
        rules,
        Arc::clone(&telemetry),
        false,
        "pcap-file",
    )?;
    let mut reader = PcapReader::open(&args.pcap)
        .with_context(|| format!("open pcap {}", args.pcap.display()))?;
    let mut records = 0u64;
    let mut link_types = BTreeSet::new();
    while let Some(record) = reader.next_record()? {
        records += 1;
        link_types.insert(record.link_type.name().to_string());
        engine.process_link_frame(record.link_type, &record.data, record.timestamp);
    }
    engine.maintenance();
    let limit = args.limit.clamp(1, 10_000);
    let flows = engine.snapshot_flows(limit);
    let events = engine.telemetry().events.recent(limit);
    let metrics = engine.telemetry().metrics.snapshot(engine.active_flows());

    if args.json {
        let report = InspectReport {
            pcap: args.pcap.display().to_string(),
            records,
            link_types: link_types.into_iter().collect(),
            metrics,
            flows,
            events,
        };
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }

    println!("Axion offline inspection");
    println!("  capture: {}", args.pcap.display());
    println!(
        "  records: {records}  link types: {}  captured bytes: {}",
        if link_types.is_empty() {
            "?".to_string()
        } else {
            link_types.into_iter().collect::<Vec<_>>().join(",")
        },
        metrics.bytes_total
    );
    println!(
        "  packets: {}  flows: {}  parse errors: {}  fragment drops: {}",
        metrics.packets_total, metrics.active_flows, metrics.parse_errors, metrics.fragment_drops
    );
    println!(
        "  detections: {}  would-block decisions were evaluated but NOT enforced",
        metrics.detections_total
    );
    let protocols = metrics
        .protocols
        .iter()
        .map(|(name, count)| format!("{name}={count}"))
        .collect::<Vec<_>>()
        .join(" ");
    if !protocols.is_empty() {
        println!("  protocols: {protocols}");
    }

    if !events.is_empty() {
        println!("\nDetection events ({} shown):", events.len());
        for event in &events {
            println!(
                "  {}  {}:{} -> {}:{}  {}  conf={:.2}  action={}  rule={}  sni={}",
                format_unix_ms(event.ts_ms),
                event.src,
                event.src_port,
                event.dst,
                event.dst_port,
                event.protocols.join(","),
                event.confidence,
                event.action,
                event.matched_rule.as_deref().unwrap_or("-"),
                event.sni.as_deref().unwrap_or("-")
            );
            for evidence in event.evidence.iter().take(3) {
                println!("      evidence: {evidence}");
            }
        }
    }

    if !flows.is_empty() {
        println!("\nTop flows ({} shown):", flows.len());
        for flow in &flows {
            println!(
                "  {} -> {}  {}  protocols={}  bytes={}  proxy={:.2}  action={}{}",
                flow.client,
                flow.server,
                flow.protocol,
                if flow.detected_protocols.is_empty() {
                    "unknown".to_string()
                } else {
                    flow.detected_protocols.join(",")
                },
                flow.total_bytes,
                flow.proxy_score,
                flow.action,
                flow.sni
                    .as_deref()
                    .map(|sni| format!("  sni={sni}"))
                    .unwrap_or_default()
            );
        }
    }
    Ok(())
}

fn api_addr(config: &Config, explicit: Option<SocketAddr>) -> SocketAddr {
    let addr = explicit.unwrap_or(config.api.bind);
    if addr.ip().is_unspecified() {
        if addr.is_ipv4() {
            SocketAddr::new("127.0.0.1".parse().unwrap(), addr.port())
        } else {
            SocketAddr::new("::1".parse().unwrap(), addr.port())
        }
    } else {
        addr
    }
}

fn http_call(
    addr: SocketAddr,
    method: &str,
    path: &str,
    token: Option<&str>,
    body: Option<&str>,
) -> Result<(u16, String)> {
    if let Some(token) = token {
        if token.contains('\r') || token.contains('\n') {
            bail!("management token contains invalid characters");
        }
    }
    let mut stream = TcpStream::connect_timeout(&addr, Duration::from_secs(3))
        .with_context(|| format!("cannot reach Axion API at {addr}; is axion running?"))?;
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    let host = if addr.is_ipv6() {
        format!("[{}]:{}", addr.ip(), addr.port())
    } else {
        addr.to_string()
    };
    let mut request = format!(
        "{method} {path} HTTP/1.1\r\nHost: {host}\r\nAccept: application/json\r\nConnection: close\r\n"
    );
    if let Some(token) = token {
        request.push_str(&format!("X-Axion-Token: {token}\r\n"));
    }
    if let Some(body) = body {
        request.push_str("Content-Type: application/json\r\n");
        request.push_str(&format!("Content-Length: {}\r\n", body.len()));
    }
    request.push_str("\r\n");
    if let Some(body) = body {
        request.push_str(body);
    }
    stream.write_all(request.as_bytes())?;
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw)?;
    let split = raw
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or_else(|| anyhow::anyhow!("malformed HTTP response from Axion API"))?;
    let headers = String::from_utf8_lossy(&raw[..split]);
    let status = headers
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse::<u16>().ok())
        .ok_or_else(|| anyhow::anyhow!("malformed HTTP status line from Axion API"))?;
    let mut body_bytes = raw[split + 4..].to_vec();
    if headers
        .to_ascii_lowercase()
        .contains("transfer-encoding: chunked")
    {
        body_bytes = decode_chunked(&body_bytes)?;
    }
    Ok((status, String::from_utf8_lossy(&body_bytes).into_owned()))
}

fn api_error_message(body: &str) -> String {
    serde_json::from_str::<Value>(body)
        .ok()
        .and_then(|value| value["error"].as_str().map(|s| s.to_string()))
        .unwrap_or_else(|| body.trim().to_string())
}

fn pretty_json(body: &str) -> Result<String> {
    let value: Value = serde_json::from_str(body)?;
    Ok(serde_json::to_string_pretty(&value)?)
}

fn decode_chunked(mut body: &[u8]) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    while let Some(line_end) = body.windows(2).position(|w| w == b"\r\n") {
        let size_text = String::from_utf8_lossy(&body[..line_end]);
        let size = usize::from_str_radix(size_text.split(';').next().unwrap_or("0").trim(), 16)
            .unwrap_or(0);
        body = &body[line_end + 2..];
        if size == 0 {
            break;
        }
        if body.len() < size + 2 {
            bail!("truncated chunked HTTP response");
        }
        out.extend_from_slice(&body[..size]);
        body = &body[size + 2..];
    }
    Ok(out)
}

fn format_unix_ms(ms: u64) -> String {
    let secs = ms / 1000;
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let (year, month, day) = civil_from_days(days);
    format!(
        "{year:04}-{month:02}-{day:02} {:02}:{:02}:{:02} UTC",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

fn civil_from_days(days_since_epoch: i64) -> (i64, u32, u32) {
    let z = days_since_epoch + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = mp + if mp < 10 { 3 } else { -9 };
    (y + i64::from(m <= 2), m as u32, d as u32)
}
