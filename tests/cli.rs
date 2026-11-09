//! End-to-end CLI, dashboard and rule-reload tests. These tests use the built
//! binary and do not require root or external network access.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_axion")
}

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join(name)
}

fn run(args: &[&str]) -> std::process::Output {
    Command::new(bin()).args(args).output().expect("run axion")
}

#[test]
fn inspect_benign_tls_extracts_sni() {
    let path = fixture("benign_tls.pcap");
    let output = run(&["inspect", "--pcap", path.to_str().unwrap(), "--json"]);
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["records"], 1);
    assert_eq!(json["flows"][0]["sni"], "www.example.com");
    assert_eq!(json["flows"][0]["blocked"], false);
}

#[test]
fn inspect_pcapng_works() {
    let path = fixture("benign_tls.pcapng");
    let output = run(&["inspect", "--pcap", path.to_str().unwrap(), "--json"]);
    assert!(output.status.success());
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["flows"][0]["sni"], "www.example.com");
}

#[test]
fn inspect_socks5_reports_detection_without_enforcing() {
    let path = fixture("proxy_socks5.pcap");
    let output = run(&["inspect", "--pcap", path.to_str().unwrap(), "--json"]);
    assert!(output.status.success());
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let event = &json["events"][0];
    assert_eq!(event["protocols"][0], "socks5");
    assert_eq!(event["action"], "drop");
    assert_eq!(
        event["blocked"], false,
        "offline inspection must never enforce"
    );
    assert!(event["confidence"].as_f64().unwrap() > 0.9);
}

#[test]
fn inspect_reassembles_ipv4_fragments() {
    let path = fixture("ipv4_fragmented_dns.pcap");
    let output = run(&["inspect", "--pcap", path.to_str().unwrap(), "--json"]);
    assert!(output.status.success());
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["flows"][0]["primary_protocol"], "dns");
    assert_eq!(json["metrics"]["parse_errors"], 0);
}

#[test]
fn config_example_round_trips() {
    let example = run(&["config", "example"]);
    assert!(example.status.success());
    let dir = std::env::temp_dir().join(format!("axion-config-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    let file = dir.join("axion.toml");
    std::fs::write(&file, &example.stdout).unwrap();
    let check = run(&["--config", file.to_str().unwrap(), "config", "check"]);
    assert!(
        check.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&check.stderr)
    );
    let output = run(&["--config", file.to_str().unwrap(), "rules", "validate"]);
    assert!(output.status.success());
    let _ = std::fs::remove_dir_all(&dir);
}

fn free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap().port()
}

fn http_request(
    port: u16,
    method: &str,
    path: &str,
    token: Option<&str>,
    body: Option<&str>,
) -> (u16, String) {
    try_http_request(port, method, path, token, body).expect("HTTP request")
}

fn try_http_request(
    port: u16,
    method: &str,
    path: &str,
    token: Option<&str>,
    body: Option<&str>,
) -> std::io::Result<(u16, String)> {
    let mut stream = TcpStream::connect(("127.0.0.1", port))?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    let mut request =
        format!("{method} {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n");
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
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "short HTTP"))?;
    let headers = String::from_utf8_lossy(&raw[..split]);
    let status = headers
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse::<u16>().ok())
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "bad status"))?;
    Ok((
        status,
        String::from_utf8_lossy(&raw[split + 4..]).into_owned(),
    ))
}

struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
#[cfg(target_os = "linux")]
fn start_api_dashboard_rules_reload_and_status_cli() {
    let port = free_port();
    let dir = std::env::temp_dir().join(format!("axion-api-{}-{}", std::process::id(), port));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let config_path = dir.join("axion.toml");
    write_api_config(&config_path, port);

    let mut child = ChildGuard(
        Command::new(bin())
            .arg("--config")
            .arg(&config_path)
            .arg("start")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn axion start"),
    );

    let deadline = Instant::now() + Duration::from_secs(30);
    let mut ready = false;
    while Instant::now() < deadline {
        if let Some(status) = child.0.try_wait().unwrap() {
            panic!("axion exited early with {status}");
        }
        if let Ok((status, _)) = try_http_request(port, "GET", "/api/health", None, None) {
            if status == 200 {
                ready = true;
                break;
            }
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    assert!(ready, "API did not become ready");

    let (status, dashboard) = http_request(port, "GET", "/", None, None);
    assert_eq!(status, 200);
    assert!(dashboard.contains("AXION"));
    assert!(dashboard.contains("dashboard.js"));

    let (status, _) = http_request(port, "GET", "/api/status", None, None);
    assert_eq!(status, 401, "token must protect API");
    let (status, body) = http_request(port, "GET", "/api/status", Some("secret"), None);
    assert_eq!(status, 200);
    let json: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(json["mode"], "monitor");
    assert_eq!(json["can_enforce"], false);

    let (status, _) = http_request(
        port,
        "POST",
        "/api/mode",
        Some("secret"),
        Some(r#"{"mode":"enforce"}"#),
    );
    assert_eq!(status, 409, "passive backend must reject enforce mode");

    // CLI status and rules list talk to the live API using the config token.
    let status_output = Command::new(bin())
        .arg("--config")
        .arg(&config_path)
        .arg("status")
        .output()
        .unwrap();
    assert!(
        status_output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&status_output.stderr)
    );
    assert!(String::from_utf8_lossy(&status_output.stdout).contains("mode=monitor"));

    let rules_output = Command::new(bin())
        .arg("--config")
        .arg(&config_path)
        .arg("rules")
        .arg("list")
        .output()
        .unwrap();
    assert!(rules_output.status.success());
    assert!(String::from_utf8_lossy(&rules_output.stdout).contains("0 rules compiled"));

    // Hot reload a new rule from the same file.
    write_api_config_with_rule(&config_path, port);
    let (status, body) = http_request(
        port,
        "POST",
        "/api/rules/reload",
        Some("secret"),
        Some("{}"),
    );
    assert_eq!(status, 200, "reload body: {body}");
    let (status, body) = http_request(port, "GET", "/api/rules", Some("secret"), None);
    assert_eq!(status, 200);
    let json: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(json["compiled_count"], 1);
    assert_eq!(json["rules"][0]["name"], "reloaded");

    let reload_output = Command::new(bin())
        .arg("--config")
        .arg(&config_path)
        .arg("rules")
        .arg("reload")
        .output()
        .unwrap();
    assert!(
        reload_output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&reload_output.stderr)
    );
    assert!(String::from_utf8_lossy(&reload_output.stdout).contains("\"reloaded\": true"));

    // An invalid reload must return 400 and leave the previous policy intact.
    let mut invalid = base_api_config(port);
    invalid.push_str(
        r#"
[[rules]]
name = "invalid"
priority = 1
action = "drop"
[rules.match]
src_cidrs = ["not-a-cidr"]
"#,
    );
    std::fs::write(&config_path, invalid).unwrap();
    let (status, _) = http_request(
        port,
        "POST",
        "/api/rules/reload",
        Some("secret"),
        Some("{}"),
    );
    assert_eq!(status, 400);
    let (status, body) = http_request(port, "GET", "/api/rules", Some("secret"), None);
    assert_eq!(status, 200);
    let json: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(
        json["compiled_count"], 1,
        "failed reload must keep old rules"
    );

    // SIGTERM must stop the daemon.
    // SAFETY: the PID belongs to the child process created above; SIGTERM has
    // no memory-safety preconditions.
    unsafe {
        libc::kill(child.0.id() as i32, libc::SIGTERM);
    }
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if child.0.try_wait().unwrap().is_some() {
            break;
        }
        if Instant::now() > deadline {
            panic!("axion did not stop after SIGTERM");
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn demo_example_config_is_valid() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("config")
        .join("axion.demo.example.toml");
    let output = run(&["--config", path.to_str().unwrap(), "config", "check"]);
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn demo_command_serves_isolated_playback_without_privileges() {
    let port = free_port();
    let demo_config = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("config")
        .join("axion.demo.example.toml");
    let mut child = ChildGuard(
        Command::new(bin())
            .arg("--config")
            .arg(&demo_config)
            .arg("demo")
            .arg("--bind")
            .arg(format!("127.0.0.1:{port}"))
            .arg("--max-sessions")
            .arg("2")
            .env_remove("AXION_API_TOKEN")
            .env_remove("AXION_DEMO_TOKEN")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn axion demo"),
    );

    let deadline = Instant::now() + Duration::from_secs(30);
    let mut ready = false;
    while Instant::now() < deadline {
        if let Some(status) = child.0.try_wait().unwrap() {
            panic!("axion demo exited early with {status}");
        }
        if let Ok((status, _)) = try_http_request(port, "GET", "/api/health", None, None) {
            if status == 200 {
                ready = true;
                break;
            }
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    assert!(ready, "demo API did not become ready");

    let (status, dashboard) = http_request(port, "GET", "/", None, None);
    assert_eq!(status, 200);
    assert!(dashboard.contains("Live Demos"));
    assert!(dashboard.contains("DEMO DATA"));

    let (status, body) = http_request(port, "GET", "/api/demo/scenarios", None, None);
    assert_eq!(status, 200);
    let json: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(json["scenarios"].as_array().unwrap().len(), 7);
    assert_eq!(json["isolation"]["real_capture"], false);

    let (status, body) = http_request(
        port,
        "POST",
        "/api/demo/sessions",
        None,
        Some(r#"{"scenario_id":"socks5-proxy","speed":2.0}"#),
    );
    assert_eq!(status, 201);
    let json: serde_json::Value = serde_json::from_str(&body).unwrap();
    let id = json["id"].as_str().unwrap().to_string();

    let deadline = Instant::now() + Duration::from_secs(10);
    let mut completed = false;
    while Instant::now() < deadline {
        let (status, body) = http_request(
            port,
            "GET",
            &format!("/api/demo/sessions/{id}/status"),
            None,
            None,
        );
        assert_eq!(status, 200);
        let json: serde_json::Value = serde_json::from_str(&body).unwrap();
        if json["state"] == "completed" {
            assert_eq!(json["flows"][0]["detected_protocols"][0], "socks5");
            assert_eq!(json["flows"][0]["action"], "drop");
            assert_eq!(json["flows"][0]["blocked"], false);
            assert_eq!(
                json["events"][0]["matched_rule"],
                "builtin:auto-block-proxy"
            );
            assert_eq!(json["enforcement"]["can_enforce"], false);
            completed = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    assert!(completed, "demo playback did not complete");

    let (status, _) = http_request(
        port,
        "POST",
        "/api/mode",
        None,
        Some(r#"{"mode":"enforce"}"#),
    );
    assert_eq!(
        status, 403,
        "demo-only mode must disable production controls"
    );

    let (status, body) = http_request(port, "GET", "/api/status", None, None);
    assert_eq!(status, 200);
    let json: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(json["demo_only"], true);
    assert_eq!(json["enforcement_active"], false);
    assert_eq!(json["capture_source"], "demo:no-capture");
}

fn base_api_config(port: u16) -> String {
    format!(
        r#"
[general]
mode = "monitor"
worker_threads = 1
max_flows = 1000
flow_idle_timeout_seconds = 30
event_capacity = 64

[capture]
backend = "none"
interface = "lo"

[api]
enabled = true
bind = "127.0.0.1:{port}"
token = "secret"

[telemetry]
sample_interval_ms = 200
history_seconds = 10

[firewall]
bypass_cidrs = ["127.0.0.0/8", "::1/128"]
bypass_tcp_ports = []
"#
    )
}

fn write_api_config(path: &Path, port: u16) {
    std::fs::write(path, base_api_config(port)).unwrap();
}

fn write_api_config_with_rule(path: &Path, port: u16) {
    let mut config = base_api_config(port);
    config.push_str(
        r#"
[[rules]]
name = "reloaded"
description = "hot reload fixture"
enabled = true
priority = 10
action = "monitor"
log = true

[rules.match]
protocols = ["tls"]
min_confidence = 0.5
"#,
    );
    std::fs::write(path, config).unwrap();
}
