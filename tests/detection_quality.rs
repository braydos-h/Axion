//! Measured precision/recall over the labelled synthetic fixture set.
//! This is a regression guard, not a claim about arbitrary Internet traffic.

use std::path::{Path, PathBuf};
use std::process::Command;

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

struct Label {
    file: &'static str,
    proxy: bool,
}

#[test]
fn labelled_fixture_precision_and_recall() {
    let labels = [
        Label {
            file: "benign_tls.pcap",
            proxy: false,
        },
        Label {
            file: "benign_http.pcap",
            proxy: false,
        },
        Label {
            file: "benign_dns.pcap",
            proxy: false,
        },
        Label {
            file: "ipv4_fragmented_dns.pcap",
            proxy: false,
        },
        Label {
            file: "proxy_socks5.pcap",
            proxy: true,
        },
        Label {
            file: "proxy_http_connect.pcap",
            proxy: true,
        },
        Label {
            file: "proxy_vless_plaintext.pcap",
            proxy: true,
        },
        Label {
            file: "proxy_trojan_plaintext.pcap",
            proxy: true,
        },
    ];
    let mut tp = 0u32;
    let mut fp = 0u32;
    let mut tn = 0u32;
    let mut fn_ = 0u32;
    for label in &labels {
        let path = fixture(label.file);
        let output = Command::new(env!("CARGO_BIN_EXE_axion"))
            .arg("inspect")
            .arg("--pcap")
            .arg(&path)
            .arg("--json")
            .output()
            .expect("run inspect");
        assert!(
            output.status.success(),
            "inspect {} failed: {}",
            label.file,
            String::from_utf8_lossy(&output.stderr)
        );
        let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        let detected = report["events"]
            .as_array()
            .map(|e| !e.is_empty())
            .unwrap_or(false);
        match (label.proxy, detected) {
            (true, true) => tp += 1,
            (true, false) => fn_ += 1,
            (false, true) => fp += 1,
            (false, false) => tn += 1,
        }
    }
    let precision = tp as f64 / f64::max(1.0, (tp + fp) as f64);
    let recall = tp as f64 / f64::max(1.0, (tp + fn_) as f64);
    eprintln!(
        "synthetic fixtures: TP={tp} FP={fp} TN={tn} FN={fn_} precision={precision:.3} recall={recall:.3}"
    );
    assert_eq!(fn_, 0, "missed labelled proxy fixtures");
    assert_eq!(fp, 0, "false positives on labelled benign fixtures");
    assert!(precision >= 0.999 && recall >= 0.999);
}
