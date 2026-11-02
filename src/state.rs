use crate::{
    ai::ClefResult, capture::Manager, config::Settings, detection::LocalDetection, flow::Flow,
};
use serde::Serialize;
use std::{
    collections::HashMap,
    sync::{atomic::AtomicBool, Arc},
};
use tokio::sync::{broadcast, Mutex, RwLock};

#[derive(Clone, Serialize)]
pub struct FlowView {
    pub flow: Flow,
    pub local: LocalDetection,
    pub ai: Option<ClefResult>,
    pub ai_status: String,
    pub last_analysis_ms: Option<u64>,
}

#[derive(Clone, Serialize)]
pub struct Status {
    pub capture_running: bool,
    pub ai_status: String,
    pub interface: String,
    pub mode: String,
    pub ai_enabled: bool,
    pub last_error: Option<String>,
}

#[derive(Clone, Default, Serialize)]
pub struct Stats {
    pub packets_captured: u64,
    pub active_flows: usize,
    pub tcp_flows: usize,
    pub udp_flows: usize,
    pub total_bytes: u64,
    pub suspicious_flows: usize,
    pub ai_classified_flows: u64,
    pub packets_per_second: u64,
    pub dropped_capture_events: u64,
    pub dropped_analysis_events: u64,
}

#[derive(Clone, Serialize)]
pub struct Event {
    #[serde(rename = "type")]
    pub kind: String,
    pub data: serde_json::Value,
}

pub struct Inner {
    pub status: Status,
    pub stats: Stats,
    pub flows: HashMap<u64, FlowView>,
}

#[derive(Clone)]
pub struct AppState {
    pub inner: Arc<RwLock<Inner>>,
    pub events: broadcast::Sender<Event>,
    pub allowed_hosts: Arc<Vec<String>>,
    pub shutdown: Arc<AtomicBool>,
    pub capture: Option<Arc<Manager>>,
    pub capture_control: Arc<Mutex<()>>,
    pub settings_control: Arc<Mutex<()>>,
    pub settings: Arc<RwLock<Settings>>,
    pub active_settings: Arc<Settings>,
    pub settings_path: Option<std::path::PathBuf>,
}

impl AppState {
    pub fn new(status: Status) -> Self {
        let (events, _) = broadcast::channel(1024);
        Self {
            inner: Arc::new(RwLock::new(Inner {
                status,
                stats: Stats::default(),
                flows: HashMap::new(),
            })),
            events,
            allowed_hosts: Arc::new(vec!["localhost".into(), "127.0.0.1".into(), "::1".into()]),
            shutdown: Arc::new(AtomicBool::new(false)),
            capture: None,
            capture_control: Arc::new(Mutex::new(())),
            settings_control: Arc::new(Mutex::new(())),
            settings: Arc::new(RwLock::new(Settings::default())),
            active_settings: Arc::new(Settings::default()),
            settings_path: Settings::path().ok(),
        }
    }
    pub fn emit<T: Serialize>(&self, kind: &str, value: &T) {
        if let Ok(data) = serde_json::to_value(value) {
            let _ = self.events.send(Event {
                kind: kind.into(),
                data,
            });
        }
    }
}
