//! Axion is a Rust-native deep packet inspection and network enforcement
//! engine. The library exposes the capture-independent analysis pipeline so it
//! can be reused by the CLI, the dashboard and offline pcap inspection.

pub mod api;
pub mod capture;
pub mod config;
pub mod detection;
pub mod dpi;
pub mod engine;
pub mod firewall;
pub mod flow;
pub mod packet;
pub mod protocols;
pub mod rules;
pub mod telemetry;
