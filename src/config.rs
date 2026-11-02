use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(
    name = "axion",
    version,
    about = "Passive network traffic intelligence"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
    #[arg(
        long,
        env = "AXION_WEB_HOST",
        default_value = "127.0.0.1",
        global = true
    )]
    pub web_host: String,
    #[arg(long, env = "AXION_WEB_PORT", default_value_t = 8080, global = true)]
    pub web_port: u16,
    #[arg(long, env = "AXION_MAX_FLOWS", default_value_t = 10_000, global = true)]
    pub max_flows: usize,
    #[arg(
        long,
        env = "AXION_FLOW_TIMEOUT_SECONDS",
        default_value_t = 120,
        global = true
    )]
    pub flow_timeout_seconds: u64,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// List capture interfaces.
    Interfaces,
    /// Passively capture live traffic.
    Capture {
        #[arg(short, long)]
        interface: String,
    },
    /// Analyze a pcap file.
    Replay {
        #[arg(short, long)]
        file: PathBuf,
    },
    /// Show explicitly simulated flow metadata.
    Demo,
}
