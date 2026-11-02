use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
use std::{
    path::{Path, PathBuf},
    str::FromStr,
};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct Settings {
    pub preferred_interface: Option<String>,
    pub auto_interface: bool,
    pub web_host: String,
    pub web_port: u16,
    pub strict_port: bool,
    pub open_browser: bool,
    pub start_capture: bool,
    pub ai_enabled: bool,
    pub max_flows: usize,
    pub flow_timeout_seconds: u64,
    pub log_filter: String,
}
impl Default for Settings {
    fn default() -> Self {
        Self {
            preferred_interface: None,
            auto_interface: true,
            web_host: "127.0.0.1".into(),
            web_port: 8080,
            strict_port: false,
            open_browser: false,
            start_capture: true,
            ai_enabled: false,
            max_flows: 10_000,
            flow_timeout_seconds: 120,
            log_filter: "axion=info".into(),
        }
    }
}
impl Settings {
    pub fn path() -> anyhow::Result<PathBuf> {
        #[cfg(target_os = "windows")]
        let base = std::env::var_os("APPDATA").map(PathBuf::from);
        #[cfg(target_os = "macos")]
        let base =
            std::env::var_os("HOME").map(|v| PathBuf::from(v).join("Library/Application Support"));
        #[cfg(not(any(target_os = "windows", target_os = "macos")))]
        let base = std::env::var_os("XDG_CONFIG_HOME")
            .filter(|v| !v.is_empty())
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("HOME").map(|v| PathBuf::from(v).join(".config")));
        Ok(base
            .ok_or_else(|| anyhow::anyhow!("Cannot determine user configuration directory"))?
            .join("axion")
            .join("config.json"))
    }
    pub fn load() -> anyhow::Result<Self> {
        Self::load_from(&Self::path()?)
    }
    pub fn load_from(path: &Path) -> anyhow::Result<Self> {
        match std::fs::read(path) {
            Ok(bytes) => {
                let settings: Self = serde_json::from_slice(&bytes)?;
                settings.validate()?;
                Ok(settings)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(e.into()),
        }
    }
    pub fn save(&self) -> anyhow::Result<()> {
        self.save_to(&Self::path()?)
    }
    pub fn save_to(&self, path: &Path) -> anyhow::Result<()> {
        self.validate()?;
        let parent = path
            .parent()
            .ok_or_else(|| anyhow::anyhow!("Invalid configuration path"))?;
        std::fs::create_dir_all(parent)?;
        // Write a complete temporary file first. Rename replaces atomically on Unix;
        // Windows requires removing the previous destination before the rename.
        let tmp = path.with_extension(format!("{}.tmp", std::process::id()));
        std::fs::write(&tmp, serde_json::to_vec_pretty(self)?)?;
        #[cfg(windows)]
        if path.exists() {
            std::fs::remove_file(path)?;
        }
        std::fs::rename(tmp, path)?;
        Ok(())
    }
    pub fn validate(&self) -> anyhow::Result<()> {
        let host = self.web_host.trim_matches(['[', ']']);
        anyhow::ensure!(host.eq_ignore_ascii_case("localhost") || std::net::IpAddr::from_str(host).is_ok_and(|ip| ip.is_loopback()), "Dashboard host must be a loopback address; remote access requires a secured reverse proxy");
        anyhow::ensure!(
            self.max_flows > 0 && self.max_flows <= 1_000_000,
            "max_flows must be between 1 and 1000000"
        );
        anyhow::ensure!(
            self.flow_timeout_seconds > 0,
            "flow_timeout_seconds must be positive"
        );
        anyhow::ensure!(
            self.preferred_interface
                .as_ref()
                .is_none_or(|s| !s.trim().is_empty() && s.len() <= 256),
            "Invalid interface name"
        );
        anyhow::ensure!(
            !self.log_filter.is_empty() && self.log_filter.len() <= 256,
            "Invalid log filter"
        );
        Ok(())
    }
}

#[derive(Debug, Parser)]
#[command(
    name = "axion",
    version,
    about = "Passive network traffic intelligence",
    long_about = "Start the local dashboard and passively analyze network traffic. Live capture may require capture permissions; demo and replay do not."
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Command>,
    #[arg(long, env = "AXION_WEB_HOST", global = true)]
    pub web_host: Option<String>,
    #[arg(long, env = "AXION_WEB_PORT", global = true)]
    pub web_port: Option<u16>,
    #[arg(long, global = true)]
    pub strict_port: bool,
    #[arg(long, global = true, conflicts_with = "no_browser")]
    pub open_browser: bool,
    #[arg(long, global = true)]
    pub no_browser: bool,
    #[arg(long, env = "AXION_MAX_FLOWS", global = true)]
    pub max_flows: Option<usize>,
    #[arg(long, env = "AXION_FLOW_TIMEOUT_SECONDS", global = true)]
    pub flow_timeout_seconds: Option<u64>,
}
impl Cli {
    pub fn resolve(&self, mut settings: Settings) -> anyhow::Result<Settings> {
        if let Some(v) = &self.web_host {
            settings.web_host = v.clone();
        }
        if let Some(v) = self.web_port {
            settings.web_port = v;
        }
        if self.strict_port {
            settings.strict_port = true;
        }
        if self.open_browser {
            settings.open_browser = true;
        }
        if self.no_browser {
            settings.open_browser = false;
        }
        if let Some(v) = self.max_flows {
            settings.max_flows = v;
        }
        if let Some(v) = self.flow_timeout_seconds {
            settings.flow_timeout_seconds = v;
        }
        if let Ok(v) = std::env::var("AXION_AI_ENABLED") {
            settings.ai_enabled = match v.to_ascii_lowercase().as_str() {
                "true" | "1" => true,
                "false" | "0" => false,
                _ => anyhow::bail!("AXION_AI_ENABLED must be true, false, 1, or 0"),
            };
        }
        settings.validate()?;
        Ok(settings)
    }
}
#[derive(Debug, Subcommand)]
pub enum Command {
    /// List capture interfaces.
    Interfaces,
    /// Passively capture live traffic.
    Capture {
        #[arg(short, long, default_value = "auto")]
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

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn settings_round_trip_and_validation() {
        let path = std::env::temp_dir()
            .join(format!("axion-config-test-{}", std::process::id()))
            .join("config.json");
        let settings = Settings {
            web_port: 9090,
            preferred_interface: Some("test0".into()),
            ..Settings::default()
        };
        settings.save_to(&path).unwrap();
        assert_eq!(Settings::load_from(&path).unwrap(), settings);
        let mut invalid = settings;
        invalid.web_host = "0.0.0.0".into();
        assert!(invalid.validate().is_err());
        std::fs::remove_file(path).unwrap();
    }
}
