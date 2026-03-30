use std::net::IpAddr;
use std::path::{Path, PathBuf};

use serde::Deserialize;

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("Config file not found: {path}")]
    FileNotFound { path: PathBuf },

    #[error("Failed to parse config: {reason}")]
    ParseError { reason: String },

    #[error("No subnets defined in config")]
    NoSubnets,

    #[error("Invalid CIDR '{cidr}': {reason}")]
    InvalidCidr { cidr: String, reason: String },

    #[error("Duplicate subnet: {cidr}")]
    DuplicateSubnet { cidr: String },

    #[error("Invalid value for '{field}': {reason}")]
    InvalidValue { field: String, reason: String },
}

#[derive(Debug, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub scan: ScanConfig,
    #[serde(default)]
    pub output: OutputConfig,
    #[serde(default)]
    pub dns: DnsConfig,
    pub subnets: Vec<SubnetEntry>,
}

#[derive(Debug, Deserialize)]
pub struct ScanConfig {
    #[serde(default = "default_method")]
    pub method: ProbeMethod,

    #[serde(default = "default_timeout")]
    pub timeout_ms: u64,

    #[serde(default)]
    pub threads: usize,

    #[serde(default)]
    pub rate_limit: u32,

    #[serde(default = "default_randomize")]
    pub randomize: RandomizeMode,

    #[serde(default = "default_tcp_port")]
    pub tcp_port: u16,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            method: default_method(),
            timeout_ms: default_timeout(),
            threads: 0,
            rate_limit: 0,
            randomize: default_randomize(),
            tcp_port: default_tcp_port(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum ProbeMethod {
    Icmp,
    Tcp,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum RandomizeMode {
    Global,
    PerSubnet,
    None,
}

#[derive(Debug, Deserialize)]
pub struct OutputConfig {
    #[serde(default)]
    pub file: String,

    #[serde(default = "default_format")]
    pub format: OutputFormat,

    #[serde(default)]
    pub include_unreachable: bool,
}

impl Default for OutputConfig {
    fn default() -> Self {
        Self {
            file: String::new(),
            format: default_format(),
            include_unreachable: false,
        }
    }
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum OutputFormat {
    Plain,
    Json,
}

#[derive(Debug, Deserialize)]
pub struct DnsConfig {
    /// DNS server addresses (e.g. "8.8.8.8", "1.1.1.1"). Empty = system default.
    #[serde(default)]
    pub servers: Vec<String>,

    /// DNS query timeout in milliseconds.
    #[serde(default = "default_dns_timeout")]
    pub timeout_ms: u64,
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            servers: Vec::new(),
            timeout_ms: default_dns_timeout(),
        }
    }
}

fn default_dns_timeout() -> u64 {
    3000
}

#[derive(Debug, Deserialize, Clone)]
pub struct SubnetEntry {
    pub cidr: String,
    #[serde(default)]
    pub label: String,
}

fn default_method() -> ProbeMethod {
    ProbeMethod::Icmp
}
fn default_timeout() -> u64 {
    1000
}
fn default_randomize() -> RandomizeMode {
    RandomizeMode::Global
}
fn default_tcp_port() -> u16 {
    80
}
fn default_format() -> OutputFormat {
    OutputFormat::Plain
}

/// Load and validate configuration from a TOML file.
pub fn load_config(path: &Path) -> Result<Config, ConfigError> {
    if !path.exists() {
        return Err(ConfigError::FileNotFound {
            path: path.to_path_buf(),
        });
    }

    let content = std::fs::read_to_string(path).map_err(|e| ConfigError::ParseError {
        reason: e.to_string(),
    })?;

    let mut config: Config =
        toml::from_str(&content).map_err(|e| ConfigError::ParseError {
            reason: e.to_string(),
        })?;

    // Validation 1: At least one subnet
    if config.subnets.is_empty() {
        return Err(ConfigError::NoSubnets);
    }

    // Validation 2: Each CIDR must parse as Ipv4Net
    for entry in &config.subnets {
        entry.cidr.parse::<ipnet::Ipv4Net>().map_err(|e| ConfigError::InvalidCidr {
            cidr: entry.cidr.clone(),
            reason: e.to_string(),
        })?;
    }

    // Validation 3: No duplicate subnets (normalized)
    let mut seen = std::collections::HashSet::new();
    for entry in &config.subnets {
        let net: ipnet::Ipv4Net = entry.cidr.parse().unwrap();
        let normalized = net.trunc().to_string();
        if !seen.insert(normalized.clone()) {
            return Err(ConfigError::DuplicateSubnet { cidr: normalized });
        }
    }

    // Validation 4: timeout_ms > 0
    if config.scan.timeout_ms == 0 {
        return Err(ConfigError::InvalidValue {
            field: "timeout_ms".into(),
            reason: "must be greater than 0".into(),
        });
    }

    // Validation 5: tcp_port 1-65535
    if config.scan.tcp_port == 0 {
        return Err(ConfigError::InvalidValue {
            field: "tcp_port".into(),
            reason: "must be between 1 and 65535".into(),
        });
    }

    // Validation 6: DNS server addresses must be valid IPs
    for addr in &config.dns.servers {
        addr.parse::<IpAddr>().map_err(|_| ConfigError::InvalidValue {
            field: "dns.servers".into(),
            reason: format!("'{}' is not a valid IP address", addr),
        })?;
    }

    // Validation 7: dns.timeout_ms > 0
    if config.dns.timeout_ms == 0 {
        return Err(ConfigError::InvalidValue {
            field: "dns.timeout_ms".into(),
            reason: "must be greater than 0".into(),
        });
    }

    // Validation 8: Resolve threads=0 to num_cpus
    if config.scan.threads == 0 {
        config.scan.threads = num_cpus::get();
    }

    // Validation 7: Warn if ICMP without root
    if config.scan.method == ProbeMethod::Icmp && !is_root() {
        eprintln!(
            "Warning: ICMP probe requires root privileges. \
             Run with sudo or use method = \"tcp\" in config."
        );
    }

    Ok(config)
}

fn is_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

// CLI argument parsing
#[derive(Debug, clap::Parser)]
#[command(name = "subnet-recon", version, about = "Network subnet scanner")]
pub struct Cli {
    /// Config file path
    #[arg(short, long, default_value = "./config.toml")]
    pub config: PathBuf,

    /// Write results to file (overrides config)
    #[arg(short, long)]
    pub output: Option<PathBuf>,

    /// Number of worker threads (overrides config)
    #[arg(short, long)]
    pub threads: Option<usize>,

    /// Increase log verbosity
    #[arg(short, long, action = clap::ArgAction::Count)]
    pub verbose: u8,

    /// Suppress progress display
    #[arg(short, long)]
    pub quiet: bool,
}
