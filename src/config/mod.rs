use serde::Deserialize;
use std::path::PathBuf;

use crate::enrichment::EnrichmentConfig;

/// Scan configuration section.
#[derive(Debug, Deserialize)]
pub struct ScanConfig {
    pub default_network: String,
    pub port_range: String,
    pub timeout_ms: u64,
    pub banner_timeout_ms: u64,
    pub concurrency: usize,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            default_network: "auto".into(),
            port_range: "top-1000".into(),
            timeout_ms: 1500,
            banner_timeout_ms: 500,
            concurrency: 512,
        }
    }
}

/// CVE lookup configuration section.
#[derive(Debug, Deserialize)]
pub struct CveConfig {
    pub nvd_api_key: String,
    pub sources: Vec<String>,
    pub cache_ttl_hours: u64,
}

impl Default for CveConfig {
    fn default() -> Self {
        Self {
            nvd_api_key: String::new(),
            sources: vec!["nvd".into(), "circl".into()],
            cache_ttl_hours: 24,
        }
    }
}

/// Report generation configuration section.
#[derive(Debug, Deserialize)]
pub struct ReportConfig {
    pub default_format: String,
    pub open_browser: bool,
}

impl Default for ReportConfig {
    fn default() -> Self {
        Self {
            default_format: "html".into(),
            open_browser: true,
        }
    }
}

/// Credentials check configuration section.
#[derive(Debug, Deserialize)]
pub struct CredentialsCheckConfig {
    pub enabled: bool,
    pub custom_list: String,
}

impl Default for CredentialsCheckConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            custom_list: String::new(),
        }
    }
}

/// Top-level application configuration loaded from `~/.netascan/config.toml`.
#[derive(Debug, Default, Deserialize)]
pub struct Config {
    pub scan: ScanConfig,
    pub cve: CveConfig,
    pub report: ReportConfig,
    pub credentials_check: CredentialsCheckConfig,
    #[serde(default)]
    pub enrichment: EnrichmentConfig,
}

impl Config {
    /// Resolve the config file path at `~/.netascan/config.toml`.
    fn config_path() -> PathBuf {
        let home = std::env::var("HOME").unwrap_or_default();
        PathBuf::from(home).join(".netascan").join("config.toml")
    }

    /// Load configuration from file, falling back to defaults if the file is missing.
    pub fn load() -> Result<Self, crate::error::Error> {
        let path = Self::config_path();
        if path.exists() {
            let content = std::fs::read_to_string(&path)?;
            let config: Config = toml::from_str(&content).map_err(|e| crate::error::Error::Config(e.to_string()))?;
            Ok(config)
        } else {
            Ok(Config::default())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_has_expected_values() {
        let cfg = Config::default();
        assert_eq!(cfg.scan.default_network, "auto");
        assert_eq!(cfg.scan.port_range, "top-1000");
        assert_eq!(cfg.scan.timeout_ms, 1500);
        assert_eq!(cfg.scan.banner_timeout_ms, 500);
        assert_eq!(cfg.scan.concurrency, 512);
        assert_eq!(cfg.cve.cache_ttl_hours, 24);
        assert_eq!(cfg.report.default_format, "html");
        assert!(cfg.report.open_browser);
        assert!(cfg.credentials_check.enabled);
    }

    #[test]
    fn load_returns_defaults_when_file_missing() {
        // On a clean environment without ~/.netascan/config.toml, load returns defaults.
        let cfg = Config::load().expect("load should succeed with defaults");
        assert_eq!(cfg.scan.default_network, "auto");
    }

    #[test]
    fn default_config_has_enrichment_defaults() {
        let cfg = Config::default();
        assert!(cfg.enrichment.snmp_enabled);
        assert!(cfg.enrichment.mdns_enabled);
        assert!(cfg.enrichment.mac_api_enabled);
        assert_eq!(cfg.enrichment.snmp_timeout_ms, 1000);
        assert_eq!(cfg.enrichment.mdns_timeout_ms, 2000);
        assert_eq!(cfg.enrichment.snmp_community, "public");
    }
}
