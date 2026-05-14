use serde::Deserialize;

use crate::scanner::DiscoveredHost;

pub mod mac_vendor;
pub mod mdns;
pub mod snmp;

#[derive(Debug, Clone, Deserialize)]
pub struct EnrichmentConfig {
    pub snmp_enabled: bool,
    pub mdns_enabled: bool,
    pub mac_api_enabled: bool,
    pub snmp_timeout_ms: u64,
    pub mdns_timeout_ms: u64,
}

impl Default for EnrichmentConfig {
    fn default() -> Self {
        Self {
            snmp_enabled: true,
            mdns_enabled: true,
            mac_api_enabled: false,
            snmp_timeout_ms: 1000,
            mdns_timeout_ms: 2000,
        }
    }
}

pub async fn enrich_devices(hosts: &mut [DiscoveredHost], config: &EnrichmentConfig) {
    if !config.snmp_enabled {
        return;
    }

    for host in hosts.iter_mut() {
        if let Some(result) = snmp::probe_snmp(host.ip, config.snmp_timeout_ms).await {
            apply_snmp_result(host, result);
        }
    }
}

fn apply_snmp_result(host: &mut DiscoveredHost, result: snmp::SnmpResult) {
    if host.hostname.as_deref().map_or(true, str::is_empty) {
        if let Some(sys_name) = result.sys_name.filter(|value| !value.trim().is_empty()) {
            host.hostname = Some(sys_name.trim().to_string());
        }
    }

    if let Some(sys_descr) = result.sys_descr {
        let trimmed = sys_descr.trim();
        if !trimmed.is_empty() {
            host.device_model = Some(trimmed.chars().take(80).collect::<String>().trim().to_string());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{EnrichmentConfig, apply_snmp_result};
    use crate::enrichment::snmp::SnmpResult;
    use crate::scanner::{DiscoveredHost, DiscoveryMethod};

    #[test]
    fn enrichment_config_defaults_match_spec() {
        let config = EnrichmentConfig::default();

        assert!(config.snmp_enabled);
        assert!(config.mdns_enabled);
        assert!(!config.mac_api_enabled);
        assert_eq!(config.snmp_timeout_ms, 1000);
        assert_eq!(config.mdns_timeout_ms, 2000);
    }

    #[test]
    fn apply_snmp_result_sets_hostname_and_trimmed_model() {
        let mut host = DiscoveredHost {
            ip: "10.0.0.5".parse().unwrap(),
            mac: None,
            hostname: None,
            method: DiscoveryMethod::Tcp,
            open_ports: vec![],
            rtt_ms: None,
            vendor: None,
            device_model: None,
            os_hint: None,
            security_findings: vec![],
        };

        apply_snmp_result(
            &mut host,
            SnmpResult {
                sys_name: Some("  edge-router  ".into()),
                sys_descr: Some(format!("  {}  ", "X".repeat(90))),
            },
        );

        assert_eq!(host.hostname, Some("edge-router".into()));
        assert_eq!(host.device_model, Some("X".repeat(80)));
    }

    #[test]
    fn apply_snmp_result_preserves_existing_hostname() {
        let mut host = DiscoveredHost {
            ip: "10.0.0.6".parse().unwrap(),
            mac: None,
            hostname: Some("existing-host".into()),
            method: DiscoveryMethod::Tcp,
            open_ports: vec![],
            rtt_ms: None,
            vendor: None,
            device_model: None,
            os_hint: None,
            security_findings: vec![],
        };

        apply_snmp_result(
            &mut host,
            SnmpResult {
                sys_name: Some("snmp-host".into()),
                sys_descr: Some("Switch Model".into()),
            },
        );

        assert_eq!(host.hostname, Some("existing-host".into()));
        assert_eq!(host.device_model, Some("Switch Model".into()));
    }
}
