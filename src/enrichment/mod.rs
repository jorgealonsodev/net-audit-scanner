use std::future::Future;
use std::path::Path;
use std::sync::Once;

use serde::Deserialize;
use tokio::task::JoinSet;
use tokio::time::{Duration, sleep};

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
    #[serde(default = "default_snmp_community")]
    pub snmp_community: String,
    #[serde(default)]
    pub mac_vendors_api_key: String,
}

impl Default for EnrichmentConfig {
    fn default() -> Self {
        Self {
            snmp_enabled: true,
            mdns_enabled: true,
            mac_api_enabled: false,
            snmp_timeout_ms: 1000,
            mdns_timeout_ms: 2000,
            snmp_community: default_snmp_community(),
            mac_vendors_api_key: String::new(),
        }
    }
}

pub async fn enrich_devices(hosts: &mut [DiscoveredHost], config: &EnrichmentConfig) {
    if hosts.is_empty() {
        return;
    }

    if config.mdns_enabled {
        warn_if_docker_bridge_network();
    }

    let snmp_results = if config.snmp_enabled {
        collect_snmp_results(hosts, config.snmp_timeout_ms).await
    } else {
        empty_results(hosts.len())
    };

    let mdns_results = if config.mdns_enabled {
        collect_mdns_results(hosts, config.mdns_timeout_ms).await
    } else {
        empty_results(hosts.len())
    };

    for (index, host) in hosts.iter_mut().enumerate() {
        if let Some(result) = snmp_results[index].clone() {
            apply_snmp_result(host, result);
        }

        if let Some(result) = mdns_results[index].clone() {
            apply_mdns_result(host, result);
        }
    }

    if config.mac_api_enabled {
        enrich_missing_vendors_with_delay(hosts, None, Duration::from_secs(1), |mac, api_key| async move {
            mac_vendor::lookup_mac_vendor(&mac, api_key.as_deref()).await
        })
        .await;
    }
}

fn default_snmp_community() -> String {
    "public".to_string()
}

fn empty_results<T>(len: usize) -> Vec<Option<T>> {
    std::iter::repeat_with(|| None).take(len).collect()
}

async fn collect_snmp_results(hosts: &[DiscoveredHost], timeout_ms: u64) -> Vec<Option<snmp::SnmpResult>> {
    let mut join_set = JoinSet::new();
    let mut results = empty_results(hosts.len());

    for (index, host) in hosts.iter().enumerate() {
        let ip = host.ip;
        join_set.spawn(async move { (index, snmp::probe_snmp(ip, timeout_ms).await) });
    }

    while let Some(joined) = join_set.join_next().await {
        match joined {
            Ok((index, result)) => results[index] = result,
            Err(error) => tracing::debug!(%error, "SNMP enrichment task failed"),
        }
    }

    results
}

async fn collect_mdns_results(hosts: &[DiscoveredHost], timeout_ms: u64) -> Vec<Option<mdns::MdnsResult>> {
    let mut join_set = JoinSet::new();
    let mut results = empty_results(hosts.len());

    for (index, host) in hosts.iter().enumerate() {
        let ip = host.ip;
        join_set.spawn(async move { (index, mdns::probe_mdns(ip, timeout_ms).await) });
    }

    while let Some(joined) = join_set.join_next().await {
        match joined {
            Ok((index, result)) => results[index] = result,
            Err(error) => tracing::debug!(%error, "mDNS enrichment task failed"),
        }
    }

    results
}

fn apply_snmp_result(host: &mut DiscoveredHost, result: snmp::SnmpResult) {
    if host.hostname.as_deref().map_or(true, str::is_empty) {
        if let Some(sys_name) = normalize_value(result.sys_name) {
            host.hostname = Some(sys_name);
        }
    }

    if let Some(sys_descr) = normalize_value(result.sys_descr) {
        let trimmed = sys_descr.chars().take(80).collect::<String>().trim().to_string();
        if !trimmed.is_empty() {
            host.device_model = Some(trimmed.clone());

            if host.os_hint.as_deref().map_or(true, str::is_empty) {
                host.os_hint = Some(trimmed);
            }
        }
    }
}

fn apply_mdns_result(host: &mut DiscoveredHost, result: mdns::MdnsResult) {
    if host.hostname.as_deref().map_or(true, str::is_empty) {
        if let Some(hostname) = normalize_value(result.hostname) {
            host.hostname = Some(hostname);
        }
    }

    if host.device_model.as_deref().map_or(true, str::is_empty) {
        if let Some(device_model) = normalize_value(result.device_model) {
            host.device_model = Some(device_model);
        }
    }
}

fn normalize_value(value: Option<String>) -> Option<String> {
    let trimmed = value?.trim().to_string();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed)
    }
}

async fn enrich_missing_vendors_with_delay<F, Fut>(
    hosts: &mut [DiscoveredHost],
    api_key: Option<&str>,
    delay: Duration,
    mut lookup: F,
) where
    F: FnMut(String, Option<String>) -> Fut,
    Fut: Future<Output = Option<String>>,
{
    let mut has_called_api = false;

    for host in hosts.iter_mut() {
        if host.vendor.is_some() {
            continue;
        }

        let Some(mac) = host.mac else {
            continue;
        };

        if has_called_api {
            sleep(delay).await;
        }
        has_called_api = true;

        if let Some(vendor) = lookup(mac.to_string(), api_key.map(str::to_owned)).await {
            host.vendor = Some(vendor);
        }
    }
}

fn warn_if_docker_bridge_network() {
    static WARN_ONCE: Once = Once::new();

    WARN_ONCE.call_once(|| {
        if Path::new("/sys/class/net/docker0").exists() {
            tracing::warn!(
                "mDNS multicast may not work in Docker bridge networks. Use --network host for accurate results."
            );
        }
    });
}

#[cfg(test)]
mod tests {
    use super::{EnrichmentConfig, apply_mdns_result, apply_snmp_result, enrich_missing_vendors_with_delay};
    use crate::enrichment::mdns::MdnsResult;
    use crate::enrichment::snmp::SnmpResult;
    use crate::scanner::{DiscoveredHost, DiscoveryMethod};
    use std::time::Duration;

    #[test]
    fn enrichment_config_defaults_match_spec() {
        let config = EnrichmentConfig::default();

        assert!(config.snmp_enabled);
        assert!(config.mdns_enabled);
        assert!(!config.mac_api_enabled);
        assert_eq!(config.snmp_timeout_ms, 1000);
        assert_eq!(config.mdns_timeout_ms, 2000);
        assert_eq!(config.snmp_community, "public");
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
        assert_eq!(host.os_hint, Some("X".repeat(80)));
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

    #[test]
    fn apply_mdns_result_only_fills_empty_fields() {
        let mut host = DiscoveredHost {
            ip: "10.0.0.7".parse().unwrap(),
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

        apply_mdns_result(
            &mut host,
            MdnsResult {
                hostname: Some("living-room-tv".into()),
                device_model: Some("Apple TV".into()),
            },
        );

        assert_eq!(host.hostname, Some("living-room-tv".into()));
        assert_eq!(host.device_model, Some("Apple TV".into()));
    }

    #[test]
    fn apply_mdns_result_preserves_existing_hostname() {
        let mut host = DiscoveredHost {
            ip: "10.0.0.8".parse().unwrap(),
            mac: None,
            hostname: Some("existing-name".into()),
            method: DiscoveryMethod::Tcp,
            open_ports: vec![],
            rtt_ms: None,
            vendor: None,
            device_model: None,
            os_hint: None,
            security_findings: vec![],
        };

        apply_mdns_result(
            &mut host,
            MdnsResult {
                hostname: Some("mdns-name".into()),
                device_model: Some("HomePod mini".into()),
            },
        );

        assert_eq!(host.hostname, Some("existing-name".into()));
        assert_eq!(host.device_model, Some("HomePod mini".into()));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn mac_vendor_lookup_only_runs_for_hosts_without_vendor() {
        let mut hosts = vec![
            DiscoveredHost {
                ip: "10.0.0.9".parse().unwrap(),
                mac: Some("AA:BB:CC:DD:EE:01".parse().unwrap()),
                hostname: None,
                method: DiscoveryMethod::Tcp,
                open_ports: vec![],
                rtt_ms: None,
                vendor: Some("Existing Vendor".into()),
                device_model: None,
                os_hint: None,
                security_findings: vec![],
            },
            DiscoveredHost {
                ip: "10.0.0.10".parse().unwrap(),
                mac: Some("AA:BB:CC:DD:EE:02".parse().unwrap()),
                hostname: None,
                method: DiscoveryMethod::Tcp,
                open_ports: vec![],
                rtt_ms: None,
                vendor: None,
                device_model: None,
                os_hint: None,
                security_findings: vec![],
            },
        ];

        let mut calls = Vec::new();
        enrich_missing_vendors_with_delay(&mut hosts, None, Duration::from_millis(0), |mac, _api_key| {
            calls.push(mac.clone());
            async move { Some(format!("Vendor for {mac}")) }
        })
        .await;

        assert_eq!(calls, vec!["AA:BB:CC:DD:EE:02".to_string()]);
        assert_eq!(hosts[0].vendor.as_deref(), Some("Existing Vendor"));
        assert_eq!(hosts[1].vendor.as_deref(), Some("Vendor for AA:BB:CC:DD:EE:02"));
    }
}
