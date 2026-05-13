//! CVE correlation module — NVD API client, local SQLite cache, vulnerability matching.
//!
//! # Pipeline
//!
//! ```text
//! OpenPort.banner → extract_version → build_cpe → query_nvd_cached → Vec<CveMatch> → port.cves
//! ```
//!
//! Call [`enrich_cve`] after port scanning and OUI enrichment in the CLI pipeline.

pub mod cache;
pub mod client;
pub mod models;
pub mod parser;

use crate::scanner::models::DiscoveredHost;
use cache::{CveCache, query_nvd_cached};
use client::NvdClient;

/// Enrich discovered hosts with CVE data from NVD.
///
/// Iterates each host's open ports, extracts version info from banners,
/// builds CPE strings, and queries NVD (through the local SQLite cache).
/// Results are attached directly to each [`OpenPort`](crate::scanner::models::OpenPort).
///
/// # Parameters
///
/// - `hosts` — mutable slice of discovered hosts (mutated in place).
/// - `cache` — SQLite-backed CVE cache.
/// - `client` — NVD API client.
/// - `skip` — when `true`, all CVE enrichment is skipped (e.g. `--no-cve`).
///
/// # Errors
///
/// NVD or cache errors are logged as warnings and do **not** abort the scan.
/// Affected ports simply receive an empty `cves` vector.
pub async fn enrich_cve(hosts: &mut [DiscoveredHost], cache: &CveCache, client: &NvdClient, skip: bool) {
    if skip {
        return;
    }

    for host in hosts.iter_mut() {
        for port in host.open_ports.iter_mut() {
            let banner = match port.banner.as_deref() {
                Some(b) if !b.is_empty() => b,
                _ => {
                    port.cves = Vec::new();
                    continue;
                }
            };

            let (product, version) = match parser::extract_version(banner, port.service.clone()) {
                Some(pv) => pv,
                None => {
                    port.cves = Vec::new();
                    continue;
                }
            };

            let cpe = parser::build_cpe(&product, &version);

            match query_nvd_cached(client, cache, &cpe).await {
                Ok(matches) => port.cves = matches,
                Err(e) => {
                    tracing::warn!("CVE lookup failed for {}:{} (CPE: {}): {}", host.ip, port.port, cpe, e);
                    port.cves = Vec::new();
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    // CveMatch is used via OpenPort.cves in tests below
    use crate::scanner::models::{DiscoveryMethod, OpenPort, Protocol, ServiceType};
    use sqlx::sqlite::SqlitePoolOptions;
    use std::net::IpAddr;
    use wiremock::matchers::{method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    async fn make_cache() -> CveCache {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        CveCache::with_pool(pool).await.unwrap()
    }

    fn make_host_with_banner(ip: &str, port: u16, banner: &str, service: ServiceType) -> DiscoveredHost {
        DiscoveredHost {
            ip: ip.parse::<IpAddr>().unwrap(),
            mac: None,
            hostname: None,
            method: DiscoveryMethod::Tcp,
            open_ports: vec![OpenPort {
                port,
                service,
                banner: Some(banner.into()),
                protocol: Protocol::Tcp,
                is_insecure: false,
                cves: vec![],
            }],
            rtt_ms: None,
            vendor: None,
            os_hint: None,
        }
    }

    // ─── enrich_cve tests ───

    #[tokio::test]
    async fn enrich_cve_populates_cves_for_banner() {
        let server = MockServer::start().await;
        let client = NvdClient::with_base_url(None, server.uri());
        let cache = make_cache().await;

        let cpe = "cpe:2.3:a:openbsd:openssh:8.9:*:*:*:*:*:*:*";
        Mock::given(method("GET"))
            .and(path("/rest/json/cves/2.0"))
            .and(query_param("cpeName", cpe))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "vulnerabilities": [
                    {
                        "cve": {
                            "id": "CVE-2021-41617",
                            "descriptions": [{"lang": "en", "value": "sshd privilege escalation"}],
                            "published": "2021-09-20T00:00:00.000"
                        },
                        "impact": {
                            "baseMetricV3": {
                                "cvssV3": {"baseScore": 7.8, "baseSeverity": "HIGH"}
                            }
                        }
                    }
                ]
            })))
            .mount(&server)
            .await;

        let mut hosts = vec![make_host_with_banner(
            "192.168.1.10",
            22,
            "SSH-2.0-OpenSSH_8.9",
            ServiceType::Ssh,
        )];

        enrich_cve(&mut hosts, &cache, &client, false).await;

        assert_eq!(hosts[0].open_ports[0].cves.len(), 1);
        assert_eq!(hosts[0].open_ports[0].cves[0].cve_id, "CVE-2021-41617");
    }

    #[tokio::test]
    async fn enrich_cve_skips_when_no_cve_flag_set() {
        let server = MockServer::start().await;
        let client = NvdClient::with_base_url(None, server.uri());
        let cache = make_cache().await;

        // No mock mounted — if it tries to call NVD the test will hang/fail
        let mut hosts = vec![make_host_with_banner(
            "192.168.1.10",
            22,
            "SSH-2.0-OpenSSH_8.9",
            ServiceType::Ssh,
        )];

        enrich_cve(&mut hosts, &cache, &client, true).await;

        assert!(hosts[0].open_ports[0].cves.is_empty());
    }

    #[tokio::test]
    async fn enrich_cve_handles_missing_banner() {
        let server = MockServer::start().await;
        let client = NvdClient::with_base_url(None, server.uri());
        let cache = make_cache().await;

        let mut hosts = vec![DiscoveredHost {
            ip: "192.168.1.10".parse().unwrap(),
            mac: None,
            hostname: None,
            method: DiscoveryMethod::Tcp,
            open_ports: vec![OpenPort {
                port: 22,
                service: ServiceType::Ssh,
                banner: None,
                protocol: Protocol::Tcp,
                is_insecure: false,
                cves: vec![],
            }],
            rtt_ms: None,
            vendor: None,
            os_hint: None,
        }];

        enrich_cve(&mut hosts, &cache, &client, false).await;
        assert!(hosts[0].open_ports[0].cves.is_empty());
    }

    #[tokio::test]
    async fn enrich_cve_deduplicates_cpe_across_hosts() {
        let server = MockServer::start().await;
        let client = NvdClient::with_base_url(None, server.uri());
        let cache = make_cache().await;

        let cpe = "cpe:2.3:a:openbsd:openssh:8.9:*:*:*:*:*:*:*";
        Mock::given(method("GET"))
            .and(path("/rest/json/cves/2.0"))
            .and(query_param("cpeName", cpe))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "vulnerabilities": [
                    {
                        "cve": {
                            "id": "CVE-2021-41617",
                            "descriptions": [{"lang": "en", "value": "sshd privilege escalation"}],
                            "published": "2021-09-20T00:00:00.000"
                        },
                        "impact": {
                            "baseMetricV3": {
                                "cvssV3": {"baseScore": 7.8, "baseSeverity": "HIGH"}
                            }
                        }
                    }
                ]
            })))
            .expect(1) // only one HTTP request despite two hosts
            .mount(&server)
            .await;

        let mut hosts = vec![
            make_host_with_banner("192.168.1.10", 22, "SSH-2.0-OpenSSH_8.9", ServiceType::Ssh),
            make_host_with_banner("192.168.1.11", 22, "SSH-2.0-OpenSSH_8.9", ServiceType::Ssh),
        ];

        enrich_cve(&mut hosts, &cache, &client, false).await;

        assert_eq!(hosts[0].open_ports[0].cves.len(), 1);
        assert_eq!(hosts[1].open_ports[0].cves.len(), 1);
        assert_eq!(hosts[0].open_ports[0].cves[0].cve_id, "CVE-2021-41617");
        assert_eq!(hosts[1].open_ports[0].cves[0].cve_id, "CVE-2021-41617");
    }

    #[tokio::test]
    async fn enrich_cve_graceful_on_api_error() {
        let server = MockServer::start().await;
        let client = NvdClient::with_base_url(None, server.uri());
        let cache = make_cache().await;

        Mock::given(method("GET"))
            .and(path("/rest/json/cves/2.0"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;

        let mut hosts = vec![make_host_with_banner(
            "192.168.1.10",
            22,
            "SSH-2.0-OpenSSH_8.9",
            ServiceType::Ssh,
        )];

        enrich_cve(&mut hosts, &cache, &client, false).await;

        // Should continue with empty cves, not panic or abort
        assert!(hosts[0].open_ports[0].cves.is_empty());
    }

    #[tokio::test]
    async fn enrich_cve_populates_multiple_ports_per_host() {
        let server = MockServer::start().await;
        let client = NvdClient::with_base_url(None, server.uri());
        let cache = make_cache().await;

        Mock::given(method("GET"))
            .and(path("/rest/json/cves/2.0"))
            .and(query_param("cpeName", "cpe:2.3:a:openbsd:openssh:8.9:*:*:*:*:*:*:*"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "vulnerabilities": [
                    {
                        "cve": {
                            "id": "CVE-SSH-001",
                            "descriptions": [{"lang": "en", "value": "SSH bug"}],
                            "published": "2021-01-01T00:00:00.000"
                        },
                        "impact": {
                            "baseMetricV3": {
                                "cvssV3": {"baseScore": 7.0, "baseSeverity": "HIGH"}
                            }
                        }
                    }
                ]
            })))
            .mount(&server)
            .await;

        Mock::given(method("GET"))
            .and(path("/rest/json/cves/2.0"))
            .and(query_param("cpeName", "cpe:2.3:a:nginx:nginx:1.21.6:*:*:*:*:*:*:*"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "vulnerabilities": [
                    {
                        "cve": {
                            "id": "CVE-NGX-001",
                            "descriptions": [{"lang": "en", "value": "nginx bug"}],
                            "published": "2022-01-01T00:00:00.000"
                        },
                        "impact": {
                            "baseMetricV3": {
                                "cvssV3": {"baseScore": 5.0, "baseSeverity": "MEDIUM"}
                            }
                        }
                    }
                ]
            })))
            .mount(&server)
            .await;

        let mut hosts = vec![DiscoveredHost {
            ip: "192.168.1.10".parse().unwrap(),
            mac: None,
            hostname: None,
            method: DiscoveryMethod::Tcp,
            open_ports: vec![
                OpenPort {
                    port: 22,
                    service: ServiceType::Ssh,
                    banner: Some("SSH-2.0-OpenSSH_8.9".into()),
                    protocol: Protocol::Tcp,
                    is_insecure: false,
                    cves: vec![],
                },
                OpenPort {
                    port: 80,
                    service: ServiceType::Http,
                    banner: Some("nginx/1.21.6".into()),
                    protocol: Protocol::Tcp,
                    is_insecure: false,
                    cves: vec![],
                },
            ],
            rtt_ms: None,
            vendor: None,
            os_hint: None,
        }];

        enrich_cve(&mut hosts, &cache, &client, false).await;

        assert_eq!(hosts[0].open_ports[0].cves.len(), 1);
        assert_eq!(hosts[0].open_ports[0].cves[0].cve_id, "CVE-SSH-001");
        assert_eq!(hosts[0].open_ports[1].cves.len(), 1);
        assert_eq!(hosts[0].open_ports[1].cves[0].cve_id, "CVE-NGX-001");
    }
}
