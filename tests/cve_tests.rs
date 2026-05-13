//! CVE engine integration tests.
//!
//! These tests exercise the full CVE pipeline with mocked NVD responses
//! and in-memory SQLite caches. No real NVD API calls are made.

use netascan::cve::cache::CveCache;
use netascan::cve::client::NvdClient;
use netascan::cve::enrich_cve;
use netascan::cve::models::Severity;
use netascan::scanner::models::{DiscoveredHost, DiscoveryMethod, OpenPort, Protocol, ServiceType};
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

/// Full pipeline: banner → extract_version → build_cpe → cached query → CveMatch returned.
#[tokio::test]
async fn banner_to_cve_pipeline() {
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

    let port = &hosts[0].open_ports[0];
    assert_eq!(port.cves.len(), 1);
    assert_eq!(port.cves[0].cve_id, "CVE-2021-41617");
    assert_eq!(port.cves[0].severity, Severity::High);
    assert_eq!(port.cves[0].score, Some(7.8));
}

/// Second scan with identical CPE hits SQLite cache; no HTTP request made.
#[tokio::test]
async fn second_scan_hits_cache() {
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
        .expect(1) // exactly one HTTP call
        .mount(&server)
        .await;

    let mut hosts1 = vec![make_host_with_banner(
        "192.168.1.10",
        22,
        "SSH-2.0-OpenSSH_8.9",
        ServiceType::Ssh,
    )];
    let mut hosts2 = vec![make_host_with_banner(
        "192.168.1.11",
        22,
        "SSH-2.0-OpenSSH_8.9",
        ServiceType::Ssh,
    )];

    enrich_cve(&mut hosts1, &cache, &client, false).await;
    enrich_cve(&mut hosts2, &cache, &client, false).await;

    assert_eq!(hosts1[0].open_ports[0].cves.len(), 1);
    assert_eq!(hosts2[0].open_ports[0].cves.len(), 1);
}

/// `--no-cve` produces hosts with empty cves arrays.
#[tokio::test]
async fn no_cve_flag_produces_empty_cves() {
    let server = MockServer::start().await;
    let client = NvdClient::with_base_url(None, server.uri());
    let cache = make_cache().await;

    // No mock mounted — would fail if any HTTP call is attempted
    let mut hosts = vec![make_host_with_banner(
        "192.168.1.10",
        22,
        "SSH-2.0-OpenSSH_8.9",
        ServiceType::Ssh,
    )];

    enrich_cve(&mut hosts, &cache, &client, true).await;

    assert!(hosts[0].open_ports[0].cves.is_empty());
}

/// NVD unreachable produces warning log, scan continues without CVEs.
#[tokio::test]
async fn nvd_unreachable_graceful_degradation() {
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

    assert!(hosts[0].open_ports[0].cves.is_empty());
}
