//! View models bridging scan data to report templates.

use crate::cve::models::CveMatch;
use crate::scanner::models::{DiscoveredHost, OpenPort};
use macaddr::MacAddr6;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// Flattened CVE info for template rendering.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ReportCve {
    pub cve_id: String,
    pub description: String,
    pub severity: String,
    pub score: Option<f32>,
}

/// Per-port summary for template rendering.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ReportPort {
    pub port: u16,
    pub service: String,
    pub banner: Option<String>,
    pub is_insecure: bool,
    pub cve_count: usize,
}

/// Per-host summary for template rendering.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportHost {
    pub ip: String,
    pub mac: Option<String>,
    pub hostname: Option<String>,
    pub vendor: Option<String>,
    pub open_ports: Vec<ReportPort>,
    pub cves: Vec<ReportCve>,
    pub total_cves: usize,
    pub insecure_ports: usize,
}

/// Top-level report container.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportContext {
    pub generated_at: String,
    pub version: String,
    pub network: String,
    pub host_count: usize,
    pub hosts: Vec<ReportHost>,
}

impl From<&CveMatch> for ReportCve {
    fn from(cve: &CveMatch) -> Self {
        ReportCve {
            cve_id: cve.cve_id.clone(),
            description: cve.description.clone(),
            severity: format!("{:?}", cve.severity).to_lowercase(),
            score: cve.score,
        }
    }
}

impl From<&OpenPort> for ReportPort {
    fn from(port: &OpenPort) -> Self {
        ReportPort {
            port: port.port,
            service: format!("{:?}", port.service).to_lowercase(),
            banner: port.banner.clone(),
            is_insecure: port.is_insecure,
            cve_count: port.cves.len(),
        }
    }
}

impl From<&DiscoveredHost> for ReportHost {
    fn from(host: &DiscoveredHost) -> Self {
        let open_ports: Vec<ReportPort> = host.open_ports.iter().map(ReportPort::from).collect();

        // Aggregate and deduplicate CVEs across all ports
        let mut seen = HashSet::new();
        let mut cves: Vec<ReportCve> = Vec::new();
        for port in &host.open_ports {
            for cve in &port.cves {
                if seen.insert(cve.cve_id.clone()) {
                    cves.push(ReportCve::from(cve));
                }
            }
        }

        let insecure_ports = host.open_ports.iter().filter(|p| p.is_insecure).count();
        let total_cves = cves.len();

        ReportHost {
            ip: host.ip.to_string(),
            mac: host.mac.map(format_mac),
            hostname: host.hostname.clone(),
            vendor: host.vendor.clone(),
            open_ports,
            cves,
            total_cves,
            insecure_ports,
        }
    }
}

impl From<&Vec<DiscoveredHost>> for ReportContext {
    fn from(hosts: &Vec<DiscoveredHost>) -> Self {
        let hosts: Vec<ReportHost> = hosts.iter().map(ReportHost::from).collect();
        let host_count = hosts.len();
        ReportContext {
            generated_at: chrono::Utc::now().to_rfc3339(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            network: "unknown".to_string(),
            host_count,
            hosts,
        }
    }
}

fn format_mac(mac: MacAddr6) -> String {
    let bytes = mac.as_bytes();
    bytes
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<_>>()
        .join(":")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cve::models::Severity;
    use crate::scanner::models::ServiceType;

    fn make_cve(id: &str, severity: Severity, score: Option<f32>) -> CveMatch {
        CveMatch {
            cve_id: id.into(),
            description: format!("Description for {}", id),
            severity,
            score,
            published: "2021-01-01".into(),
        }
    }

    fn make_port(port: u16, service: ServiceType, is_insecure: bool, cves: Vec<CveMatch>) -> OpenPort {
        OpenPort {
            port,
            service,
            banner: None,
            protocol: crate::scanner::models::Protocol::Tcp,
            is_insecure,
            cves,
        }
    }

    // ── ReportCve tests ──

    #[test]
    fn report_cve_from_cve_match() {
        let cve = make_cve("CVE-2021-1234", Severity::High, Some(7.5));
        let report = ReportCve::from(&cve);
        assert_eq!(report.cve_id, "CVE-2021-1234");
        assert_eq!(report.description, "Description for CVE-2021-1234");
        assert_eq!(report.severity, "high");
        assert_eq!(report.score, Some(7.5));
    }

    #[test]
    fn report_cve_with_none_score() {
        let cve = make_cve("CVE-2020-0001", Severity::Unknown, None);
        let report = ReportCve::from(&cve);
        assert_eq!(report.score, None);
        assert_eq!(report.severity, "unknown");
    }

    #[test]
    fn report_cve_serializes_to_json() {
        let cve = ReportCve {
            cve_id: "CVE-2021-1234".into(),
            description: "Test".into(),
            severity: "high".into(),
            score: Some(7.5),
        };
        let json = serde_json::to_string(&cve).unwrap();
        assert!(json.contains("cve_id"));
        assert!(json.contains("CVE-2021-1234"));
        assert!(json.contains("description"));
        assert!(json.contains("severity"));
        assert!(json.contains("score"));
        assert!(json.contains("7.5"));
    }

    // ── ReportPort tests ──

    #[test]
    fn report_port_from_open_port() {
        let port = make_port(22, ServiceType::Ssh, false, vec![make_cve("CVE-2021-1", Severity::High, Some(7.0))]);
        let report = ReportPort::from(&port);
        assert_eq!(report.port, 22);
        assert_eq!(report.service, "ssh");
        assert!(!report.is_insecure);
        assert_eq!(report.cve_count, 1);
    }

    #[test]
    fn report_port_insecure_flag() {
        let port = make_port(23, ServiceType::Telnet, true, vec![]);
        let report = ReportPort::from(&port);
        assert!(report.is_insecure);
        assert_eq!(report.cve_count, 0);
    }

    #[test]
    fn report_port_serializes_to_json() {
        let port = ReportPort {
            port: 80,
            service: "http".into(),
            banner: Some("Apache/2.4".into()),
            is_insecure: true,
            cve_count: 3,
        };
        let json = serde_json::to_string(&port).unwrap();
        assert!(json.contains("80"));
        assert!(json.contains("http"));
        assert!(json.contains("Apache/2.4"));
        assert!(json.contains("true"));
        assert!(json.contains("3"));
    }

    #[test]
    fn report_port_json_roundtrip() {
        let port = ReportPort {
            port: 443,
            service: "https".into(),
            banner: None,
            is_insecure: false,
            cve_count: 0,
        };
        let json = serde_json::to_string(&port).unwrap();
        let decoded: ReportPort = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.port, 443);
        assert_eq!(decoded.service, "https");
        assert_eq!(decoded.banner, None);
        assert!(!decoded.is_insecure);
        assert_eq!(decoded.cve_count, 0);
    }

    // ── ReportHost tests ──

    #[test]
    fn report_host_from_discovered_with_cves() {
        let host = DiscoveredHost {
            ip: "192.168.1.10".parse().unwrap(),
            mac: Some("aa:bb:cc:dd:ee:ff".parse().unwrap()),
            hostname: Some("myhost.local".into()),
            method: crate::scanner::models::DiscoveryMethod::Icmp,
            open_ports: vec![
                make_port(22, ServiceType::Ssh, false, vec![
                    make_cve("CVE-2021-001", Severity::High, Some(7.5)),
                    make_cve("CVE-2021-002", Severity::Medium, Some(5.0)),
                ]),
                make_port(80, ServiceType::Http, true, vec![
                    make_cve("CVE-2021-003", Severity::Critical, Some(9.8)),
                    make_cve("CVE-2021-004", Severity::High, Some(7.0)),
                    make_cve("CVE-2021-005", Severity::Medium, Some(4.3)),
                ]),
            ],
            rtt_ms: Some(5),
            vendor: Some("Apple, Inc.".into()),
        };
        let report = ReportHost::from(&host);
        assert_eq!(report.ip, "192.168.1.10");
        assert_eq!(report.hostname, Some("myhost.local".into()));
        assert_eq!(report.vendor, Some("Apple, Inc.".into()));
        assert_eq!(report.cves.len(), 5);
        assert_eq!(report.total_cves, 5);
        assert_eq!(report.insecure_ports, 1);
        assert_eq!(report.open_ports.len(), 2);
    }

    #[test]
    fn report_host_deduplicates_cves_across_ports() {
        let shared_cve = make_cve("CVE-2021-SHARED", Severity::High, Some(7.5));
        let host = DiscoveredHost {
            ip: "10.0.0.1".parse().unwrap(),
            mac: None,
            hostname: None,
            method: crate::scanner::models::DiscoveryMethod::Tcp,
            open_ports: vec![
                make_port(22, ServiceType::Ssh, false, vec![shared_cve.clone()]),
                make_port(80, ServiceType::Http, true, vec![shared_cve.clone()]),
            ],
            rtt_ms: None,
            vendor: None,
        };
        let report = ReportHost::from(&host);
        // Same CVE on both ports → deduplicated to 1
        assert_eq!(report.cves.len(), 1);
        assert_eq!(report.total_cves, 1);
        assert_eq!(report.cves[0].cve_id, "CVE-2021-SHARED");
    }

    #[test]
    fn report_host_with_no_cves() {
        let host = DiscoveredHost {
            ip: "10.0.0.2".parse().unwrap(),
            mac: None,
            hostname: None,
            method: crate::scanner::models::DiscoveryMethod::Arp,
            open_ports: vec![
                make_port(443, ServiceType::Https, false, vec![]),
            ],
            rtt_ms: None,
            vendor: None,
        };
        let report = ReportHost::from(&host);
        assert!(report.cves.is_empty());
        assert_eq!(report.total_cves, 0);
        assert_eq!(report.insecure_ports, 0);
    }

    #[test]
    fn report_host_mac_formatted_as_hex() {
        let host = DiscoveredHost {
            ip: "10.0.0.3".parse().unwrap(),
            mac: Some("00:11:22:33:44:55".parse().unwrap()),
            hostname: None,
            method: crate::scanner::models::DiscoveryMethod::Merged,
            open_ports: vec![],
            rtt_ms: None,
            vendor: None,
        };
        let report = ReportHost::from(&host);
        assert_eq!(report.mac, Some("00:11:22:33:44:55".into()));
    }

    #[test]
    fn report_host_mac_is_none_when_missing() {
        let host = DiscoveredHost {
            ip: "10.0.0.4".parse().unwrap(),
            mac: None,
            hostname: None,
            method: crate::scanner::models::DiscoveryMethod::Icmp,
            open_ports: vec![],
            rtt_ms: None,
            vendor: None,
        };
        let report = ReportHost::from(&host);
        assert!(report.mac.is_none());
    }

    #[test]
    fn report_host_insecure_ports_counted() {
        let host = DiscoveredHost {
            ip: "10.0.0.5".parse().unwrap(),
            mac: None,
            hostname: None,
            method: crate::scanner::models::DiscoveryMethod::Tcp,
            open_ports: vec![
                make_port(23, ServiceType::Telnet, true, vec![]),
                make_port(21, ServiceType::Ftp, true, vec![]),
                make_port(22, ServiceType::Ssh, false, vec![]),
            ],
            rtt_ms: None,
            vendor: None,
        };
        let report = ReportHost::from(&host);
        assert_eq!(report.insecure_ports, 2);
    }

    #[test]
    fn report_host_serializes_to_json() {
        let host = DiscoveredHost {
            ip: "192.168.1.1".parse().unwrap(),
            mac: None,
            hostname: Some("router".into()),
            method: crate::scanner::models::DiscoveryMethod::Icmp,
            open_ports: vec![
                make_port(80, ServiceType::Http, true, vec![
                    make_cve("CVE-2021-TEST", Severity::High, Some(7.5)),
                ]),
            ],
            rtt_ms: Some(10),
            vendor: None,
        };
        let report = ReportHost::from(&host);
        let json = serde_json::to_string(&report).unwrap();
        assert!(json.contains("192.168.1.1"));
        assert!(json.contains("router"));
        assert!(json.contains("CVE-2021-TEST"));
        assert!(json.contains("total_cves"));
        assert!(json.contains("insecure_ports"));
    }

    // ── ReportContext tests ──

    #[test]
    fn report_context_from_vec_hosts() {
        let hosts = vec![
            DiscoveredHost {
                ip: "192.168.1.10".parse().unwrap(),
                mac: None,
                hostname: None,
                method: crate::scanner::models::DiscoveryMethod::Icmp,
                open_ports: vec![],
                rtt_ms: None,
                vendor: None,
            },
            DiscoveredHost {
                ip: "192.168.1.11".parse().unwrap(),
                mac: None,
                hostname: None,
                method: crate::scanner::models::DiscoveryMethod::Tcp,
                open_ports: vec![],
                rtt_ms: None,
                vendor: None,
            },
        ];
        let ctx = ReportContext::from(&hosts);
        assert_eq!(ctx.host_count, 2);
        assert_eq!(ctx.hosts.len(), 2);
        assert_eq!(ctx.version, "0.1.0");
        assert_eq!(ctx.network, "unknown");
        // generated_at should be a valid RFC3339 timestamp
        assert!(!ctx.generated_at.is_empty());
        assert!(ctx.generated_at.contains("T"));
    }

    #[test]
    fn report_context_empty_hosts() {
        let hosts: Vec<DiscoveredHost> = vec![];
        let ctx = ReportContext::from(&hosts);
        assert_eq!(ctx.host_count, 0);
        assert!(ctx.hosts.is_empty());
    }

    #[test]
    fn report_context_json_roundtrip() {
        let hosts = vec![DiscoveredHost {
            ip: "10.0.0.1".parse().unwrap(),
            mac: None,
            hostname: Some("test".into()),
            method: crate::scanner::models::DiscoveryMethod::Tcp,
            open_ports: vec![],
            rtt_ms: None,
            vendor: None,
        }];
        let ctx = ReportContext::from(&hosts);
        let json = serde_json::to_string(&ctx).unwrap();
        let decoded: ReportContext = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.host_count, 1);
        assert_eq!(decoded.version, "0.1.0");
        assert_eq!(decoded.network, "unknown");
        assert_eq!(decoded.hosts[0].ip, "10.0.0.1");
    }

    #[test]
    fn report_context_json_has_required_fields() {
        let hosts: Vec<DiscoveredHost> = vec![];
        let ctx = ReportContext::from(&hosts);
        let json = serde_json::to_string(&ctx).unwrap();
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(value.get("generated_at").is_some());
        assert!(value.get("version").is_some());
        assert!(value.get("network").is_some());
        assert!(value.get("host_count").is_some());
        assert!(value.get("hosts").is_some());
    }
}
