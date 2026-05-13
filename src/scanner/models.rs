//! Data models for network discovery: hosts, methods, and capability detection.

use crate::cve::models::CveMatch;
use crate::security::SecurityFinding;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

/// Detected service type on an open port.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ServiceType {
    Http,
    Https,
    Ssh,
    Telnet,
    Ftp,
    Rtsp,
    Mqtt,
    Upnp,
    Smtp,
    Dns,
    Unknown,
}

/// Network protocol used for port scanning.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Tcp,
}

/// An open port with service detection metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenPort {
    /// Port number (1-65535).
    pub port: u16,
    /// Detected service type.
    pub service: ServiceType,
    /// Banner text grabbed from the service, if available.
    pub banner: Option<String>,
    /// Network protocol used.
    pub protocol: Protocol,
    /// Whether this service is considered insecure.
    pub is_insecure: bool,
    /// CVEs matched to this service, if any.
    #[serde(default)]
    pub cves: Vec<CveMatch>,
}

/// A host discovered during network scanning.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveredHost {
    /// IP address of the discovered host.
    pub ip: IpAddr,
    /// MAC address (from ARP table), if available.
    pub mac: Option<macaddr::MacAddr6>,
    /// Resolved hostname (from reverse DNS), if available.
    pub hostname: Option<String>,
    /// How this host was discovered.
    pub method: DiscoveryMethod,
    /// Open ports detected on this host.
    pub open_ports: Vec<OpenPort>,
    /// Round-trip time in milliseconds, if measured.
    pub rtt_ms: Option<u128>,
    /// Vendor name from OUI/MAC fingerprinting, if available.
    pub vendor: Option<String>,
    /// OS hint inferred from TTL or service banners, if available.
    #[serde(default)]
    pub os_hint: Option<String>,
    /// Security findings from credential and protocol checks.
    #[serde(default)]
    pub security_findings: Vec<SecurityFinding>,
}

/// The method by which a host was discovered.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DiscoveryMethod {
    /// Discovered via ICMP echo reply.
    Icmp,
    /// Discovered via TCP connect probe.
    Tcp,
    /// Discovered via ARP table entry.
    Arp,
    /// Merged from multiple discovery methods.
    Merged,
}

/// An entry from the ARP table (IP → MAC mapping).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArpEntry {
    /// IP address.
    pub ip: IpAddr,
    /// MAC address.
    pub mac: macaddr::MacAddr6,
}

/// Result of a ping probe against a single IP.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PingResult {
    /// Target IP address.
    pub ip: IpAddr,
    /// Whether the host responded.
    pub alive: bool,
    /// Round-trip time in milliseconds, if alive.
    pub rtt_ms: Option<u128>,
    /// OS hint derived from TTL in ICMP reply, if available.
    #[serde(default)]
    pub ttl_hint: Option<String>,
}

/// Detected platform capabilities for network scanning.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Capabilities {
    /// Whether the process runs as root (UID 0).
    pub is_root: bool,
    /// Whether ICMP raw sockets can be used.
    pub can_icmp: bool,
    /// Whether raw sockets are available.
    pub can_raw_sockets: bool,
    /// Whether ARP table is readable.
    pub can_arp_table: bool,
}

/// CLI arguments captured at scan time, persisted with scan results.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanCliArgs {
    /// Port range specification (e.g., "top-1000", "full", "80-443").
    pub port_range: String,
    /// Whether a full port scan was requested.
    pub full: bool,
    /// Whether CVE lookup was skipped.
    pub no_cve: bool,
}

/// A complete scan record persisted to disk after CVE enrichment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanRecord {
    /// Unique identifier for this scan (UUID v4).
    pub id: String,
    /// ISO 8601 UTC timestamp when scanning started.
    pub started_at: String,
    /// ISO 8601 UTC timestamp when scanning completed.
    pub completed_at: String,
    /// CIDR network string from CLI args.
    pub network: String,
    /// CLI arguments used for this scan.
    pub cli_args: ScanCliArgs,
    /// Number of hosts discovered.
    pub host_count: usize,
    /// Total CVEs across all hosts.
    pub total_cves: usize,
    /// Discovered hosts with enriched data.
    pub hosts: Vec<DiscoveredHost>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discovered_host_serializes_to_json() {
        let host = DiscoveredHost {
            ip: "192.168.1.10".parse().unwrap(),
            mac: Some("aa:bb:cc:dd:ee:ff".parse().unwrap()),
            hostname: Some("myhost.local".into()),
            method: DiscoveryMethod::Icmp,
            open_ports: vec![
                OpenPort {
                    port: 22,
                    service: ServiceType::Ssh,
                    banner: None,
                    protocol: Protocol::Tcp,
                    is_insecure: false,
                    cves: vec![],
                },
                OpenPort {
                    port: 80,
                    service: ServiceType::Http,
                    banner: None,
                    protocol: Protocol::Tcp,
                    is_insecure: true,
                    cves: vec![],
                },
            ],
            rtt_ms: Some(5),
            vendor: None,
            os_hint: None,
            security_findings: vec![],
        };
        let json = serde_json::to_string(&host).unwrap();
        assert!(json.contains("192.168.1.10"));
        // macaddr serializes as byte array
        assert!(json.contains("170"));
        assert!(json.contains("myhost.local"));
        assert!(json.contains("icmp"));
        assert!(json.contains("22"));
        assert!(json.contains("80"));
    }

    #[test]
    fn discovered_host_deserializes_from_json() {
        let json = r#"{
            "ip": "10.0.0.1",
            "mac": null,
            "hostname": null,
            "method": "tcp",
            "open_ports": [{"port": 443, "service": "https", "banner": null, "protocol": "tcp", "is_insecure": false}],
            "rtt_ms": null
        }"#;
        let host: DiscoveredHost = serde_json::from_str(json).unwrap();
        assert_eq!(host.ip.to_string(), "10.0.0.1");
        assert!(host.mac.is_none());
        assert!(host.hostname.is_none());
        assert!(matches!(host.method, DiscoveryMethod::Tcp));
        assert_eq!(host.open_ports.len(), 1);
        assert_eq!(host.open_ports[0].port, 443);
    }

    #[test]
    fn discovery_method_variants_serialize_correctly() {
        assert_eq!(serde_json::to_string(&DiscoveryMethod::Icmp).unwrap(), r#""icmp""#);
        assert_eq!(serde_json::to_string(&DiscoveryMethod::Tcp).unwrap(), r#""tcp""#);
        assert_eq!(serde_json::to_string(&DiscoveryMethod::Arp).unwrap(), r#""arp""#);
        assert_eq!(serde_json::to_string(&DiscoveryMethod::Merged).unwrap(), r#""merged""#);
    }

    #[test]
    fn arp_entry_serializes() {
        let entry = ArpEntry {
            ip: "192.168.1.1".parse().unwrap(),
            mac: "aa:bb:cc:dd:ee:01".parse().unwrap(),
        };
        let json = serde_json::to_string(&entry).unwrap();
        assert!(json.contains("192.168.1.1"));
        // macaddr serializes as byte array: [170,187,204,221,238,1]
        assert!(json.contains("170"));
        assert!(json.contains("187"));
    }

    #[test]
    fn ping_result_serializes() {
        let result = PingResult {
            ip: "10.0.0.5".parse().unwrap(),
            alive: true,
            rtt_ms: Some(12),
            ttl_hint: None,
        };
        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("10.0.0.5"));
        assert!(json.contains("true"));
        assert!(json.contains("12"));
    }

    #[test]
    fn capabilities_serializes() {
        let caps = Capabilities {
            is_root: true,
            can_icmp: true,
            can_raw_sockets: true,
            can_arp_table: true,
        };
        let json = serde_json::to_string(&caps).unwrap();
        assert!(json.contains("is_root"));
        assert!(json.contains("can_icmp"));
    }

    #[test]
    fn discovered_host_debug_output() {
        let host = DiscoveredHost {
            ip: "127.0.0.1".parse().unwrap(),
            mac: None,
            hostname: None,
            method: DiscoveryMethod::Tcp,
            open_ports: vec![],
            rtt_ms: None,
            vendor: None,
            os_hint: None,
            security_findings: vec![],
        };
        let debug = format!("{:?}", host);
        assert!(debug.contains("127.0.0.1"));
        assert!(debug.contains("Tcp"));
    }

    #[test]
    fn discovered_host_clone() {
        let host = DiscoveredHost {
            ip: "1.2.3.4".parse().unwrap(),
            mac: Some("00:11:22:33:44:55".parse().unwrap()),
            hostname: Some("test".into()),
            method: DiscoveryMethod::Arp,
            open_ports: vec![OpenPort {
                port: 80,
                service: ServiceType::Http,
                banner: None,
                protocol: Protocol::Tcp,
                is_insecure: true,
                cves: vec![],
            }],
            rtt_ms: Some(3),
            vendor: None,
            os_hint: None,
            security_findings: vec![],
        };
        let cloned = host.clone();
        assert_eq!(host.ip, cloned.ip);
        assert_eq!(host.mac, cloned.mac);
    }

    #[test]
    fn service_type_variants() {
        assert_eq!(serde_json::to_string(&ServiceType::Http).unwrap(), r#""http""#);
        assert_eq!(serde_json::to_string(&ServiceType::Https).unwrap(), r#""https""#);
        assert_eq!(serde_json::to_string(&ServiceType::Ssh).unwrap(), r#""ssh""#);
        assert_eq!(serde_json::to_string(&ServiceType::Telnet).unwrap(), r#""telnet""#);
        assert_eq!(serde_json::to_string(&ServiceType::Ftp).unwrap(), r#""ftp""#);
        assert_eq!(serde_json::to_string(&ServiceType::Unknown).unwrap(), r#""unknown""#);
    }

    #[test]
    fn discovered_host_vendor_serializes() {
        let host = DiscoveredHost {
            ip: "192.168.1.1".parse().unwrap(),
            mac: None,
            hostname: None,
            method: DiscoveryMethod::Icmp,
            open_ports: vec![],
            rtt_ms: None,
            vendor: Some("Apple, Inc.".into()),
            os_hint: None,
            security_findings: vec![],
        };
        let json = serde_json::to_string(&host).unwrap();
        assert!(json.contains("Apple, Inc."));
    }

    #[test]
    fn discovered_host_vendor_deserializes() {
        let json = r#"{"ip":"10.0.0.1","mac":null,"hostname":null,"method":"tcp","open_ports":[],"rtt_ms":null,"vendor":"Cisco Systems"}"#;
        let host: DiscoveredHost = serde_json::from_str(json).unwrap();
        assert_eq!(host.vendor, Some("Cisco Systems".into()));
    }

    #[test]
    fn protocol_tcp_serializes() {
        assert_eq!(serde_json::to_string(&Protocol::Tcp).unwrap(), r#""tcp""#);
    }

    #[test]
    fn open_port_with_cves_serializes() {
        use crate::cve::models::{CveMatch, Severity};
        let port = OpenPort {
            port: 22,
            service: ServiceType::Ssh,
            banner: Some("SSH-2.0-OpenSSH_8.9".into()),
            protocol: Protocol::Tcp,
            is_insecure: false,
            cves: vec![CveMatch {
                cve_id: "CVE-2021-1234".into(),
                description: "Test".into(),
                severity: Severity::High,
                score: Some(7.5),
                published: "2021-01-01".into(),
            }],
        };
        let json = serde_json::to_string(&port).unwrap();
        assert!(json.contains("CVE-2021-1234"));
        assert!(json.contains("cves"));
    }

    #[test]
    fn open_port_deserializes_with_empty_cves() {
        let json =
            r#"{"port": 80, "service": "http", "banner": null, "protocol": "tcp", "is_insecure": true, "cves": []}"#;
        let port: OpenPort = serde_json::from_str(json).unwrap();
        assert!(port.cves.is_empty());
    }

    #[test]
    fn open_port_serializes() {
        let port = OpenPort {
            port: 22,
            service: ServiceType::Ssh,
            banner: Some("SSH-2.0-OpenSSH_8.9".into()),
            protocol: Protocol::Tcp,
            is_insecure: false,
            cves: vec![],
        };
        let json = serde_json::to_string(&port).unwrap();
        assert!(json.contains("22"));
        assert!(json.contains("ssh"));
        assert!(json.contains("SSH-2.0"));
        assert!(json.contains("false"));
    }

    #[test]
    fn open_port_deserializes() {
        let json = r#"{"port": 80, "service": "http", "banner": null, "protocol": "tcp", "is_insecure": true}"#;
        let port: OpenPort = serde_json::from_str(json).unwrap();
        assert_eq!(port.port, 80);
        assert_eq!(port.service, ServiceType::Http);
        assert!(port.banner.is_none());
        assert!(port.is_insecure);
    }

    // ─── os_hint field tests (device-fingerprint) ───

    #[test]
    fn discovered_host_os_hint_none_serializes_as_null() {
        let host = DiscoveredHost {
            ip: "192.168.1.1".parse().unwrap(),
            mac: None,
            hostname: None,
            method: DiscoveryMethod::Icmp,
            open_ports: vec![],
            rtt_ms: None,
            vendor: None,
            os_hint: None,
            security_findings: vec![],
        };
        let json = serde_json::to_string(&host).unwrap();
        assert!(json.contains("\"os_hint\":null"));
    }

    #[test]
    fn discovered_host_os_hint_some_serializes_value() {
        let host = DiscoveredHost {
            ip: "192.168.1.1".parse().unwrap(),
            mac: None,
            hostname: None,
            method: DiscoveryMethod::Icmp,
            open_ports: vec![],
            rtt_ms: None,
            vendor: None,
            os_hint: Some("Linux".into()),
            security_findings: vec![],
        };
        let json = serde_json::to_string(&host).unwrap();
        assert!(json.contains("\"os_hint\":\"Linux\""));
    }

    #[test]
    fn discovered_host_os_hint_deserializes_from_json() {
        let json = r#"{"ip":"10.0.0.1","mac":null,"hostname":null,"method":"tcp","open_ports":[],"rtt_ms":null,"os_hint":"Windows"}"#;
        let host: DiscoveredHost = serde_json::from_str(json).unwrap();
        assert_eq!(host.os_hint, Some("Windows".into()));
    }

    #[test]
    fn discovered_host_os_hint_deserializes_null() {
        let json = r#"{"ip":"10.0.0.1","mac":null,"hostname":null,"method":"tcp","open_ports":[],"rtt_ms":null,"os_hint":null}"#;
        let host: DiscoveredHost = serde_json::from_str(json).unwrap();
        assert!(host.os_hint.is_none());
    }

    #[test]
    fn discovered_host_os_hint_backward_compat_missing_field() {
        // JSON without os_hint field should still deserialize (serde default)
        let json = r#"{"ip":"10.0.0.1","mac":null,"hostname":null,"method":"tcp","open_ports":[],"rtt_ms":null}"#;
        let host: DiscoveredHost = serde_json::from_str(json).unwrap();
        assert!(host.os_hint.is_none());
    }

    // ─── ScanCliArgs and ScanRecord tests (scan-persistence) ───

    #[test]
    fn scan_cli_args_serializes() {
        let args = ScanCliArgs {
            port_range: "top-1000".into(),
            full: false,
            no_cve: true,
        };
        let json = serde_json::to_string(&args).unwrap();
        assert!(json.contains("top-1000"));
        assert!(json.contains("false"));
        assert!(json.contains("true"));
    }

    #[test]
    fn scan_cli_args_deserializes() {
        let json = r#"{"port_range":"full","full":true,"no_cve":false}"#;
        let args: ScanCliArgs = serde_json::from_str(json).unwrap();
        assert_eq!(args.port_range, "full");
        assert!(args.full);
        assert!(!args.no_cve);
    }

    #[test]
    fn scan_record_serializes() {
        let record = ScanRecord {
            id: "test-uuid-1234".into(),
            started_at: "2026-05-13T10:30:00Z".into(),
            completed_at: "2026-05-13T10:35:00Z".into(),
            network: "192.168.1.0/24".into(),
            cli_args: ScanCliArgs {
                port_range: "top-1000".into(),
                full: false,
                no_cve: true,
            },
            host_count: 1,
            total_cves: 0,
            hosts: vec![DiscoveredHost {
                ip: "192.168.1.1".parse().unwrap(),
                mac: None,
                hostname: None,
                method: DiscoveryMethod::Icmp,
                open_ports: vec![],
                rtt_ms: None,
                vendor: None,
                os_hint: None,
                security_findings: vec![],
            }],
        };
        let json = serde_json::to_string(&record).unwrap();
        assert!(json.contains("test-uuid-1234"));
        assert!(json.contains("192.168.1.0/24"));
        assert!(json.contains("top-1000"));
        assert!(json.contains("host_count"));
        assert!(json.contains("total_cves"));
    }

    #[test]
    fn scan_record_deserializes() {
        let json = r#"{
            "id": "test-uuid-5678",
            "started_at": "2026-05-13T10:30:00Z",
            "completed_at": "2026-05-13T10:35:00Z",
            "network": "10.0.0.0/8",
            "cli_args": {"port_range": "full", "full": true, "no_cve": false},
            "host_count": 0,
            "total_cves": 0,
            "hosts": []
        }"#;
        let record: ScanRecord = serde_json::from_str(json).unwrap();
        assert_eq!(record.id, "test-uuid-5678");
        assert_eq!(record.network, "10.0.0.0/8");
        assert!(record.cli_args.full);
        assert_eq!(record.host_count, 0);
        assert!(record.hosts.is_empty());
    }

    #[test]
    fn scan_record_roundtrip() {
        let original = ScanRecord {
            id: "roundtrip-uuid".into(),
            started_at: "2026-05-13T12:00:00Z".into(),
            completed_at: "2026-05-13T12:05:00Z".into(),
            network: "172.16.0.0/16".into(),
            cli_args: ScanCliArgs {
                port_range: "80-443".into(),
                full: false,
                no_cve: false,
            },
            host_count: 2,
            total_cves: 3,
            hosts: vec![
                DiscoveredHost {
                    ip: "172.16.0.1".parse().unwrap(),
                    mac: Some("aa:bb:cc:dd:ee:01".parse().unwrap()),
                    hostname: Some("gw.local".into()),
                    method: DiscoveryMethod::Icmp,
                    open_ports: vec![],
                    rtt_ms: Some(2),
                    vendor: None,
                    os_hint: None,
                    security_findings: vec![],
                },
                DiscoveredHost {
                    ip: "172.16.0.2".parse().unwrap(),
                    mac: None,
                    hostname: None,
                    method: DiscoveryMethod::Tcp,
                    open_ports: vec![],
                    rtt_ms: None,
                    vendor: Some("Unknown".into()),
                    os_hint: Some("Linux".into()),
                    security_findings: vec![],
                },
            ],
        };
        let json = serde_json::to_string(&original).unwrap();
        let restored: ScanRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(original.id, restored.id);
        assert_eq!(original.network, restored.network);
        assert_eq!(original.host_count, restored.host_count);
        assert_eq!(original.total_cves, restored.total_cves);
        assert_eq!(original.hosts.len(), restored.hosts.len());
        assert_eq!(original.hosts[0].ip, restored.hosts[0].ip);
        assert_eq!(original.hosts[1].os_hint, restored.hosts[1].os_hint);
    }

    #[test]
    fn scan_record_empty_hosts_serializes() {
        let record = ScanRecord {
            id: "empty-scan".into(),
            started_at: "2026-05-13T10:00:00Z".into(),
            completed_at: "2026-05-13T10:00:01Z".into(),
            network: "192.168.99.0/24".into(),
            cli_args: ScanCliArgs {
                port_range: "top-1000".into(),
                full: false,
                no_cve: true,
            },
            host_count: 0,
            total_cves: 0,
            hosts: vec![],
        };
        let json = serde_json::to_string(&record).unwrap();
        let restored: ScanRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.host_count, 0);
        assert!(restored.hosts.is_empty());
    }
}
