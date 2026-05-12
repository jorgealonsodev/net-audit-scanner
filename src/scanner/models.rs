//! Data models for network discovery: hosts, methods, and capability detection.

use serde::{Deserialize, Serialize};
use std::net::IpAddr;

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
    pub open_ports: Vec<u16>,
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
            open_ports: vec![22, 80],
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
            "open_ports": [443]
        }"#;
        let host: DiscoveredHost = serde_json::from_str(json).unwrap();
        assert_eq!(host.ip.to_string(), "10.0.0.1");
        assert!(host.mac.is_none());
        assert!(host.hostname.is_none());
        assert!(matches!(host.method, DiscoveryMethod::Tcp));
        assert_eq!(host.open_ports, vec![443]);
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
            open_ports: vec![80],
        };
        let cloned = host.clone();
        assert_eq!(host.ip, cloned.ip);
        assert_eq!(host.mac, cloned.mac);
    }
}
