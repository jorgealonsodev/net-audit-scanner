use clap::Args;

use crate::scanner::models::DiscoveredHost;

/// Arguments for the `scan` subcommand.
#[derive(Args)]
pub struct ScanArgs {
    /// Network range to scan (CIDR notation or "auto")
    #[arg(short, long, default_value = "auto")]
    pub network: String,

    /// Specific target IP to scan in depth
    #[arg(long)]
    pub target: Option<String>,

    /// Number of concurrent probes
    #[arg(long, default_value_t = 512)]
    pub concurrency: usize,

    /// Timeout per probe in milliseconds
    #[arg(long, default_value_t = 1500)]
    pub timeout_ms: u64,

    /// Banner grab timeout in milliseconds
    #[arg(long, default_value_t = 500)]
    pub banner_timeout_ms: u64,

    /// Output results as JSON instead of a table
    #[arg(long)]
    pub json: bool,

    /// Skip CVE lookup for faster results
    #[arg(long)]
    pub no_cve: bool,

    /// Full port scan (1-65535) instead of top-1000
    #[arg(long)]
    pub full: bool,

    /// Port list to scan: top-100, top-1000, full, or custom range (e.g. 80-443)
    #[arg(long)]
    pub port_range: Option<String>,

    /// Output report format (html, json)
    #[arg(short, long, default_value = "html")]
    pub report: String,

    /// Skip cache and use embedded OUI database
    #[arg(long)]
    pub no_update: bool,

    /// Skip MacVendors API lookup (enabled by default, no key needed for ≤1000 req/day)
    #[arg(long)]
    pub no_mac_api: bool,
}

/// Format discovered hosts as an aligned plain-text table.
///
/// Columns: IP, MAC, Vendor, Hostname, Method, Response Time, CVEs
pub fn format_hosts_table(hosts: &[DiscoveredHost]) -> String {
    if hosts.is_empty() {
        return "No hosts discovered.".to_string();
    }

    // Compute column widths
    let mut ip_width = 2; // "IP"
    let mut mac_width = 3; // "MAC"
    let mut vendor_width = 6; // "Vendor"
    let mut hostname_width = 8; // "Hostname"
    let mut method_width = 6; // "Method"
    let mut rtt_width = 11; // "Response Time"
    let mut cve_width = 4; // "CVEs"

    for host in hosts {
        let ip_len = host.ip.to_string().len();
        let mac_len = host.mac.map(|m| m.to_string().len()).unwrap_or(0);
        let vendor_len = host.vendor.as_deref().unwrap_or("-").len();
        let hostname_len = host.hostname.as_deref().unwrap_or("-").len();
        let method_len = format!("{:?}", host.method).len();
        let rtt_len = host.rtt_ms.map(|r| format!("{r} ms").len()).unwrap_or(2); // "-"
        let cve_count: usize = host.open_ports.iter().map(|p| p.cves.len()).sum();
        let cve_len = if cve_count > 0 {
            format!("{cve_count} CVEs").len()
        } else {
            1 // "-"
        };

        ip_width = ip_width.max(ip_len);
        mac_width = mac_width.max(mac_len);
        vendor_width = vendor_width.max(vendor_len);
        hostname_width = hostname_width.max(hostname_len);
        method_width = method_width.max(method_len);
        rtt_width = rtt_width.max(rtt_len);
        cve_width = cve_width.max(cve_len);
    }

    let mut lines = Vec::new();

    // Header
    lines.push(format!(
        "{:<ip_width$}  {:<mac_width$}  {:<vendor_width$}  {:<hostname_width$}  {:<method_width$}  {:<rtt_width$}  {:<cve_width$}",
        "IP",
        "MAC",
        "Vendor",
        "Hostname",
        "Method",
        "Response Time",
        "CVEs",
        ip_width = ip_width,
        mac_width = mac_width,
        vendor_width = vendor_width,
        hostname_width = hostname_width,
        method_width = method_width,
        rtt_width = rtt_width,
        cve_width = cve_width,
    ));

    // Separator
    lines.push(format!(
        "{:-<ip_width$}  {:-<mac_width$}  {:-<vendor_width$}  {:-<hostname_width$}  {:-<method_width$}  {:-<rtt_width$}  {:-<cve_width$}",
        "",
        "",
        "",
        "",
        "",
        "",
        "",
        ip_width = ip_width,
        mac_width = mac_width,
        vendor_width = vendor_width,
        hostname_width = hostname_width,
        method_width = method_width,
        rtt_width = rtt_width,
        cve_width = cve_width,
    ));

    // Rows
    for host in hosts {
        let mac = host.mac.map(|m| m.to_string()).unwrap_or_default();
        let vendor = host.vendor.as_deref().unwrap_or("-");
        let hostname = host.hostname.as_deref().unwrap_or("-");
        let method = format!("{:?}", host.method);
        let rtt = host.rtt_ms.map(|r| format!("{r} ms")).unwrap_or("-".to_string());
        let cve_count: usize = host.open_ports.iter().map(|p| p.cves.len()).sum();
        let cves = if cve_count > 0 {
            format!("{cve_count} CVEs")
        } else {
            "-".to_string()
        };

        lines.push(format!(
            "{:<ip_width$}  {:<mac_width$}  {:<vendor_width$}  {:<hostname_width$}  {:<method_width$}  {:<rtt_width$}  {:<cve_width$}",
            host.ip,
            mac,
            vendor,
            hostname,
            method,
            rtt,
            cves,
            ip_width = ip_width,
            mac_width = mac_width,
            vendor_width = vendor_width,
            hostname_width = hostname_width,
            method_width = method_width,
            rtt_width = rtt_width,
            cve_width = cve_width,
        ));
    }

    lines.join("\n")
}

/// Format discovered hosts as a JSON array string.
pub fn format_hosts_json(hosts: &[DiscoveredHost]) -> String {
    serde_json::to_string_pretty(hosts).unwrap_or_else(|_| "[]".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanner::models::DiscoveryMethod;
    use std::net::IpAddr;

    fn make_host(
        ip: &str,
        mac: Option<&str>,
        hostname: Option<&str>,
        method: DiscoveryMethod,
        rtt_ms: Option<u128>,
    ) -> DiscoveredHost {
        make_host_with_vendor(ip, mac, hostname, method, rtt_ms, None)
    }

    fn make_host_with_vendor(
        ip: &str,
        mac: Option<&str>,
        hostname: Option<&str>,
        method: DiscoveryMethod,
        rtt_ms: Option<u128>,
        vendor: Option<&str>,
    ) -> DiscoveredHost {
        DiscoveredHost {
            ip: ip.parse::<IpAddr>().unwrap(),
            mac: mac.map(|m| m.parse().unwrap()),
            hostname: hostname.map(String::from),
            method,
            open_ports: vec![],
            rtt_ms,
            vendor: vendor.map(String::from),
            device_model: None,
            os_hint: None,
            security_findings: vec![],
        }
    }

    #[test]
    fn format_hosts_table_empty_returns_message() {
        let output = format_hosts_table(&[]);
        assert_eq!(output, "No hosts discovered.");
    }

    #[test]
    fn format_hosts_table_single_host() {
        let hosts = vec![make_host(
            "192.168.1.1",
            Some("aa:bb:cc:dd:ee:01"),
            Some("router.local"),
            DiscoveryMethod::Icmp,
            Some(5),
        )];
        let output = format_hosts_table(&hosts);
        assert!(output.contains("192.168.1.1"));
        assert!(output.contains("AA:BB:CC:DD:EE:01"));
        assert!(output.contains("router.local"));
        assert!(output.contains("Icmp"));
        assert!(output.contains("5 ms"));
        assert!(output.contains("IP"));
        assert!(output.contains("MAC"));
        assert!(output.contains("Hostname"));
        assert!(output.contains("Method"));
        assert!(output.contains("Response Time"));
    }

    #[test]
    fn format_hosts_table_multiple_hosts_sorted() {
        let hosts = vec![
            make_host("192.168.1.20", None, None, DiscoveryMethod::Tcp, None),
            make_host(
                "192.168.1.10",
                Some("aa:bb:cc:dd:ee:10"),
                None,
                DiscoveryMethod::Icmp,
                Some(12),
            ),
        ];
        let output = format_hosts_table(&hosts);
        // Both hosts should appear
        assert!(output.contains("192.168.1.10"));
        assert!(output.contains("192.168.1.20"));
        // MAC should appear for .10 but not .20
        assert!(output.contains("AA:BB:CC:DD:EE:10"));
        // Method labels
        assert!(output.contains("Icmp"));
        assert!(output.contains("Tcp"));
    }

    #[test]
    fn format_hosts_table_missing_fields_show_dash() {
        let hosts = vec![make_host("10.0.0.1", None, None, DiscoveryMethod::Tcp, None)];
        let output = format_hosts_table(&hosts);
        // Missing MAC and hostname should show as empty or dash
        assert!(output.contains("10.0.0.1"));
        assert!(output.contains("Tcp"));
    }

    #[test]
    fn format_hosts_json_serializes_hosts() {
        let hosts = vec![make_host("192.168.1.1", None, None, DiscoveryMethod::Icmp, Some(5))];
        let output = format_hosts_json(&hosts);
        assert!(output.contains("192.168.1.1"));
        assert!(output.contains("icmp"));
    }

    #[test]
    fn format_hosts_json_empty_array() {
        let output = format_hosts_json(&[]);
        assert_eq!(output.trim(), "[]");
    }

    #[test]
    fn format_hosts_table_includes_vendor_column() {
        let hosts = vec![make_host_with_vendor(
            "192.168.1.1",
            Some("00:00:0C:11:22:33"),
            Some("router.local"),
            DiscoveryMethod::Icmp,
            Some(5),
            Some("Cisco Systems, Inc."),
        )];
        let output = format_hosts_table(&hosts);
        assert!(output.contains("Vendor"), "Header should contain 'Vendor'");
        assert!(output.contains("Cisco Systems, Inc."), "Row should contain vendor name");
    }

    #[test]
    fn format_hosts_table_missing_vendor_shows_dash() {
        let hosts = vec![make_host("192.168.1.2", None, None, DiscoveryMethod::Tcp, None)];
        let output = format_hosts_table(&hosts);
        assert!(output.contains("Vendor"), "Header should contain 'Vendor'");
        assert!(output.contains("192.168.1.2"), "Row should contain IP");
    }

    #[test]
    fn format_hosts_table_includes_cve_column() {
        let hosts = vec![make_host("192.168.1.1", None, None, DiscoveryMethod::Icmp, Some(5))];
        let output = format_hosts_table(&hosts);
        assert!(output.contains("CVEs"), "Header should contain 'CVEs'");
    }

    #[test]
    fn format_hosts_table_shows_cve_count() {
        use crate::cve::models::{CveMatch, Severity};
        use crate::scanner::models::{OpenPort, Protocol, ServiceType};

        let hosts = vec![DiscoveredHost {
            ip: "192.168.1.1".parse().unwrap(),
            mac: None,
            hostname: None,
            method: DiscoveryMethod::Tcp,
            open_ports: vec![OpenPort {
                port: 22,
                service: ServiceType::Ssh,
                banner: Some("SSH-2.0-OpenSSH_8.9".into()),
                protocol: Protocol::Tcp,
                is_insecure: false,
                cves: vec![
                    CveMatch {
                        cve_id: "CVE-2021-41617".into(),
                        description: "sshd privilege escalation".into(),
                        severity: Severity::High,
                        score: Some(7.8),
                        published: "2021-09-20".into(),
                    },
                    CveMatch {
                        cve_id: "CVE-2023-9999".into(),
                        description: "Another SSH bug".into(),
                        severity: Severity::Medium,
                        score: Some(5.0),
                        published: "2023-01-01".into(),
                    },
                ],
            }],
            rtt_ms: None,
            vendor: None,
            device_model: None,
            os_hint: None,
            security_findings: vec![],
        }];

        let output = format_hosts_table(&hosts);
        assert!(output.contains("2 CVEs"), "Row should show CVE count");
    }

    #[test]
    fn format_hosts_table_shows_dash_when_no_cves() {
        let hosts = vec![make_host("192.168.1.1", None, None, DiscoveryMethod::Tcp, None)];
        let output = format_hosts_table(&hosts);
        assert!(output.contains("CVEs"), "Header should contain 'CVEs'");
        // With no open ports (or empty cves), should show "-" in the CVE column
        assert!(output.contains("192.168.1.1"), "Row should contain IP");
    }

    #[test]
    fn format_hosts_json_includes_cves() {
        use crate::cve::models::{CveMatch, Severity};
        use crate::scanner::models::{OpenPort, Protocol, ServiceType};

        let hosts = vec![DiscoveredHost {
            ip: "192.168.1.1".parse().unwrap(),
            mac: None,
            hostname: None,
            method: DiscoveryMethod::Tcp,
            open_ports: vec![OpenPort {
                port: 22,
                service: ServiceType::Ssh,
                banner: Some("SSH-2.0-OpenSSH_8.9".into()),
                protocol: Protocol::Tcp,
                is_insecure: false,
                cves: vec![CveMatch {
                    cve_id: "CVE-2021-41617".into(),
                    description: "sshd privilege escalation".into(),
                    severity: Severity::High,
                    score: Some(7.8),
                    published: "2021-09-20".into(),
                }],
            }],
            rtt_ms: None,
            vendor: None,
            device_model: None,
            os_hint: None,
            security_findings: vec![],
        }];

        let output = format_hosts_json(&hosts);
        assert!(output.contains("CVE-2021-41617"), "JSON should include CVE ID");
        assert!(output.contains("cves"), "JSON should include cves field");
        assert!(
            output.contains("sshd privilege escalation"),
            "JSON should include CVE description"
        );
    }
}
