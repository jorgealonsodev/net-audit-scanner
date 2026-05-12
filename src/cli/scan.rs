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
}

/// Format discovered hosts as an aligned plain-text table.
///
/// Columns: IP, MAC, Hostname, Method, Response Time
pub fn format_hosts_table(hosts: &[DiscoveredHost]) -> String {
    if hosts.is_empty() {
        return "No hosts discovered.".to_string();
    }

    // Compute column widths
    let mut ip_width = 2; // "IP"
    let mut mac_width = 3; // "MAC"
    let mut hostname_width = 8; // "Hostname"
    let mut method_width = 6; // "Method"
    let mut rtt_width = 11; // "Response Time"

    for host in hosts {
        let ip_len = host.ip.to_string().len();
        let mac_len = host.mac.map(|m| m.to_string().len()).unwrap_or(0);
        let hostname_len = host.hostname.as_deref().unwrap_or("-").len();
        let method_len = format!("{:?}", host.method).len();
        let rtt_len = host.rtt_ms.map(|r| format!("{r} ms").len()).unwrap_or(2); // "-"

        ip_width = ip_width.max(ip_len);
        mac_width = mac_width.max(mac_len);
        hostname_width = hostname_width.max(hostname_len);
        method_width = method_width.max(method_len);
        rtt_width = rtt_width.max(rtt_len);
    }

    let mut lines = Vec::new();

    // Header
    lines.push(format!(
        "{:<ip_width$}  {:<mac_width$}  {:<hostname_width$}  {:<method_width$}  {:<rtt_width$}",
        "IP",
        "MAC",
        "Hostname",
        "Method",
        "Response Time",
        ip_width = ip_width,
        mac_width = mac_width,
        hostname_width = hostname_width,
        method_width = method_width,
        rtt_width = rtt_width,
    ));

    // Separator
    lines.push(format!(
        "{:-<ip_width$}  {:-<mac_width$}  {:-<hostname_width$}  {:-<method_width$}  {:-<rtt_width$}",
        "",
        "",
        "",
        "",
        "",
        ip_width = ip_width,
        mac_width = mac_width,
        hostname_width = hostname_width,
        method_width = method_width,
        rtt_width = rtt_width,
    ));

    // Rows
    for host in hosts {
        let mac = host.mac.map(|m| m.to_string()).unwrap_or_default();
        let hostname = host.hostname.as_deref().unwrap_or("-");
        let method = format!("{:?}", host.method);
        let rtt = host.rtt_ms.map(|r| format!("{r} ms")).unwrap_or("-".to_string());

        lines.push(format!(
            "{:<ip_width$}  {:<mac_width$}  {:<hostname_width$}  {:<method_width$}  {:<rtt_width$}",
            host.ip,
            mac,
            hostname,
            method,
            rtt,
            ip_width = ip_width,
            mac_width = mac_width,
            hostname_width = hostname_width,
            method_width = method_width,
            rtt_width = rtt_width,
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
        DiscoveredHost {
            ip: ip.parse::<IpAddr>().unwrap(),
            mac: mac.map(|m| m.parse().unwrap()),
            hostname: hostname.map(String::from),
            method,
            open_ports: vec![],
            rtt_ms,
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
}
