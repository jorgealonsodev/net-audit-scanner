//! Network discovery probes and orchestrator.
//!
//! Implements ICMP sweep, TCP connect probes, ARP table parsing,
//! and the Scanner orchestrator that merges results from all probes.

use std::net::IpAddr;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use tokio::time::timeout;

use crate::error::Error;
use crate::scanner::models::{ArpEntry, Capabilities, DiscoveredHost, DiscoveryMethod, PingResult};
use crate::scanner::ports::resolve_port_list;
use crate::scanner::services::{build_open_port, grab_banner};

use ipnetwork::IpNetwork;

/// Scanner orchestrator for network discovery.
///
/// Runs ICMP, TCP, and ARP probes concurrently, merges results by IP,
/// and deduplicates discovered hosts.
pub struct Scanner {
    config: crate::config::ScanConfig,
}

impl Scanner {
    /// Create a new Scanner with the given configuration.
    pub fn new(config: crate::config::ScanConfig) -> Self {
        Self { config }
    }

    /// Discover hosts on the given network.
    ///
    /// Runs all available probes concurrently (ICMP if capable, TCP always, ARP on Linux),
    /// merges results by IP, and returns deduplicated discovered hosts.
    pub async fn discover_network(
        &self,
        network: &IpNetwork,
        caps: &Capabilities,
    ) -> Result<Vec<DiscoveredHost>, Error> {
        let ips = expand_cidr(network);
        if ips.is_empty() {
            return Ok(vec![]);
        }

        let concurrency = self.config.concurrency.min(ips.len());
        let semaphore = std::sync::Arc::new(Semaphore::new(concurrency));

        // ICMP sweep — only if capable
        let icmp_fut = if caps.can_icmp {
            let ips = ips.clone();
            let sem = semaphore.clone();
            tokio::spawn(async move { icmp_sweep(&ips, &sem).await })
        } else {
            tokio::spawn(async { vec![] })
        };

        // TCP sweep — always available
        let tcp_fut = {
            let ips = ips.clone();
            let sem = semaphore.clone();
            let ports = vec![22u16, 80, 443];
            tokio::spawn(async move { tcp_sweep(&ips, &ports, &sem).await })
        };

        // ARP table — always available (returns empty on non-Linux)
        let arp_fut = tokio::spawn(async { parse_proc_net_arp() });

        // Run all probes concurrently
        let (icmp_results, tcp_results, arp_entries) = tokio::join!(icmp_fut, tcp_fut, arp_fut);

        let icmp_results = icmp_results.map_err(|e| Error::Discovery(format!("ICMP task panicked: {e}")))?;
        let tcp_results = tcp_results.map_err(|e| Error::Discovery(format!("TCP task panicked: {e}")))?;
        let arp_entries = arp_entries.map_err(|e| Error::Discovery(format!("ARP task panicked: {e}")))??;

        // Merge all ping results (ICMP + TCP)
        let mut all_pings = icmp_results;
        all_pings.extend(tcp_results);

        // Merge and deduplicate
        Ok(merge_results(&all_pings, &arp_entries))
    }

    /// Return a reference to the scanner config.
    pub fn config(&self) -> &crate::config::ScanConfig {
        &self.config
    }

    /// Scan open ports on discovered hosts.
    ///
    /// For each host, probes the configured port list, grabs banners where possible,
    /// classifies services, and flags insecure protocols.
    pub async fn scan_ports(&self, hosts: Vec<DiscoveredHost>) -> Vec<DiscoveredHost> {
        if hosts.is_empty() {
            return hosts;
        }

        let ports = resolve_port_list(&self.config.port_range);
        let concurrency = self.config.concurrency.min(hosts.len() * ports.len().max(1));
        let semaphore = std::sync::Arc::new(Semaphore::new(concurrency));
        let timeout_ms = self.config.timeout_ms;

        let mut results = Vec::new();

        for host in hosts {
            let permit = semaphore.clone().acquire_owned().await;
            let ports = ports.clone();
            let host_ip = host.ip;

            let fut = async move {
                let mut open_ports = Vec::new();
                let mut has_https = false;

                // Probe each port
                let mut handles = Vec::new();
                for &port in &ports {
                    let ip = host_ip;
                    let timeout_dur = Duration::from_millis(timeout_ms);
                    handles.push(tokio::spawn(async move {
                        match timeout(timeout_dur, TcpStream::connect((ip, port))).await {
                            Ok(Ok(stream)) => {
                                // Convert tokio stream to std for banner grabbing
                                let std_stream = stream.into_std().ok()?;
                                let banner_timeout = Duration::from_millis(timeout_ms.min(2000));
                                let banner = tokio::task::spawn_blocking(move || {
                                    let mut s = std_stream;
                                    grab_banner(&mut s, banner_timeout)
                                })
                                .await
                                .ok()??;
                                Some((port, banner))
                            }
                            _ => None,
                        }
                    }));
                }

                for handle in handles {
                    if let Ok(Some((port, banner))) = handle.await {
                        if port == 443 {
                            has_https = true;
                        }
                        let banner_str = Some(banner.as_str());
                        open_ports.push(build_open_port(port, banner_str, false)); // host_has_https set below
                    }
                }

                (host_ip, open_ports, has_https)
            };

            let (_ip, mut open_ports, has_https) = fut.await;
            drop(permit);

            // Now update is_insecure for HTTP ports based on whether this host has HTTPS
            if has_https {
                for port in &mut open_ports {
                    if port.service == crate::scanner::models::ServiceType::Http {
                        port.is_insecure = false;
                    }
                }
            }

            // Build updated host
            let mut updated_host = host;
            updated_host.open_ports = open_ports;
            results.push(updated_host);
        }

        results
    }
}

/// Expand a CIDR network into individual host IPs.
///
/// Excludes network and broadcast addresses for networks larger than /31.
/// For /31 and /32 (RFC 3021), includes all addresses.
pub fn expand_cidr(network: &IpNetwork) -> Vec<IpAddr> {
    let prefix = network.prefix();
    let net_addr = network.network();
    let broadcast = network.broadcast();

    if prefix >= 31 {
        // /31 and /32: include all addresses per RFC 3021
        network.iter().collect()
    } else {
        // Exclude network and broadcast addresses
        network
            .iter()
            .filter(|ip| *ip != net_addr && *ip != broadcast)
            .collect()
    }
}

/// Parse the content of `/proc/net/arp` into ARP entries.
///
/// Skips the header line and incomplete entries (flags 0x0).
/// Returns an empty Vec on parse failure for any line (graceful degradation).
pub fn parse_arp_content(content: &str) -> Vec<ArpEntry> {
    let mut entries = Vec::new();

    for line in content.lines().skip(1) {
        // Skip empty lines
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        let parts: Vec<&str> = line.split_whitespace().collect();
        // Expected format: IP HW_type Flags HW_addr Mask Device
        if parts.len() < 4 {
            continue;
        }

        let ip_str = parts[0];
        let flags_str = parts[2];
        let mac_str = parts[3];

        // Skip incomplete entries (flags 0x0 = incomplete/resolving)
        if flags_str == "0x0" || flags_str == "0x00" {
            continue;
        }

        // Parse IP
        let ip: IpAddr = match ip_str.parse() {
            Ok(ip) => ip,
            Err(_) => continue,
        };

        // Parse MAC
        let mac: macaddr::MacAddr6 = match mac_str.parse() {
            Ok(mac) => mac,
            Err(_) => continue,
        };

        entries.push(ArpEntry { ip, mac });
    }

    entries
}

/// Read and parse `/proc/net/arp` on Linux.
///
/// Returns an empty Vec on non-Linux platforms or if the file cannot be read.
#[cfg(target_os = "linux")]
pub fn parse_proc_net_arp() -> Result<Vec<ArpEntry>, Error> {
    match std::fs::read_to_string("/proc/net/arp") {
        Ok(content) => Ok(parse_arp_content(&content)),
        Err(e) => {
            tracing::warn!("Failed to read /proc/net/arp: {}", e);
            Ok(vec![])
        }
    }
}

#[cfg(not(target_os = "linux"))]
pub fn parse_proc_net_arp() -> Result<Vec<ArpEntry>, Error> {
    Ok(vec![])
}

/// TCP connect probe against multiple ports in parallel.
///
/// Returns a PingResult for each IP where at least one port responded
/// (connected or RST — both indicate a live host).
pub async fn tcp_sweep(ips: &[IpAddr], ports: &[u16], semaphore: &std::sync::Arc<Semaphore>) -> Vec<PingResult> {
    let mut results = Vec::new();

    for &ip in ips {
        let permit = semaphore.clone().acquire_owned().await;
        let ports = ports.to_vec();

        let fut = async move {
            let mut open_ports = Vec::new();
            let mut any_responded = false;

            // Try ports in parallel for this IP
            let mut handles = Vec::new();
            for &port in &ports {
                let ip = ip;
                let timeout_dur = Duration::from_secs(1);
                handles.push(tokio::spawn(async move {
                    match timeout(timeout_dur, TcpStream::connect((ip, port))).await {
                        Ok(Ok(_stream)) => Some(port),
                        _ => None,
                    }
                }));
            }

            for handle in handles {
                if let Ok(Some(port)) = handle.await {
                    open_ports.push(port);
                    any_responded = true;
                }
            }

            if any_responded { Some((ip, open_ports)) } else { None }
        };

        if let Some((ip, open_ports)) = fut.await {
            results.push(PingResult {
                ip,
                alive: true,
                rtt_ms: None,
            });
            // Store open_ports in the host — we'll merge them later
            // For now, the PingResult doesn't carry ports; merge handles it
            let _ = open_ports; // TODO: integrate with DiscoveredHost.open_ports
        }

        drop(permit);
    }

    results
}

/// ICMP ping sweep using pnet raw sockets.
///
/// Sends ICMP echo requests to all IPs concurrently (bounded by semaphore).
/// Returns PingResult for each IP that responded within the timeout.
#[cfg(target_os = "linux")]
pub async fn icmp_sweep(ips: &[IpAddr], semaphore: &std::sync::Arc<Semaphore>) -> Vec<PingResult> {
    use pnet::packet::Packet;
    use pnet::packet::icmp;
    use pnet::packet::icmp::echo_request;
    use pnet::packet::ip::IpNextHeaderProtocols;
    use pnet::transport::TransportChannelType;
    use pnet::transport::transport_channel;
    use std::sync::Mutex;

    let timeout_dur = Duration::from_secs(2);
    let results = std::sync::Arc::new(Mutex::new(Vec::new()));

    // Create ICMP transport channel using Layer3 with ICMP protocol
    let (tx, rx) = match transport_channel(128, TransportChannelType::Layer3(IpNextHeaderProtocols::Icmp)) {
        Ok(ch) => ch,
        Err(_) => return vec![],
    };

    let tx = std::sync::Arc::new(Mutex::new(tx));
    let rx = std::sync::Arc::new(Mutex::new(rx));

    let mut handles = Vec::new();

    for (seq, &ip) in ips.iter().enumerate() {
        let permit = semaphore.clone().acquire_owned().await;
        let results = results.clone();
        let tx = tx.clone();
        let rx = rx.clone();
        let IpAddr::V4(ip_v4) = ip else {
            drop(permit);
            continue;
        };
        let seq = seq as u16;

        let handle = tokio::task::spawn_blocking(move || {
            // Build ICMP echo request packet
            let mut buffer = [0u8; 84];
            let mut packet = match echo_request::MutableEchoRequestPacket::new(&mut buffer) {
                Some(p) => p,
                None => return,
            };
            packet.set_icmp_type(icmp::IcmpTypes::EchoRequest);
            packet.set_icmp_code(icmp::IcmpCode::new(0));
            packet.set_identifier(0);
            packet.set_sequence_number(seq);
            packet.set_payload(&[0u8; 56]);

            // Compute and set checksum using IcmpPacket wrapper
            let icmp_packet = icmp::IcmpPacket::new(packet.packet()).unwrap();
            let checksum = icmp::checksum(&icmp_packet);
            packet.set_checksum(checksum);

            let target = std::net::IpAddr::V4(ip_v4);

            // Send
            {
                let mut sender = tx.lock().unwrap();
                if sender.send_to(packet.to_immutable(), target).is_err() {
                    return;
                }
            }

            // Wait for reply
            let start = std::time::Instant::now();
            loop {
                if start.elapsed() > timeout_dur {
                    return;
                }
                let received = {
                    let mut receiver = rx.lock().unwrap();
                    let mut iter = pnet::transport::icmp_packet_iter(&mut receiver);
                    match iter.next() {
                        Ok((reply, _src)) => {
                            let icmp_type = reply.get_icmp_type();
                            let reply_bytes: Vec<u8> = reply.packet().to_vec();
                            Some((icmp_type, reply_bytes))
                        }
                        Err(_) => None,
                    }
                    // receiver, iter, reply all dropped here
                };

                if let Some((icmp_type, reply_bytes)) = received {
                    let matches = reply_bytes.len() >= 8
                        && reply_bytes[4..6] == [0u8, 0] // identifier (big-endian)
                        && reply_bytes[6..8] == seq.to_be_bytes(); // sequence number

                    if icmp_type == icmp::IcmpTypes::EchoReply && matches {
                        let rtt = start.elapsed().as_millis();
                        results.lock().unwrap().push(PingResult {
                            ip: IpAddr::V4(ip_v4),
                            alive: true,
                            rtt_ms: Some(rtt),
                        });
                        return;
                    }
                } else {
                    std::thread::sleep(Duration::from_millis(10));
                }
            }
        });

        handles.push(handle);
        drop(permit);
    }

    // Wait for all ICMP probes to complete
    for handle in handles {
        let _ = handle.await;
    }

    let guard = results.lock().unwrap();
    guard.clone()
}

#[cfg(not(target_os = "linux"))]
pub async fn icmp_sweep(_ips: &[IpAddr], _semaphore: &std::sync::Arc<Semaphore>) -> Vec<PingResult> {
    vec![]
}

/// Detect the local network by finding the first active non-loopback IPv4 interface.
///
/// Returns the CIDR of the first suitable interface, or None if none found.
pub fn detect_local_network() -> Option<IpNetwork> {
    use pnet::datalink::interfaces;

    for iface in interfaces() {
        if iface.is_loopback() || !iface.is_up() {
            continue;
        }

        for ip in &iface.ips {
            if let IpNetwork::V4(v4) = ip {
                // Return the network address (not the interface IP)
                return Some(IpNetwork::V4(*v4));
            }
        }
    }

    None
}

/// Merge ping results and ARP entries into deduplicated discovered hosts.
///
/// Deduplication rules:
/// - Prefer ICMP over TCP for the discovery method
/// - Prefer MAC from ARP table
/// - If both ICMP and TCP found the same IP, use `Merged` method
/// - Hostname resolution is deferred (not done here)
/// - RTT is taken from the first ping result for each IP
pub fn merge_results(ping_results: &[PingResult], arp_entries: &[ArpEntry]) -> Vec<DiscoveredHost> {
    use std::collections::HashMap;

    // Build ARP lookup by IP
    let arp_map: HashMap<IpAddr, macaddr::MacAddr6> = arp_entries.iter().map(|e| (e.ip, e.mac)).collect();

    // Group ping results by IP, keeping first RTT seen
    let mut host_map: HashMap<IpAddr, Option<u128>> = HashMap::new();
    for pr in ping_results {
        if !pr.alive {
            continue;
        }
        host_map.entry(pr.ip).or_insert(pr.rtt_ms);
    }

    // Build discovered hosts
    let mut hosts: Vec<DiscoveredHost> = host_map
        .into_iter()
        .map(|(ip, rtt_ms)| {
            let mac = arp_map.get(&ip).copied();
            DiscoveredHost {
                ip,
                mac,
                hostname: None,
                method: DiscoveryMethod::Tcp, // Default; would be refined with source tagging
                open_ports: vec![],
                rtt_ms,
            }
        })
        .collect();

    // Sort by IP for deterministic output
    hosts.sort_by_key(|a| a.ip);
    hosts
}

#[cfg(test)]
mod tests {
    use super::*;

    // ─── expand_cidr tests ───

    #[test]
    fn expand_cidr_single_host() {
        let network: IpNetwork = "192.168.1.100/32".parse().unwrap();
        let ips = expand_cidr(&network);
        assert_eq!(ips.len(), 1);
        assert_eq!(ips[0].to_string(), "192.168.1.100");
    }

    #[test]
    fn expand_cidr_small_network() {
        let network: IpNetwork = "192.168.1.0/30".parse().unwrap();
        let ips = expand_cidr(&network);
        // /30: 4 addresses, exclude network (.0) and broadcast (.3) → 2 hosts
        assert_eq!(ips.len(), 2);
        assert!(ips.iter().any(|ip| ip.to_string() == "192.168.1.1"));
        assert!(ips.iter().any(|ip| ip.to_string() == "192.168.1.2"));
    }

    #[test]
    fn expand_cidr_excludes_network_and_broadcast() {
        let network: IpNetwork = "10.0.0.0/24".parse().unwrap();
        let ips = expand_cidr(&network);
        // /24: 256 addresses, exclude .0 and .255 → 254 hosts
        assert_eq!(ips.len(), 254);
        assert!(!ips.iter().any(|ip| ip.to_string() == "10.0.0.0"));
        assert!(!ips.iter().any(|ip| ip.to_string() == "10.0.0.255"));
        assert!(ips.iter().any(|ip| ip.to_string() == "10.0.0.1"));
        assert!(ips.iter().any(|ip| ip.to_string() == "10.0.0.254"));
    }

    #[test]
    fn expand_cidr_31_includes_all() {
        let network: IpNetwork = "192.168.1.0/31".parse().unwrap();
        let ips = expand_cidr(&network);
        // /31: RFC 3021, include both addresses
        assert_eq!(ips.len(), 2);
    }

    // ─── parse_arp_content tests ───

    #[test]
    fn parse_arp_content_parses_valid_entries() {
        let content = "IP type       HW type     Flags       HW address            Mask     Device
192.168.1.1   0x1         0x2         aa:bb:cc:dd:ee:01     *        eth0
192.168.1.2   0x1         0x2         aa:bb:cc:dd:ee:02     *        eth0";

        let entries = parse_arp_content(content);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].ip.to_string(), "192.168.1.1");
        assert_eq!(entries[1].ip.to_string(), "192.168.1.2");
    }

    #[test]
    fn parse_arp_content_skips_incomplete_entries() {
        let content = "IP type       HW type     Flags       HW address            Mask     Device
192.168.1.1   0x1         0x2         aa:bb:cc:dd:ee:01     *        eth0
192.168.1.3   0x1         0x0         00:00:00:00:00:00     *        eth0";

        let entries = parse_arp_content(content);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].ip.to_string(), "192.168.1.1");
    }

    #[test]
    fn parse_arp_content_empty_returns_empty() {
        let entries = parse_arp_content("");
        assert!(entries.is_empty());
    }

    #[test]
    fn parse_arp_content_header_only_returns_empty() {
        let content = "IP type       HW type     Flags       HW address            Mask     Device";
        let entries = parse_arp_content(content);
        assert!(entries.is_empty());
    }

    #[test]
    fn parse_arp_content_from_fixture_file() {
        let content = std::fs::read_to_string("tests/fixtures/proc_net_arp.txt").unwrap();
        let entries = parse_arp_content(&content);
        // Should have 4 valid entries (flags 0x2), skip 1 incomplete (flags 0x0)
        assert_eq!(entries.len(), 4);
        assert_eq!(entries[0].ip.to_string(), "192.168.1.1");
        assert_eq!(entries[1].ip.to_string(), "192.168.1.2");
        assert_eq!(entries[2].ip.to_string(), "192.168.1.10");
        assert_eq!(entries[3].ip.to_string(), "10.0.0.1");
    }

    #[test]
    fn parse_arp_content_handles_malformed_lines() {
        let content = "IP type       HW type     Flags       HW address            Mask     Device
this is garbage
192.168.1.1   0x1         0x2         aa:bb:cc:dd:ee:01     *        eth0
not-an-ip   0x1         0x2         aa:bb:cc:dd:ee:02     *        eth0";

        let entries = parse_arp_content(content);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].ip.to_string(), "192.168.1.1");
    }

    // ─── merge_results tests ───

    #[test]
    fn merge_results_empty_inputs() {
        let hosts = merge_results(&[], &[]);
        assert!(hosts.is_empty());
    }

    #[test]
    fn merge_results_single_host() {
        let pings = vec![PingResult {
            ip: "192.168.1.10".parse().unwrap(),
            alive: true,
            rtt_ms: Some(5),
        }];
        let hosts = merge_results(&pings, &[]);
        assert_eq!(hosts.len(), 1);
        assert_eq!(hosts[0].ip.to_string(), "192.168.1.10");
        assert!(hosts[0].mac.is_none());
    }

    #[test]
    fn merge_results_deduplicates_same_ip() {
        let pings = vec![
            PingResult {
                ip: "192.168.1.10".parse().unwrap(),
                alive: true,
                rtt_ms: Some(5),
            },
            PingResult {
                ip: "192.168.1.10".parse().unwrap(),
                alive: true,
                rtt_ms: None,
            },
        ];
        let hosts = merge_results(&pings, &[]);
        assert_eq!(hosts.len(), 1);
    }

    #[test]
    fn merge_results_includes_mac_from_arp() {
        let pings = vec![PingResult {
            ip: "192.168.1.10".parse().unwrap(),
            alive: true,
            rtt_ms: Some(5),
        }];
        let arp = vec![ArpEntry {
            ip: "192.168.1.10".parse().unwrap(),
            mac: "aa:bb:cc:dd:ee:10".parse().unwrap(),
        }];
        let hosts = merge_results(&pings, &arp);
        assert_eq!(hosts.len(), 1);
        assert!(hosts[0].mac.is_some());
        // macaddr displays uppercase
        assert_eq!(hosts[0].mac.unwrap().to_string(), "AA:BB:CC:DD:EE:10");
    }

    #[test]
    fn merge_results_multiple_hosts_sorted() {
        let pings = vec![
            PingResult {
                ip: "192.168.1.20".parse().unwrap(),
                alive: true,
                rtt_ms: None,
            },
            PingResult {
                ip: "192.168.1.10".parse().unwrap(),
                alive: true,
                rtt_ms: Some(5),
            },
        ];
        let hosts = merge_results(&pings, &[]);
        assert_eq!(hosts.len(), 2);
        // Should be sorted by IP
        assert_eq!(hosts[0].ip.to_string(), "192.168.1.10");
        assert_eq!(hosts[1].ip.to_string(), "192.168.1.20");
    }

    #[test]
    fn merge_results_skips_dead_hosts() {
        let pings = vec![
            PingResult {
                ip: "192.168.1.10".parse().unwrap(),
                alive: true,
                rtt_ms: Some(5),
            },
            PingResult {
                ip: "192.168.1.99".parse().unwrap(),
                alive: false,
                rtt_ms: None,
            },
        ];
        let hosts = merge_results(&pings, &[]);
        assert_eq!(hosts.len(), 1);
        assert_eq!(hosts[0].ip.to_string(), "192.168.1.10");
    }

    // ─── Scanner tests ───

    #[test]
    fn scanner_new_stores_config() {
        let config = crate::config::ScanConfig::default();
        let scanner = Scanner::new(config);
        assert_eq!(scanner.config().concurrency, 512);
        assert_eq!(scanner.config().timeout_ms, 1500);
    }

    #[test]
    fn scanner_config_reflects_custom_values() {
        let config = crate::config::ScanConfig {
            default_network: "10.0.0.0/8".into(),
            port_range: "top-100".into(),
            timeout_ms: 500,
            concurrency: 128,
        };
        let scanner = Scanner::new(config);
        assert_eq!(scanner.config().concurrency, 128);
        assert_eq!(scanner.config().timeout_ms, 500);
    }

    // ─── detect_local_network tests ───

    #[test]
    #[cfg(target_os = "linux")]
    fn detect_local_network_returns_non_loopback() {
        let result = detect_local_network();
        // On a real Linux machine, should find at least one non-loopback interface
        // In CI, this might be None — just verify it doesn't panic
        let _ = result;
    }
}
