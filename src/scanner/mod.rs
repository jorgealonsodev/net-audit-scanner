//! Network scanner module — host discovery via ICMP, TCP, and ARP probes.
//!
//! Provides the `Scanner` orchestrator that runs discovery probes concurrently,
//! merges results by IP, and deduplicates discovered hosts. Includes platform
//! capability detection (`detect()`) and CIDR expansion utilities.

pub mod capabilities;
pub mod discovery;
pub mod models;
pub mod ports;
pub mod services;

pub use capabilities::detect;
pub use discovery::{Scanner, detect_local_network, expand_cidr, merge_results, parse_arp_content, parse_proc_net_arp};
pub use models::{
    ArpEntry, Capabilities, DiscoveredHost, DiscoveryMethod, OpenPort, PingResult, Protocol, ServiceType,
};
pub use ports::{IOT_CRITICAL_PORTS, PORT_LIST_TOP_100, PORT_LIST_TOP_1000, resolve_port_list};
pub use services::{build_open_port, classify_service, grab_banner, is_insecure};

/// Returns the module path for reachability checks.
pub fn module_path() -> &'static str {
    "scanner"
}
