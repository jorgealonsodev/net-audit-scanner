//! Network scanner module — port scanning, host discovery, and service detection.

pub mod capabilities;
pub mod discovery;
pub mod models;

pub use capabilities::detect;
pub use discovery::{Scanner, detect_local_network, expand_cidr, merge_results, parse_arp_content, parse_proc_net_arp};
pub use models::{ArpEntry, Capabilities, DiscoveredHost, DiscoveryMethod, PingResult};

/// Returns the module path for reachability checks.
pub fn module_path() -> &'static str {
    "scanner"
}
