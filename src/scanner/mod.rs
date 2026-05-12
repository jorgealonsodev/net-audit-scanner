//! Network scanner module — port scanning, host discovery, and service detection.

pub mod capabilities;
pub mod models;

pub use capabilities::detect;
pub use models::{ArpEntry, Capabilities, DiscoveredHost, DiscoveryMethod, PingResult};

/// Returns the module path for reachability checks.
pub fn module_path() -> &'static str {
    "scanner"
}
