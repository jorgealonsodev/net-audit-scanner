//! Platform capability detection for network scanning.
//!
//! Detects whether the process has the privileges needed for
//! ICMP raw sockets and ARP table access.

use super::models::Capabilities;

/// Detect platform capabilities for network scanning.
///
/// Checks:
/// - Whether the process runs as root (UID 0)
/// - Whether raw sockets can be created (requires root or CAP_NET_RAW)
/// - ARP table is always readable on Linux
pub fn detect() -> Capabilities {
    let is_root = unsafe { libc::geteuid() } == 0;

    // Raw socket probe: try to create a raw ICMP socket.
    // This succeeds only with root or CAP_NET_RAW.
    let can_raw_sockets = probe_raw_socket();

    Capabilities {
        is_root,
        can_icmp: can_raw_sockets,
        can_raw_sockets,
        can_arp_table: cfg!(target_os = "linux"),
    }
}

/// Attempt to create a raw socket to test privilege level.
/// Returns true if successful, false otherwise.
fn probe_raw_socket() -> bool {
    // SAFETY: libc::socket is a standard POSIX function.
    // We use IPPROTO_ICMP (1) for the raw socket probe.
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_RAW, 1) };
    if fd < 0 {
        return false;
    }
    // SAFETY: fd is a valid socket descriptor from the call above.
    unsafe { libc::close(fd) };
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_returns_capabilities() {
        let caps = detect();
        let _ = caps.is_root;
        let _ = caps.can_icmp;
        let _ = caps.can_raw_sockets;
        let _ = caps.can_arp_table;
    }

    #[test]
    fn detect_arp_table_is_linux_only() {
        let caps = detect();
        #[cfg(target_os = "linux")]
        assert!(caps.can_arp_table);
        #[cfg(not(target_os = "linux"))]
        assert!(!caps.can_arp_table);
    }

    #[test]
    fn capabilities_struct_has_expected_fields() {
        let caps = Capabilities {
            is_root: false,
            can_icmp: false,
            can_raw_sockets: false,
            can_arp_table: true,
        };
        assert!(!caps.is_root);
        assert!(!caps.can_icmp);
        assert!(!caps.can_raw_sockets);
        assert!(caps.can_arp_table);
    }

    #[test]
    fn capabilities_root_implies_raw_sockets() {
        let caps = detect();
        if caps.is_root {
            assert!(
                caps.can_raw_sockets,
                "root process should be able to create raw sockets"
            );
            assert!(caps.can_icmp, "root process should have ICMP capability");
        }
    }

    #[test]
    fn probe_raw_socket_returns_bool() {
        let result = probe_raw_socket();
        let _ = result;
    }
}
