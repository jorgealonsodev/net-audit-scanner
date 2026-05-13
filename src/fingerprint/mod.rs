//! Device fingerprinting — OS hints from TTL and service banners.
//!
//! Provides lightweight OS detection using:
//! - TTL values from ICMP echo replies (round down to standard initial TTLs)
//! - Pattern matching on service banners (SSH, HTTP, etc.)

/// Infer OS from TTL value in ICMP echo reply.
///
/// Maps common initial TTL values to OS families:
/// - 60–64 → Linux/macOS (initial TTL=64)
/// - 120–128 → Windows (initial TTL=128)
/// - 250–254 → FreeBSD (initial TTL=254/255)
/// - Below 32 → None (too many hops for reliable inference)
pub fn ttl_to_os_hint(ttl: u8) -> Option<&'static str> {
    match ttl {
        60..=64 => Some("Linux/macOS"),
        120..=128 => Some("Windows"),
        250..=255 => Some("FreeBSD"),
        _ => None,
    }
}

/// Infer OS from service banner text using pattern matching.
///
/// Checks for known OS substrings in order of specificity:
/// Linux distros first (Ubuntu, Debian, RHEL), then Windows, FreeBSD,
/// generic Linux, and Cisco IOS.
pub fn infer_os_from_banner(banner: &str) -> Option<String> {
    let lower = banner.to_lowercase();

    // Linux distros (check before generic "linux")
    if lower.contains("ubuntu") {
        return Some("Ubuntu Linux".into());
    }
    if lower.contains("debian") {
        return Some("Debian Linux".into());
    }
    if lower.contains("centos") || lower.contains("red hat") || lower.contains("rhel") {
        return Some("RHEL/CentOS Linux".into());
    }

    // Windows
    if lower.contains("microsoft") || lower.contains("windows") {
        return Some("Windows".into());
    }

    // FreeBSD
    if lower.contains("freebsd") {
        return Some("FreeBSD".into());
    }

    // Generic Linux (SSH banners often contain "Linux")
    if lower.contains("linux") {
        return Some("Linux".into());
    }

    // Cisco IOS
    if lower.contains("cisco") || lower.contains("ios") {
        return Some("Cisco IOS".into());
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    // ─── ttl_to_os_hint tests ───

    #[test]
    fn ttl_64_maps_to_linux_macos() {
        assert_eq!(ttl_to_os_hint(64), Some("Linux/macOS"));
    }

    #[test]
    fn ttl_63_maps_to_linux_macos() {
        assert_eq!(ttl_to_os_hint(63), Some("Linux/macOS"));
    }

    #[test]
    fn ttl_60_maps_to_linux_macos() {
        assert_eq!(ttl_to_os_hint(60), Some("Linux/macOS"));
    }

    #[test]
    fn ttl_128_maps_to_windows() {
        assert_eq!(ttl_to_os_hint(128), Some("Windows"));
    }

    #[test]
    fn ttl_127_maps_to_windows() {
        assert_eq!(ttl_to_os_hint(127), Some("Windows"));
    }

    #[test]
    fn ttl_120_maps_to_windows() {
        assert_eq!(ttl_to_os_hint(120), Some("Windows"));
    }

    #[test]
    fn ttl_254_maps_to_freebsd() {
        assert_eq!(ttl_to_os_hint(254), Some("FreeBSD"));
    }

    #[test]
    fn ttl_255_maps_to_freebsd() {
        assert_eq!(ttl_to_os_hint(255), Some("FreeBSD"));
    }

    #[test]
    fn ttl_250_maps_to_freebsd() {
        assert_eq!(ttl_to_os_hint(250), Some("FreeBSD"));
    }

    #[test]
    fn ttl_below_32_returns_none() {
        assert_eq!(ttl_to_os_hint(31), None);
        assert_eq!(ttl_to_os_hint(1), None);
        assert_eq!(ttl_to_os_hint(0), None);
    }

    #[test]
    fn ttl_edge_cases_return_none() {
        assert_eq!(ttl_to_os_hint(65), None);
        assert_eq!(ttl_to_os_hint(129), None);
        assert_eq!(ttl_to_os_hint(32), None);
        assert_eq!(ttl_to_os_hint(200), None);
    }

    // ─── infer_os_from_banner tests ───

    #[test]
    fn banner_ubuntu_ssh() {
        let banner = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-4ubuntu0.5";
        assert_eq!(infer_os_from_banner(banner), Some("Ubuntu Linux".into()));
    }

    #[test]
    fn banner_debian_ssh() {
        let banner = "SSH-2.0-OpenSSH_7.9p1 Debian-10+deb10u2";
        assert_eq!(infer_os_from_banner(banner), Some("Debian Linux".into()));
    }

    #[test]
    fn banner_centos() {
        let banner = "SSH-2.0-OpenSSH_8.0 CentOS-8";
        assert_eq!(infer_os_from_banner(banner), Some("RHEL/CentOS Linux".into()));
    }

    #[test]
    fn banner_red_hat() {
        let banner = "SSH-2.0-OpenSSH_7.4 Red Hat";
        assert_eq!(infer_os_from_banner(banner), Some("RHEL/CentOS Linux".into()));
    }

    #[test]
    fn banner_windows_smb() {
        let banner = "Microsoft Windows SMB";
        assert_eq!(infer_os_from_banner(banner), Some("Windows".into()));
    }

    #[test]
    fn banner_windows_ssh() {
        let banner = "SSH-2.0-OpenSSH_for_Windows_8.1";
        assert_eq!(infer_os_from_banner(banner), Some("Windows".into()));
    }

    #[test]
    fn banner_freebsd_ssh() {
        let banner = "SSH-2.0-OpenSSH_8.1 FreeBSD-20200214";
        assert_eq!(infer_os_from_banner(banner), Some("FreeBSD".into()));
    }

    #[test]
    fn banner_generic_linux() {
        let banner = "SSH-2.0-OpenSSH_8.2 Linux";
        assert_eq!(infer_os_from_banner(banner), Some("Linux".into()));
    }

    #[test]
    fn banner_cisco_ios() {
        let banner = "Cisco IOS Software, C2960";
        assert_eq!(infer_os_from_banner(banner), Some("Cisco IOS".into()));
    }

    #[test]
    fn banner_no_match_returns_none() {
        let banner = "SSH-2.0-OpenSSH_9.0";
        assert_eq!(infer_os_from_banner(banner), None);
    }

    #[test]
    fn banner_empty_returns_none() {
        assert_eq!(infer_os_from_banner(""), None);
    }

    #[test]
    fn banner_case_insensitive() {
        assert_eq!(infer_os_from_banner("Ubuntu"), Some("Ubuntu Linux".into()));
        assert_eq!(infer_os_from_banner("UBUNTU"), Some("Ubuntu Linux".into()));
        assert_eq!(infer_os_from_banner("ubuntu"), Some("Ubuntu Linux".into()));
    }
}
