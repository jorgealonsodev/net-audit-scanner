//! OUI (Organizationally Unique Identifier) fingerprinting module.
//!
//! Provides MAC address vendor lookup using the Wireshark manuf database.
//! The database is embedded at compile time via `include_dir!` and parsed
//! into three `HashMap`s keyed by 3-byte, 4-byte, and 5-byte MAC prefixes.
//! Lookup uses longest-prefix-match: tries 5-byte first, then 4-byte, then 3-byte.

use std::collections::HashMap;
use std::sync::LazyLock;

use crate::scanner::models::DiscoveredHost;

/// Parsed OUI/manuf database with prefix lookups.
#[derive(Debug, Clone)]
pub struct OuiDb {
    prefix3: HashMap<[u8; 3], String>,
    prefix4: HashMap<[u8; 4], String>,
    prefix5: HashMap<[u8; 5], String>,
}

impl OuiDb {
    /// Load the embedded Wireshark manuf database.
    pub fn from_embedded() -> Self {
        use include_dir::{include_dir, Dir};
        static DATA_DIR: Dir<'_> = include_dir!("$CARGO_MANIFEST_DIR/data/manuf");

        let content = DATA_DIR
            .get_file("manuf")
            .and_then(|f| f.contents_utf8())
            .unwrap_or("");

        if content.is_empty() {
            tracing::warn!("Embedded manuf database is empty or missing");
        }

        parse_manuf(content)
    }

    /// Look up the vendor for a MAC address using longest-prefix-match.
    ///
    /// Tries 5-byte prefix first, then 4-byte, then 3-byte.
    pub fn lookup(&self, mac: &macaddr::MacAddr6) -> Option<&str> {
        let bytes = mac.as_bytes();

        // Try longest prefix first: 5-byte → 4-byte → 3-byte
        let key5 = [bytes[0], bytes[1], bytes[2], bytes[3], bytes[4]];
        if let Some(vendor) = self.prefix5.get(&key5) {
            return Some(vendor);
        }

        let key4 = [bytes[0], bytes[1], bytes[2], bytes[3]];
        if let Some(vendor) = self.prefix4.get(&key4) {
            return Some(vendor);
        }

        let key3 = [bytes[0], bytes[1], bytes[2]];
        self.prefix3.get(&key3).map(|s| s.as_str())
    }
}

/// Parse manuf file content into an `OuiDb`.
///
/// Skips comment lines (starting with `#`) and blank lines.
/// Ignores malformed lines gracefully.
///
/// Each line is tab-separated with fields:
/// `PREFIX[/MASK]\tSHORT_NAME\tLONG_NAME`
///
/// The prefix byte count (3, 4, or 5) determines which HashMap the entry
/// is stored in. The long name is preferred; short name is used as fallback.
pub fn parse_manuf(content: &str) -> OuiDb {
    let mut prefix3 = HashMap::new();
    let mut prefix4 = HashMap::new();
    let mut prefix5 = HashMap::new();

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let fields: Vec<&str> = line.split('\t').collect();
        if fields.is_empty() {
            continue;
        }

        // Parse prefix: may have /MASK suffix
        let prefix_field = fields[0];
        let prefix_hex = prefix_field.split('/').next().unwrap_or(prefix_field);

        // Parse hex bytes
        let bytes: Vec<u8> = prefix_hex
            .split(':')
            .filter_map(|s| u8::from_str_radix(s, 16).ok())
            .collect();

        if bytes.len() < 3 || bytes.len() > 5 {
            continue;
        }

        // Vendor name: prefer long name (3rd field), fallback to short name (2nd field)
        let vendor = fields
            .get(2)
            .or_else(|| fields.get(1))
            .unwrap_or(&"Unknown")
            .to_string();

        match bytes.len() {
            3 => {
                let key = [bytes[0], bytes[1], bytes[2]];
                prefix3.insert(key, vendor);
            }
            4 => {
                let key = [bytes[0], bytes[1], bytes[2], bytes[3]];
                prefix4.insert(key, vendor);
            }
            5 => {
                let key = [bytes[0], bytes[1], bytes[2], bytes[3], bytes[4]];
                prefix5.insert(key, vendor);
            }
            _ => continue,
        }
    }

    OuiDb {
        prefix3,
        prefix4,
        prefix5,
    }
}

/// Enrich discovered hosts with vendor information from the OUI database.
///
/// Preconditions:
/// - Call after `scan_ports()` in the CLI pipeline.
/// - MAC addresses must be populated (typically by ARP discovery).
pub fn enrich_oui(db: &OuiDb, hosts: &mut [DiscoveredHost]) {
    for host in hosts.iter_mut() {
        if let Some(mac) = host.mac.as_ref() {
            if let Some(vendor) = db.lookup(mac) {
                host.vendor = Some(vendor.to_string());
            }
        }
    }
}

/// Global lazy-initialized OUI database.
pub static OUI_DB: LazyLock<OuiDb> = LazyLock::new(OuiDb::from_embedded);

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    // ─── parse_manuf tests ───

    #[test]
    fn parse_manuf_parses_3byte_prefix() {
        let content = "00:00:0C\tCisco\tCisco Systems, Inc.\n";
        let db = parse_manuf(content);
        let mac: macaddr::MacAddr6 = "00:00:0C:11:22:33".parse().unwrap();
        assert_eq!(db.lookup(&mac), Some("Cisco Systems, Inc."));
    }

    #[test]
    fn parse_manuf_parses_4byte_prefix() {
        let content = "00:1B:63:84\tApple4\tApple Inc. (4-byte)\n";
        let db = parse_manuf(content);
        let mac: macaddr::MacAddr6 = "00:1B:63:84:AA:BB".parse().unwrap();
        assert_eq!(db.lookup(&mac), Some("Apple Inc. (4-byte)"));
    }

    #[test]
    fn parse_manuf_parses_5byte_prefix() {
        let content = "00:1B:63:84:E0\tApple5\tApple, Inc.\n";
        let db = parse_manuf(content);
        let mac: macaddr::MacAddr6 = "00:1B:63:84:E0:01".parse().unwrap();
        assert_eq!(db.lookup(&mac), Some("Apple, Inc."));
    }

    #[test]
    fn parse_manuf_skips_comments_and_blank_lines() {
        let content = "# This is a comment\n\n00:50:56\tVMware\tVMware, Inc.\n\n";
        let db = parse_manuf(content);
        let mac: macaddr::MacAddr6 = "00:50:56:01:02:03".parse().unwrap();
        assert_eq!(db.lookup(&mac), Some("VMware, Inc."));
    }

    #[test]
    fn parse_manuf_handles_malformed_lines() {
        let content = "not-a-valid-line\n00:50:56\tVMware\tVMware, Inc.\nZZ:YY:XX\tBad\tBad Vendor\n";
        let db = parse_manuf(content);
        let mac: macaddr::MacAddr6 = "00:50:56:01:02:03".parse().unwrap();
        assert_eq!(db.lookup(&mac), Some("VMware, Inc."));
    }

    // ─── OuiDb::lookup tests ───

    #[test]
    fn oui_db_lookup_finds_3byte_exact() {
        let db = parse_manuf("00:00:0C\tCisco\tCisco Systems, Inc.\n");
        let mac: macaddr::MacAddr6 = "00:00:0C:11:22:33".parse().unwrap();
        assert_eq!(db.lookup(&mac), Some("Cisco Systems, Inc."));
    }

    #[test]
    fn oui_db_lookup_finds_4byte_exact() {
        let db = parse_manuf("00:1B:63:84\tApple4\tApple Inc. (4-byte)\n");
        let mac: macaddr::MacAddr6 = "00:1B:63:84:AA:BB".parse().unwrap();
        assert_eq!(db.lookup(&mac), Some("Apple Inc. (4-byte)"));
    }

    #[test]
    fn oui_db_lookup_finds_5byte_exact() {
        let db = parse_manuf("00:1B:63:84:E0\tApple5\tApple, Inc.\n");
        let mac: macaddr::MacAddr6 = "00:1B:63:84:E0:01".parse().unwrap();
        assert_eq!(db.lookup(&mac), Some("Apple, Inc."));
    }

    #[test]
    fn oui_db_lookup_unknown_returns_none() {
        let db = parse_manuf("00:00:0C\tCisco\tCisco Systems, Inc.\n");
        let mac: macaddr::MacAddr6 = "FF:FF:FF:FF:FF:FF".parse().unwrap();
        assert_eq!(db.lookup(&mac), None);
    }

    #[test]
    fn oui_db_lookup_longest_prefix_wins() {
        // Both 3-byte and 4-byte prefixes match the same MAC
        let content = "00:1B:63\tApple3\tApple (3-byte)\n00:1B:63:84\tApple4\tApple Inc. (4-byte)\n";
        let db = parse_manuf(content);
        let mac: macaddr::MacAddr6 = "00:1B:63:84:AA:BB".parse().unwrap();
        // Longest prefix (4-byte) should win
        assert_eq!(db.lookup(&mac), Some("Apple Inc. (4-byte)"));
    }

    // ─── enrich_oui tests ───

    #[test]
    fn enrich_oui_populates_vendor_for_mac_hosts() {
        let db = parse_manuf("00:00:0C\tCisco\tCisco Systems, Inc.\n");
        let mut hosts = vec![DiscoveredHost {
            ip: "192.168.1.1".parse::<IpAddr>().unwrap(),
            mac: Some("00:00:0C:11:22:33".parse().unwrap()),
            hostname: None,
            method: crate::scanner::models::DiscoveryMethod::Arp,
            open_ports: vec![],
            rtt_ms: None,
            vendor: None,
        }];
        enrich_oui(&db, &mut hosts);
        assert_eq!(hosts[0].vendor, Some("Cisco Systems, Inc.".into()));
    }

    #[test]
    fn enrich_oui_leaves_vendor_none_for_no_mac() {
        let db = parse_manuf("00:00:0C\tCisco\tCisco Systems, Inc.\n");
        let mut hosts = vec![DiscoveredHost {
            ip: "192.168.1.1".parse::<IpAddr>().unwrap(),
            mac: None,
            hostname: None,
            method: crate::scanner::models::DiscoveryMethod::Icmp,
            open_ports: vec![],
            rtt_ms: None,
            vendor: None,
        }];
        enrich_oui(&db, &mut hosts);
        assert!(hosts[0].vendor.is_none());
    }

    #[test]
    fn enrich_oui_mutates_in_place() {
        let db = parse_manuf("B8:27:EB\tRaspberry\tRaspberry Pi Foundation\n");
        let mut hosts = vec![
            DiscoveredHost {
                ip: "192.168.1.1".parse::<IpAddr>().unwrap(),
                mac: Some("B8:27:EB:01:02:03".parse().unwrap()),
                hostname: None,
                method: crate::scanner::models::DiscoveryMethod::Arp,
                open_ports: vec![],
                rtt_ms: None,
                vendor: None,
            },
            DiscoveredHost {
                ip: "192.168.1.2".parse::<IpAddr>().unwrap(),
                mac: Some("00:00:0C:AA:BB:CC".parse().unwrap()),
                hostname: None,
                method: crate::scanner::models::DiscoveryMethod::Arp,
                open_ports: vec![],
                rtt_ms: None,
                vendor: None,
            },
        ];
        enrich_oui(&db, &mut hosts);
        assert_eq!(hosts[0].vendor, Some("Raspberry Pi Foundation".into()));
        assert!(hosts[1].vendor.is_none());
    }
}
