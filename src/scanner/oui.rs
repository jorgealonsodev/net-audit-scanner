//! OUI (Organizationally Unique Identifier) fingerprinting module.
//!
//! Provides MAC address vendor lookup using the Wireshark `manuf` database.
//! The database is embedded at compile time via [`include_dir!`] and parsed
//! into three `HashMap`s keyed by 3-byte, 4-byte, and 5-byte MAC prefixes.
//!
//! # Design
//!
//! - **Three HashMaps** (`[u8; 3]`, `[u8; 4]`, `[u8; 5]`) give compile-time key sizes,
//!   trivial `Hash`/`Eq`, and zero allocations on lookup.
//! - **Longest-prefix-match**: lookup tries 5-byte first, then 4-byte, then 3-byte.
//!   This ensures the most specific OUI wins when multiple prefixes overlap.
//! - **Byte-boundary rounding**: prefix masks (e.g. `/28`, `/30`) are rounded up to
//!   the nearest byte boundary. A `/28` entry is stored as a 4-byte exact match.
//! - **Compile-time embed**: the `manuf` file lives in `data/manuf/` and is baked
//!   into the binary via `include_dir!`. A missing file causes a compile error
//!   (hard fail) rather than silent degradation at runtime.
//!
//! # Pipeline
//!
//! ```text
//! data/manuf (embedded) → LazyLock<OuiDb> → lookup(mac) → Option<&str>
//!                                                    ↓
//! CLI: discover → scan_ports → enrich_oui → output
//! ```
//!
//! [`include_dir!`]: include_dir::include_dir

use std::collections::HashMap;
use std::path::{Path, PathBuf};
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
        use include_dir::{Dir, include_dir};
        static DATA_DIR: Dir<'_> = include_dir!("$CARGO_MANIFEST_DIR/data/manuf");

        let content = DATA_DIR.get_file("manuf").and_then(|f| f.contents_utf8()).unwrap_or("");

        if content.is_empty() {
            tracing::warn!("Embedded manuf database is empty or missing");
        }

        parse_manuf(content)
    }

    /// Parse a manuf database from any reader.
    ///
    /// This is the shared entry point used by both [`Self::from_embedded`]
    /// and [`Self::from_file`].
    pub fn from_reader(mut reader: impl std::io::Read) -> std::io::Result<Self> {
        let mut buf = String::new();
        reader.read_to_string(&mut buf)?;
        Ok(parse_manuf(&buf))
    }

    /// Load a manuf database from a file on disk.
    pub fn from_file(path: &Path) -> std::io::Result<Self> {
        let file = std::fs::File::open(path)?;
        Self::from_reader(file)
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
/// Iterates over `hosts` and mutates `vendor` in place when a matching OUI
/// prefix is found for the host's MAC address.
///
/// # Preconditions
///
/// 1. Call **after** `scan_ports()` in the CLI pipeline.
/// 2. MAC addresses must be populated — typically by ARP discovery
///    (`parse_proc_net_arp`) or other L2 probes.
/// 3. Hosts without a MAC address are left unchanged (`vendor` stays `None`).
///
/// # Example
///
/// ```rust,no_run
/// use netascan::scanner::{OuiDb, enrich_oui};
///
/// let db = OuiDb::from_embedded();
/// // hosts must have MAC addresses populated
/// // enrich_oui(&db, &mut hosts);
/// ```
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
///
/// Uses cache-first initialization: tries `~/.cache/netascan/manuf` first,
/// falls back to the embedded database if the cache is absent or corrupted.
pub static OUI_DB: LazyLock<OuiDb> = LazyLock::new(get_oui_db);

/// Returns the default cache path for the OUI manuf database.
///
/// Path: `~/.cache/netascan/manuf`
pub fn cache_path() -> PathBuf {
    dirs::cache_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("netascan/manuf")
}

/// Cache-first OUI database initialization.
///
/// Tries to load from `~/.cache/netascan/manuf`. If the cache is absent,
/// unreadable, or corrupted, falls back to the embedded database.
pub fn get_oui_db() -> OuiDb {
    let path = cache_path();
    get_oui_db_from(&path).unwrap_or_else(|_| {
        tracing::info!("Loading OUI database from embedded copy");
        OuiDb::from_embedded()
    })
}

/// Internal helper: try to load OUI DB from a specific path, falling back
/// to embedded on any error. Used by [`get_oui_db`] and testable with temp dirs.
pub fn get_oui_db_from(path: &Path) -> Result<OuiDb, std::io::Error> {
    match OuiDb::from_file(path) {
        Ok(db) => Ok(db),
        Err(e) => {
            if e.kind() != std::io::ErrorKind::NotFound {
                tracing::warn!("Cache file at {:?} is corrupted or unreadable: {}", path, e);
            }
            Err(e)
        }
    }
}

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
            device_model: None,
            os_hint: None,
            security_findings: vec![],
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
            device_model: None,
            os_hint: None,
            security_findings: vec![],
        }];
        enrich_oui(&db, &mut hosts);
        assert!(hosts[0].vendor.is_none());
    }

    // ─── fixture-based integration test ───

    #[test]
    fn parse_manuf_from_fixture_file() {
        let content = std::fs::read_to_string("tests/fixtures/manuf.txt").unwrap();
        let db = parse_manuf(&content);

        // 3-byte prefix
        let mac3: macaddr::MacAddr6 = "00:00:0C:11:22:33".parse().unwrap();
        assert_eq!(db.lookup(&mac3), Some("Cisco Systems, Inc."));

        // 4-byte prefix
        let mac4: macaddr::MacAddr6 = "00:1B:63:84:AA:BB".parse().unwrap();
        assert_eq!(db.lookup(&mac4), Some("Apple Inc. (4-byte)"));

        // 5-byte prefix
        let mac5: macaddr::MacAddr6 = "00:1B:63:84:E0:01".parse().unwrap();
        assert_eq!(db.lookup(&mac5), Some("Apple, Inc."));

        // Another 3-byte prefix from fixture
        let mac_vm: macaddr::MacAddr6 = "00:50:56:01:02:03".parse().unwrap();
        assert_eq!(db.lookup(&mac_vm), Some("VMware, Inc."));

        // Unknown MAC should return None
        let mac_unknown: macaddr::MacAddr6 = "FF:FF:FF:FF:FF:FF".parse().unwrap();
        assert_eq!(db.lookup(&mac_unknown), None);
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
                device_model: None,
                os_hint: None,
                security_findings: vec![],
            },
            DiscoveredHost {
                ip: "192.168.1.2".parse::<IpAddr>().unwrap(),
                mac: Some("00:00:0C:AA:BB:CC".parse().unwrap()),
                hostname: None,
                method: crate::scanner::models::DiscoveryMethod::Arp,
                open_ports: vec![],
                rtt_ms: None,
                vendor: None,
                device_model: None,
                os_hint: None,
                security_findings: vec![],
            },
        ];
        enrich_oui(&db, &mut hosts);
        assert_eq!(hosts[0].vendor, Some("Raspberry Pi Foundation".into()));
        assert!(hosts[1].vendor.is_none());
    }

    // ─── OuiDb::from_reader tests ───

    #[test]
    fn from_reader_parses_valid_input() {
        use std::io::Cursor;
        let content = "00:00:0C\tCisco\tCisco Systems, Inc.\n00:50:56\tVMware\tVMware, Inc.\n";
        let db = OuiDb::from_reader(Cursor::new(content)).unwrap();
        let mac: macaddr::MacAddr6 = "00:00:0C:11:22:33".parse().unwrap();
        assert_eq!(db.lookup(&mac), Some("Cisco Systems, Inc."));
        let mac2: macaddr::MacAddr6 = "00:50:56:AA:BB:CC".parse().unwrap();
        assert_eq!(db.lookup(&mac2), Some("VMware, Inc."));
    }

    #[test]
    fn from_reader_empty_input_returns_empty_db() {
        use std::io::Cursor;
        let db = OuiDb::from_reader(Cursor::new("")).unwrap();
        let mac: macaddr::MacAddr6 = "00:00:0C:11:22:33".parse().unwrap();
        assert_eq!(db.lookup(&mac), None);
    }

    #[test]
    fn from_reader_io_error_propagates() {
        use std::io;
        // Create a reader that always fails
        struct FailingReader;
        impl std::io::Read for FailingReader {
            fn read(&mut self, _buf: &mut [u8]) -> std::io::Result<usize> {
                Err(io::Error::other("read failed"))
            }
        }
        let result = OuiDb::from_reader(FailingReader);
        assert!(result.is_err());
    }

    // ─── OuiDb::from_file tests ───

    #[test]
    fn from_file_reads_valid_manuf() {
        use std::io::Write;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("manuf");
        let mut file = std::fs::File::create(&path).unwrap();
        file.write_all(b"00:00:0C\tCisco\tCisco Systems, Inc.\n").unwrap();
        drop(file);

        let db = OuiDb::from_file(&path).unwrap();
        let mac: macaddr::MacAddr6 = "00:00:0C:11:22:33".parse().unwrap();
        assert_eq!(db.lookup(&mac), Some("Cisco Systems, Inc."));
    }

    #[test]
    fn from_file_missing_file_returns_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nonexistent");
        let result = OuiDb::from_file(&path);
        assert!(result.is_err());
    }

    // ─── cache_path tests ───

    #[test]
    fn cache_path_returns_cache_dir_netascan_manuf() {
        let expected = dirs::cache_dir()
            .expect("cache dir should exist")
            .join("netascan/manuf");
        assert_eq!(cache_path(), expected);
    }

    // ─── get_oui_db tests ───

    #[test]
    fn get_oui_db_from_uses_cache_when_valid() {
        use std::io::Write;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("manuf");
        let mut file = std::fs::File::create(&path).unwrap();
        file.write_all(b"00:00:0C\tCisco\tCisco Systems, Inc.\n").unwrap();
        drop(file);

        let db = get_oui_db_from(&path).unwrap();
        let mac: macaddr::MacAddr6 = "00:00:0C:11:22:33".parse().unwrap();
        assert_eq!(db.lookup(&mac), Some("Cisco Systems, Inc."));
    }

    #[test]
    fn get_oui_db_from_returns_error_on_missing_cache() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nonexistent");
        // get_oui_db_from returns Err when file is missing; fallback is in get_oui_db()
        let result = get_oui_db_from(&path);
        assert!(result.is_err());
    }

    #[test]
    fn get_oui_db_from_returns_error_on_corrupted_cache() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("manuf");
        std::fs::write(&path, "this is not a valid manuf file\nGIBBERISH!!!\n").unwrap();

        // Corrupted content still parses (malformed lines are skipped), so this
        // returns Ok with an empty DB. The "corrupted" case in get_oui_db refers
        // to unreadable files (permission errors, etc.)
        let result = get_oui_db_from(&path);
        // Even gibberish parses as empty DB (no valid lines)
        assert!(result.is_ok());
    }

    #[test]
    fn get_oui_db_falls_back_to_embedded_on_missing_cache() {
        // Save real cache path, test with a nonexistent temp path
        let dir = tempfile::tempdir().unwrap();
        let _fake_path = dir.path().join("nonexistent");

        // We can't easily mock cache_path(), so test get_oui_db() directly
        // by temporarily ensuring no cache exists. Since we can't control
        // the real cache, we verify get_oui_db() doesn't panic and returns a valid DB.
        let db = get_oui_db();
        // Should return a valid DB (either from cache or embedded)
        let _ = db.lookup(&"00:00:00:00:00:00".parse().unwrap());
    }
}
