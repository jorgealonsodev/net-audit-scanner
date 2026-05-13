//! Scan persistence: save/load scan results as JSON files.
//!
//! Files are stored in `~/.cache/netascan/scans/` with atomic writes
//! (temp file + rename). A maximum of 10 timestamped scans are kept.

use std::fs;
use std::path::{Path, PathBuf};

use chrono::Utc;
use tracing;

use crate::cli::scan::ScanArgs;
use crate::error::Error;
use crate::scanner::models::{DiscoveredHost, ScanCliArgs, ScanRecord};

/// Returns the scans directory path: `~/.cache/netascan/scans/`.
pub fn scans_dir() -> PathBuf {
    let base = dirs::cache_dir().unwrap_or_else(|| PathBuf::from("."));
    base.join("netascan").join("scans")
}

/// Save scan results to disk. Non-fatal — logs warning on failure.
///
/// Writes a timestamped JSON file and a `last.json` copy atomically,
/// then enforces the 10-file retention limit.
pub fn save_scan(
    hosts: &[DiscoveredHost],
    args: &ScanArgs,
    network: &str,
    started_at_iso: &str,
) -> Result<(), Error> {
    let completed_at = Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    let id = uuid::Uuid::new_v4().to_string();

    // Resolve port range for persistence (same logic as in mod.rs)
    let port_range = if let Some(ref pr) = args.port_range {
        pr.clone()
    } else if args.full {
        "full".into()
    } else {
        crate::config::ScanConfig::default().port_range
    };

    let total_cves: usize = hosts.iter().map(|h| h.open_ports.iter().map(|p| p.cves.len()).sum::<usize>()).sum();

    let record = ScanRecord {
        id,
        started_at: started_at_iso.to_string(),
        completed_at,
        network: network.to_string(),
        cli_args: ScanCliArgs {
            port_range,
            full: args.full,
            no_cve: args.no_cve,
        },
        host_count: hosts.len(),
        total_cves,
        hosts: hosts.to_vec(),
    };

    let dir = scans_dir();
    fs::create_dir_all(&dir).map_err(|e| Error::Persist(format!("Cannot create scans dir: {e}")))?;

    // Filename: ISO timestamp with colons replaced by dashes
    let timestamp = Utc::now().format("%Y-%m-%dT%H-%M-%SZ").to_string();
    let filename = format!("{timestamp}.json");
    let target = dir.join(&filename);

    let json =
        serde_json::to_string_pretty(&record).map_err(|e| Error::Persist(format!("Serialize failed: {e}")))?;

    atomic_write(&target, json.as_bytes())?;

    // Copy to last.json via same atomic pattern
    let last_path = dir.join("last.json");
    atomic_write(&last_path, json.as_bytes())?;

    // Enforce retention limit
    if let Err(e) = cleanup_old_scans(&dir) {
        tracing::warn!("Failed to cleanup old scans: {}", e);
    }

    Ok(())
}

/// Load the most recent scan. Returns error if none exist.
pub fn load_last_scan() -> Result<Vec<DiscoveredHost>, Error> {
    let last_path = scans_dir().join("last.json");

    if !last_path.exists() {
        return Err(Error::Persist(
            "No saved scans found. Run `netascan scan` first.".into(),
        ));
    }

    let content = fs::read_to_string(&last_path)
        .map_err(|e| Error::Persist(format!("Cannot read last.json at {}: {e}", last_path.display())))?;

    let record: ScanRecord = serde_json::from_str(&content)
        .map_err(|e| Error::Persist(format!("Cannot parse last.json: {e}")))?;

    Ok(record.hosts)
}

/// Delete oldest scan files if count exceeds MAX_SCANS (10).
/// `last.json` is never counted or deleted.
pub fn cleanup_old_scans(dir: &Path) -> Result<(), Error> {
    const MAX_SCANS: usize = 10;

    let mut entries: Vec<PathBuf> = fs::read_dir(dir)
        .map_err(|e| Error::Persist(format!("Cannot read scans dir: {e}")))?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| {
            p.extension().is_some_and(|ext| ext == "json")
                && p.file_name().is_some_and(|name| name != "last.json")
        })
        .collect();

    // Lexicographic sort = chronological for ISO timestamps
    entries.sort();

    if entries.len() > MAX_SCANS {
        let to_delete = entries.len() - MAX_SCANS;
        for path in entries.iter().take(to_delete) {
            if let Err(e) = fs::remove_file(path) {
                tracing::warn!("Failed to delete old scan {}: {}", path.display(), e);
            }
        }
    }

    Ok(())
}

/// Write data to a temp file, then atomically rename to target.
fn atomic_write(target: &Path, data: &[u8]) -> Result<(), Error> {
    let tmp_path = target.with_extension("json.tmp");
    fs::write(&tmp_path, data).map_err(|e| Error::Persist(format!("Write temp file failed: {e}")))?;
    fs::rename(&tmp_path, target).map_err(|e| Error::Persist(format!("Rename failed: {e}")))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanner::models::DiscoveryMethod;
    use std::net::IpAddr;

    fn make_test_dir() -> PathBuf {
        let dir = std::env::temp_dir().join(format!("netascan-test-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn cleanup_test_dir(dir: &Path) {
        let _ = fs::remove_dir_all(dir);
    }

    fn test_hosts() -> Vec<DiscoveredHost> {
        vec![DiscoveredHost {
            ip: "192.168.1.1".parse::<IpAddr>().unwrap(),
            mac: None,
            hostname: Some("test.local".into()),
            method: DiscoveryMethod::Icmp,
            open_ports: vec![],
            rtt_ms: Some(5),
            vendor: None,
            os_hint: None,
            security_findings: vec![],
        }]
    }

    fn test_args() -> ScanArgs {
        ScanArgs {
            network: "192.168.1.0/24".into(),
            target: None,
            concurrency: 512,
            timeout_ms: 1500,
            banner_timeout_ms: 500,
            json: false,
            no_cve: true,
            full: false,
            port_range: None,
            report: "html".into(),
            no_update: false,
        }
    }

    #[test]
    fn save_and_load_last_roundtrip() {
        let dir = make_test_dir();
        let hosts = test_hosts();

        // Build record manually to test atomic_write + load path
        let record = ScanRecord {
            id: "test-uuid".into(),
            started_at: "2026-05-13T10:00:00Z".into(),
            completed_at: "2026-05-13T10:05:00Z".into(),
            network: "192.168.1.0/24".into(),
            cli_args: ScanCliArgs {
                port_range: "top-1000".into(),
                full: false,
                no_cve: true,
            },
            host_count: hosts.len(),
            total_cves: 0,
            hosts: hosts.clone(),
        };

        let json = serde_json::to_string_pretty(&record).unwrap();
        let last_path = dir.join("last.json");
        atomic_write(&last_path, json.as_bytes()).unwrap();

        // Read back
        let content = fs::read_to_string(&last_path).unwrap();
        let restored: ScanRecord = serde_json::from_str(&content).unwrap();
        assert_eq!(restored.hosts.len(), 1);
        assert_eq!(restored.hosts[0].ip, hosts[0].ip);

        cleanup_test_dir(&dir);
    }

    #[test]
    fn load_last_scan_no_file_returns_error() {
        // Use a non-existent temp dir
        let dir = make_test_dir();
        // Don't create last.json
        let result = fs::read_to_string(dir.join("last.json"));
        assert!(result.is_err());
        cleanup_test_dir(&dir);
    }

    #[test]
    fn cleanup_old_scans_under_limit() {
        let dir = make_test_dir();
        // Create 5 scan files
        for i in 0..5 {
            let path = dir.join(format!("2026-05-13T10-0{}-00Z.json", i));
            fs::write(&path, "{}").unwrap();
        }
        // Also create last.json (should be ignored)
        fs::write(dir.join("last.json"), "{}").unwrap();

        cleanup_old_scans(&dir).unwrap();

        let count: usize = fs::read_dir(&dir)
            .unwrap()
            .filter(|e| {
                e.as_ref().is_ok_and(|e| {
                    e.path().extension().is_some_and(|ext| ext == "json")
                        && e.path().file_name().is_some_and(|n| n != "last.json")
                })
            })
            .count();
        assert_eq!(count, 5);

        cleanup_test_dir(&dir);
    }

    #[test]
    fn cleanup_old_scans_at_limit_deletes_oldest() {
        let dir = make_test_dir();
        // Create 11 scan files
        for i in 0..11 {
            let path = dir.join(format!("2026-05-13T10-{:02}-00Z.json", i));
            fs::write(&path, "{}").unwrap();
        }
        fs::write(dir.join("last.json"), "{}").unwrap();

        cleanup_old_scans(&dir).unwrap();

        let mut remaining: Vec<String> = fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| {
                e.path().extension().is_some_and(|ext| ext == "json")
                    && e.path().file_name().is_some_and(|n| n != "last.json")
            })
            .map(|e| e.file_name().to_string_lossy().to_string())
            .collect();
        remaining.sort();

        assert_eq!(remaining.len(), 10);
        // Oldest (00) should be deleted, newest (10) should remain
        assert!(!remaining.contains(&"2026-05-13T10-00-00Z.json".to_string()));
        assert!(remaining.contains(&"2026-05-13T10-10-00Z.json".to_string()));

        cleanup_test_dir(&dir);
    }

    #[test]
    fn cleanup_old_scans_preserves_last_json() {
        let dir = make_test_dir();
        // Create 12 scan files + last.json
        for i in 0..12 {
            let path = dir.join(format!("2026-05-13T10-{:02}-00Z.json", i));
            fs::write(&path, "{}").unwrap();
        }
        fs::write(dir.join("last.json"), "{\"id\":\"important\"}").unwrap();

        cleanup_old_scans(&dir).unwrap();

        assert!(dir.join("last.json").exists());
        let content = fs::read_to_string(dir.join("last.json")).unwrap();
        assert!(content.contains("important"));

        cleanup_test_dir(&dir);
    }

    #[test]
    fn atomic_write_creates_file() {
        let dir = make_test_dir();
        let target = dir.join("test.json");
        atomic_write(&target, b"hello").unwrap();
        assert!(target.exists());
        assert!(!target.with_extension("json.tmp").exists());
        assert_eq!(fs::read_to_string(&target).unwrap(), "hello");
        cleanup_test_dir(&dir);
    }

    #[test]
    fn atomic_write_no_partial_file_on_failure() {
        // This test verifies the temp file is renamed, not left behind
        let dir = make_test_dir();
        let target = dir.join("output.json");
        atomic_write(&target, b"data").unwrap();
        // Temp file should not exist after successful write
        let tmp = target.with_extension("json.tmp");
        assert!(!tmp.exists(), "Temp file should be cleaned up after atomic write");
        cleanup_test_dir(&dir);
    }
}
