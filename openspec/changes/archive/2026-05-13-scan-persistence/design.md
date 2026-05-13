# Design: Scan Persistence

## Architecture

JSON file-based persistence in `~/.cache/netascan/scans/`. No database, no migrations. The existing report engine consumes `Vec<DiscoveredHost>` — we feed it the same data loaded from disk.

## Data Model

### ScanRecord (new struct in `src/scanner/models.rs`)

```rust
pub struct ScanRecord {
    pub id: String,              // UUID v4
    pub started_at: String,      // ISO 8601 UTC
    pub completed_at: String,    // ISO 8601 UTC
    pub network: String,         // CIDR from CLI args
    pub cli_args: ScanCliArgs,   // port_range, full, no_cve
    pub host_count: usize,
    pub total_cves: usize,
    pub hosts: Vec<DiscoveredHost>,
}

pub struct ScanCliArgs {
    pub port_range: String,
    pub full: bool,
    pub no_cve: bool,
}
```

### File Layout

```
~/.cache/netascan/scans/
├── 2026-05-13T10-30-00Z.json   # timestamped scan
├── 2026-05-13T11-00-00Z.json   # timestamped scan
└── last.json                   # copy of most recent
```

## Module Design: `src/cli/persist.rs`

### Public API

```rust
/// Save scan results to disk. Non-fatal — logs warning on failure.
pub async fn save_scan(
    hosts: &[DiscoveredHost],
    args: &ScanArgs,
    network: &str,
    started_at: Instant,
) -> Result<(), Error>;

/// Load the most recent scan. Returns error if none exist.
pub fn load_last_scan() -> Result<Vec<DiscoveredHost>, Error>;
```

### save_scan Flow

1. Build `ScanRecord` from hosts + args + timestamps
2. Ensure `~/.cache/netascan/scans/` directory exists (`create_dir_all`)
3. Generate filename: `<ISO-8601-timestamp>.json` (colons replaced with dashes)
4. Serialize to JSON (`serde_json::to_string_pretty`)
5. **Atomic write**: write to `<filename>.tmp`, then `std::fs::rename` to target
6. Copy to `last.json` via same atomic pattern (temp + rename)
7. Run `cleanup_old_scans()` — list directory, sort by filename, delete oldest beyond 10
8. On any error: `tracing::warn!` and return `Ok(())` (non-blocking)

### load_last_scan Flow

1. Read `~/.cache/netascan/scans/last.json`
2. If file missing → `Error::Persist("No saved scans found...")`
3. Deserialize to `ScanRecord`
4. Return `record.hosts`

### cleanup_old_scans Flow

1. Read directory entries, filter `*.json`, exclude `last.json`
2. Sort by filename (lexicographic = chronological for ISO timestamps)
3. If count > 10, delete oldest N-10 files
4. Log warning on individual deletion failures, continue

## Integration Points

### `src/cli/mod.rs` (scan handler)

After CVE enrichment (line ~121), before output (line ~124):

```rust
let started_at = std::time::Instant::now();
// ... existing scan logic ...

// Persist scan results (non-fatal)
if let Err(e) = persist::save_scan(&hosts, &args, &args.network, started_at).await {
    tracing::warn!("Failed to persist scan results: {}", e);
}

// ... existing output logic ...
```

### `src/cli/report.rs` (--last handler)

Replace the stub at line 56-59:

```rust
if args.last {
    let hosts = persist::load_last_scan()?;
    let engine = ReportEngine::new().map_err(|e| Error::Template(e.to_string()))?;
    let ctx = crate::report::ReportContext::from(&hosts);
    // ... existing format dispatch ...
}
```

### `src/error.rs`

Add new variant:

```rust
#[error("Persist error: {0}")]
Persist(String),
```

## Timing Capture

`started_at` is captured before the scan begins in `mod.rs` (existing code already has the timing). `completed_at` is computed at save time. Both stored as ISO 8601 strings in the `ScanRecord`.

## Concurrency Safety

- Atomic write via temp+rename prevents partial files
- `last.json` is overwritten on each save — last writer wins (acceptable for MVP)
- No file locking needed: scans are CLI-invoked, not daemonized

## Disk Space Budget

- Typical /24 scan: ~5-50 hosts → 5-50 KB JSON
- Max 10 files → ~500 KB worst case
- Negligible for modern systems

## Why Not SQLite

SQLite was considered (already a dependency via sqlx for CVE cache) but rejected for MVP because:
1. The immediate need is "save last scan" — JSON solves this in ~50 lines
2. Existing report engine already consumes JSON — zero integration friction
3. JSON files are portable, human-readable, debuggable with `cat`/`jq`
4. Migration path to SQLite exists if query needs emerge later
