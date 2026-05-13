## Exploration: scan-persistence

### Current State

The scan pipeline in `src/cli/mod.rs` (lines 40-129) produces `Vec<DiscoveredHost>`, formats it as a table or JSON to stdout, and then the data is **completely lost**. There is zero persistence between scans.

The `report` subcommand (`src/cli/report.rs`) has a `--last` flag that currently prints `"not yet implemented"` (line 57). The report engine can generate HTML/JSON from input files or stdin, but has no way to automatically find the most recent scan.

SQLite is already a dependency (sqlx 0.7) used exclusively for the CVE cache (`src/cve/cache.rs`). The CVE cache uses a single-table schema (`cve_cache`) with JSON-serialized responses.

The `DiscoveredHost` model (`src/scanner/models.rs`) is fully serializable via serde. It contains: IP, MAC, hostname, discovery method, open ports (with service, banner, CVEs), RTT, and vendor.

The server module (`src/server/mod.rs`) accepts JSON scan uploads via POST /report but does not persist them either.

Config lives at `~/.netascan/config.toml`. Cache directory uses `dirs::cache_dir()`.

### Affected Areas

- `src/cli/mod.rs` — scan handler dispatch; needs persistence call after scan completes
- `src/cli/report.rs` — `--last` flag implementation; needs to locate most recent scan
- `src/cli/persist.rs` — NEW module for scan persistence logic
- `src/error.rs` — may need a `Persist` or `Storage` error variant
- `src/scanner/models.rs` — `DiscoveredHost` already serializable; may need a `ScanRecord` wrapper

### Approaches

#### 1. JSON Files in `~/.cache/netascan/scans/` (Recommended for MVP)
Each scan saved as `<timestamp>.json`. `last.json` is a copy/symlink to most recent.

- **Pros**: Zero schema complexity, human-readable, portable, no DB migration, aligns with existing JSON output, easy to debug, `--last` is trivial (read `last.json`)
- **Cons**: No structured querying (by date range, network, etc.), file I/O for large scans, no atomic transactions
- **Effort**: Low

#### 2. SQLite in Existing CVE Cache DB
Add `scan_runs` table to the same `cve.db` file.

- **Pros**: Single storage file, structured querying, atomic writes, consistent with existing pattern
- **Cons**: Mixes concerns (cache vs. user data), harder to inspect/debug, requires sqlx migrations, overkill for MVP
- **Effort**: Medium

#### 3. SQLite in Separate Scan DB
New `scans.db` file with full relational schema (scan_runs, hosts, ports, cves).

- **Pros**: Full queryability, normalized data, future-proof for dashboard/history features
- **Cons**: Highest complexity, requires schema design + migrations, over-engineered for "save last scan"
- **Effort**: High

### Recommendation

**Approach 1 (JSON files)** for MVP. Rationale:
- The immediate need is "save last scan + `--last` flag works" — JSON files solve this in ~50 lines
- The existing report engine already consumes JSON — zero integration friction
- JSON files are portable: users can share, backup, or pipe them
- Future migration to SQLite is straightforward if query needs emerge
- Follows the Unix philosophy: simple text files, composable tools

**Proposed schema per file** (`~/.cache/netascan/scans/<timestamp>.json`):
```json
{
  "id": "uuid-or-timestamp",
  "started_at": "2026-05-13T10:30:00Z",
  "completed_at": "2026-05-13T10:32:15Z",
  "network": "192.168.1.0/24",
  "cli_args": { "port_range": "top-1000", "full": false, "no_cve": false },
  "host_count": 5,
  "total_cves": 3,
  "hosts": [ ... DiscoveredHost[] ... ]
}
```

Also maintain `last.json` as a copy of the most recent scan for O(1) `--last` access.

### Integration Point

In `src/cli/mod.rs`, after the CVE enrichment block (line 121) and before output (line 124):
```rust
// Persist scan results
persist::save_scan(&hosts, &args).await?;
```

The `--last` flag in `src/cli/report.rs` becomes:
```rust
if args.last {
    let hosts = persist::load_last_scan()?;
    // ... generate report from hosts
}
```

### MVP Scope

- Save last N scans as timestamped JSON files (configurable, default 10)
- `netascan report --last` loads most recent scan
- `netascan report --last --format json` for JSON output
- Cleanup: auto-delete oldest scans beyond N
- No CLI flag to list history (future enhancement)
- No `--scan-id` to load specific scan (future enhancement)

### Risks

- **Large scan files**: Full /16 network scans could produce large JSON. Mitigation: N limit + potential future compression
- **Concurrent scans**: Two simultaneous scans could race on `last.json`. Mitigation: atomic write (write to temp, rename)
- **Disk space**: Unbounded growth if N is not enforced. Mitigation: cleanup on save
- **Missing CVE data**: If `--no-cve` is used, the saved scan has no CVEs. This is expected behavior — the scan reflects what was actually run.

### Ready for Proposal

**Yes.** The exploration is complete with a clear recommendation (JSON files), integration points identified, MVP scope defined, and risks assessed. The orchestrator should proceed to `sdd-propose` to create a formal change proposal, then `sdd-spec` for requirements, and `sdd-tasks` for implementation breakdown.
