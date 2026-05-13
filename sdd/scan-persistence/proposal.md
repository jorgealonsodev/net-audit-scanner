# Proposal: Scan Persistence

## Intent

Scan results are lost after CLI output. `netascan report --last` prints "not yet implemented". Users cannot re-generate reports or review past scans without re-running the full scan. This change adds automatic JSON persistence of scan results and wires `--last` to load the most recent scan.

## Scope

### In Scope
- Auto-save scan results as timestamped JSON files in `~/.cache/netascan/scans/`
- `--last` flag loads most recent scan and passes to report engine
- Cleanup old scans, keeping last 10 by default
- Atomic writes (temp file + rename) to prevent corruption

### Out of Scope
- CLI flag to list scan history (`netascan report --list`)
- `--scan-id` to load a specific historical scan
- SQLite migration or structured querying
- Compression of large scan files

## Capabilities

### New Capabilities
- `scan-persistence`: Auto-save and retrieval of completed scan results as JSON files

### Modified Capabilities
- `report-generation`: `--last` changes from "not yet implemented" to loading most recent persisted scan

## Approach

JSON files per scan in `~/.cache/netascan/scans/<timestamp>.json`. Each file wraps `Vec<DiscoveredHost>` with metadata (id, timestamps, network, cli_args, counts). A `last.json` symlink/copy provides O(1) access for `--last`. Cleanup runs on every save, deleting oldest files beyond N=10. Atomic write via temp file + `std::fs::rename`.

## Affected Areas

| Area | Impact | Description |
|------|--------|-------------|
| `src/cli/mod.rs` | Modified | Call `persist::save_scan()` after CVE enrichment, before output |
| `src/cli/report.rs` | Modified | `--last` loads from `persist::load_last_scan()` instead of stub |
| `src/cli/persist.rs` | New | Scan persistence module: save, load, cleanup |
| `src/error.rs` | Modified | Add `Persist` error variant |
| `src/scanner/models.rs` | Modified | Add `ScanRecord` wrapper struct |

## Risks

| Risk | Likelihood | Mitigation |
|------|------------|------------|
| Large scan files (/16 networks) | Low | N=10 limit caps disk; future compression if needed |
| Concurrent scan race on `last.json` | Low | Atomic rename prevents partial writes |
| Disk space unbounded | Low | Cleanup enforces max N on every save |

## Rollback Plan

Revert the commit. The scan CLI continues to work normally (output to stdout only). `--last` returns to "not yet implemented" behavior. Existing JSON files in `~/.cache/netascan/scans/` are harmless orphan files that can be manually deleted.

## Dependencies

- None — uses existing `serde`, `serde_json`, `dirs`, `std::fs`

## Success Criteria

- [ ] `netascan scan --network 192.168.1.0/24` creates a JSON file in `~/.cache/netascan/scans/`
- [ ] `netascan report --last` generates an HTML report from the most recent scan
- [ ] `netascan report --last --format json` outputs JSON from the most recent scan
- [ ] More than 10 scans triggers automatic cleanup of oldest files
- [ ] Concurrent scans do not corrupt `last.json`
