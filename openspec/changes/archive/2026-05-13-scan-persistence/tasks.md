# Tasks: Scan Persistence

## Review Workload Forecast

| Field | Value |
|-------|-------|
| Estimated changed lines | ~150–200 |
| 400-line budget risk | Low |
| Chained PRs recommended | No |
| Suggested split | Single PR |
| Delivery strategy | auto-chain |
| Chain strategy | stacked-to-main |

Decision needed before apply: No
Chained PRs recommended: No
Chain strategy: stacked-to-main
400-line budget risk: Low

## Phase 1: Data Model

- [ ] 1.1 Add `Persist(String)` variant to `src/error.rs` with `#[error("Persist error: {0}")]`
- [ ] 1.2 Add `ScanCliArgs` and `ScanRecord` structs to `src/scanner/models.rs` with serde derive

## Phase 2: Persistence Module

- [ ] 2.1 Create `src/cli/persist.rs` with `save_scan()`, `load_last_scan()`, `cleanup_old_scans()`, and `scans_dir()` helpers
- [ ] 2.2 Add `mod persist;` and `pub mod persist;` to `src/cli/mod.rs`

## Phase 3: Integration

- [ ] 3.1 In `src/cli/mod.rs` scan handler: capture `started_at` before discovery, call `persist::save_scan()` after CVE enrichment (line ~121), before output
- [ ] 3.2 In `src/cli/report.rs` `handle_report()`: replace stub at lines 56–59 with `persist::load_last_scan()` call, pass resulting `Vec<DiscoveredHost>` to report engine

## Phase 4: Testing

- [ ] 4.1 Write unit tests for `ScanRecord` serialization round-trip in `src/scanner/models.rs`
- [ ] 4.2 Write unit tests for `save_scan` and `load_last_scan` in `src/cli/persist.rs`
- [ ] 4.3 Write unit tests for `cleanup_old_scans` (under 10 files, at limit, preserves `last.json`)
- [ ] 4.4 Run `cargo test` — all tests must pass

## Phase 5: Verification

- [ ] 5.1 Run `cargo clippy -- -D warnings` — no warnings
- [ ] 5.2 Manual smoke test: `netascan scan --network 192.168.1.0/24 --no-cve`, verify `~/.cache/netascan/scans/` contains timestamped JSON and `last.json`
- [ ] 5.3 Manual smoke test: `netascan report --last --format html`, verify report renders from saved scan