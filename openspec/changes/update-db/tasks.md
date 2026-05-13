# Tasks: update-db

## Review Workload Forecast

| Field | Value |
|-------|-------|
| Estimated changed lines | 180–260 |
| 400-line budget risk | Low |
| Chained PRs recommended | No |
| Suggested split | Single PR |

Decision needed before apply: No
Chained PRs recommended: No
Chain strategy: pending
400-line budget risk: Low

### Suggested Work Units

| Unit | Goal | Likely PR | Notes |
|------|------|-----------|-------|
| 1 | Cache-first OUI init in `oui.rs` | PR 1 | All phases included; standalone deliverable |

## Phase 1: Foundation — Types and Error Variant

- [ ] 1.1 Add `Update(String)` variant to `src/error.rs`
- [ ] 1.2 Add `from_reader(reader: impl Read) -> Result<OuiDb, io::Error>` to `src/scanner/oui.rs` — consume `parse_manuf` via `Cursor::new`
- [ ] 1.3 Add `from_file(path: &Path) -> Result<OuiDb, io::Error>` to `src/scanner/oui.rs` — opens file, calls `from_reader`
- [ ] 1.4 Add `cache_path() -> PathBuf` to `src/scanner/oui.rs` — returns `dirs::cache_dir()/netascan/manuf`
- [ ] 1.5 Add `get_oui_db() -> OuiDb` to `src/scanner/oui.rs` — cache-first, fall back to embedded; log warning on corrupted cache

## Phase 2: Core — OUI_DB Init & Update Command

- [ ] 2.1 Change `OUI_DB` in `src/scanner/oui.rs` to `LazyLock::new(get_oui_db)` (was `from_embedded`)
- [ ] 2.2 Add `UpdateArgs` struct to `src/cli/update.rs` with `source: Option<String>` field
- [ ] 2.3 Add `handle_update(args: &UpdateArgs) -> Result<(), Error>` async to `src/cli/update.rs` — download from `WIRESHARK_MANUF_URL`, write via `.tmp` + rename, print entry count
- [ ] 2.4 Wire `Commands::Update(UpdateArgs)` in `src/cli/mod.rs` — replace stub with `handle_update`
- [ ] 2.5 Add `no_update: bool` field to `ScanArgs` in `src/cli/scan.rs`
- [ ] 2.6 In `src/cli/mod.rs` `Commands::Scan` arm: if `no_update`, call `OuiDb::from_embedded()` directly instead of `&OUI_DB`

## Phase 3: Testing

- [ ] 3.1 RED: write `#[test]` for `from_reader` valid/invalid input in `src/scanner/oui.rs`
- [ ] 3.2 RED: write `#[test]` for `from_file` with `tempfile::tempdir()` in `src/scanner/oui.rs`
- [ ] 3.3 RED: write `#[test]` for `cache_path` asserting `dirs::cache_dir().join("netascan/manuf")`
- [ ] 3.4 RED: write `#[test]` for `get_oui_db` fallback behavior (missing cache → embedded; corrupted → warning + embedded)
- [ ] 3.5 GREEN: implement `from_reader`, `from_file`, `cache_path`, `get_oui_db` to pass tests
- [ ] 3.6 REFACTOR: clean up dead code from `from_embedded` if any duplication remains
- [ ] 3.7 Integration: add `#[tokio::test]` for `handle_update` success with `mockito` fixture
- [ ] 3.8 Integration: add `#[tokio::test]` for `handle_update` failure (500), verify no `.tmp` residue
- [ ] 3.9 CLI: add `assert_cmd` test for `netascan update` — stdout/exit code

## Phase 4: Cleanup

- [ ] 4.1 Remove `#[allow(dead_code)]` on old `UpdateArgs` stub in `src/cli/update.rs`
- [ ] 4.2 Run `cargo test` — all tests pass, no warnings
- [ ] 4.3 Run `cargo clippy -- -D warnings` — zero warnings