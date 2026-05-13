# Design: update-db

## Technical Approach

Replace OUI_DB `LazyLock` init from compile-time-only to cache-first: try `~/.cache/netascan/manuf`, fall back to embedded. Expand `netascan update` stub into an async download handler using `reqwest` with atomic writes. Add `OuiDb::from_reader()` as shared parse entry point for `from_embedded()` and `from_file()`.

## Architecture Decisions

### Decision: OUI DB loading strategy

| Option | Tradeoff | Decision |
|--------|----------|----------|
| Embedded only (current) | Zero I/O, always 6-entry stub | Rejected |
| Cache-first, embedded fallback | Best accuracy, graceful degradation | **Chosen** |
| Download inline on scan startup | Network-dependent scans | Rejected |
| Always download on scan | Latency, fails offline | Rejected |

### Decision: Wireshark manuf URL

| Option | Tradeoff | Decision |
|--------|----------|----------|
| `code.wireshark.org/review/gitweb?...;a=blob_plain;f=manuf` | Official but fragile CGI params | Rejected |
| `gitlab.com/wireshark/wireshark/-/raw/master/manuf` | Stable GitLab raw URL, CDN-backed | **Chosen** |
| Custom mirror `--source` | Flexible but P2 scope | Phase 2 |

### Decision: Cache path

| Option | Tradeoff | Decision |
|--------|----------|----------|
| `~/.cache/netascan/oui/manuf` | Matches CVE subdirectory pattern | Rejected (overly nested) |
| `~/.cache/netascan/manuf` | Flat, consistent with `netascan/cve.db` | **Chosen** |

### Decision: Atomic write

| Option | Tradeoff | Decision |
|--------|----------|----------|
| Write directly | Simple, corrupt on failure | Rejected |
| Write `.tmp` then rename | Atomic, no partial state | **Chosen** |

### Decision: Shared parse entry point

| Option | Tradeoff | Decision |
|--------|----------|----------|
| `from_file(path)` only | Duplicates string-read logic | Rejected |
| `from_reader(impl Read)` | Single parse path for both | **Chosen** |

`from_reader()` consumed by `from_embedded()` (via `Cursor::new`) and `from_file()` (via `File::open`). One parse path, one test set.

## Data Flow

```
netascan update
    ├─ reqwest::get(MANUF_URL) ──→ bytes
    │   ↓ failure → eprintln → exit(1)
    │   ↓ success → fs::write(tmp) → fs::rename(tmp, manuf)
    │               parse_manuf(bytes) → count → println

netascan scan
    ├─ OUI_DB = LazyLock::new(get_oui_db)
    │   cache exists? → from_file(path) → YES
    │   no cache?     → from_embedded()  → YES + tracing::info
    │
    ├─ --no-update? → skip cache, use from_embedded() directly
```

## File Changes

| File | Action | Description |
|------|--------|-------------|
| `src/scanner/oui.rs` | Modify | Add `from_reader()`, `from_file()`, `get_oui_db()`, `cache_path()`; change `OUI_DB` init |
| `src/cli/update.rs` | Modify | Expand stub: `UpdateArgs`, `handle_update()` async, download + atomic write |
| `src/cli/mod.rs` | Modify | Wire `Commands::Update`; add `--no-update` to `ScanArgs` |
| `src/error.rs` | Modify | Add `Update(String)` variant |

## Interfaces / Contracts

```rust
// src/scanner/oui.rs
impl OuiDb {
    pub fn from_reader(reader: impl std::io::Read) -> Result<Self, std::io::Error>;
    pub fn from_file(path: &std::path::Path) -> Result<Self, std::io::Error>;
    pub fn from_embedded() -> Self; // uses from_reader internally
}
pub fn get_oui_db() -> OuiDb;
pub fn cache_path() -> std::path::PathBuf;
pub static OUI_DB: LazyLock<OuiDb> = LazyLock::new(get_oui_db);

// src/cli/update.rs
pub struct UpdateArgs { pub source: Option<String> }
pub async fn handle_update(args: &UpdateArgs) -> Result<(), Error>;
const WIRESHARK_MANUF_URL: &str =
    "https://gitlab.com/wireshark/wireshark/-/raw/master/manuf";

// src/cli/mod.rs — ScanArgs gains:
pub no_update: bool, // --no-update: skip cache, force embedded
```

## Testing Strategy

| Layer | What | How |
|-------|------|-----|
| Unit | `from_reader()` valid/invalid | `#[cfg(test)]` with `Cursor::new` |
| Unit | `from_file()` temp file | `tempfile::tempdir()` |
| Unit | `get_oui_db()` fallback | Mock cache_path to missing dir |
| Unit | `cache_path()` output | Assert matches `dirs::cache_dir().join("netascan/manuf")` |
| Integration | `handle_update()` success | `mockito` returning fixture manuf |
| Integration | `handle_update()` failure | `mockito` returning 500, verify no partial file |
| CLI | `netascan update` end-to-end | `assert_cmd`: check stdout/exit code |
| CLI | `netascan scan --no-update` | Verify embedded DB used when cache exists |

## Migration / Rollout

No migration required. `netascan update` creates `~/.cache/netascan/` if absent. Deleting `~/.cache/netascan/manuf` rolls back to embedded behavior.

## Open Questions

None.