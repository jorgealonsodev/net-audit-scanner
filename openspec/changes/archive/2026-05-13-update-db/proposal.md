# Proposal: update-db

## Intent

The `netascan update` subcommand is a stub. The OUI database used for vendor fingerprinting is a synthetic 6-entry test file embedded at compile time. Users need a way to download the real Wireshark manuf database so OUI lookups return accurate vendor names.

## Scope

### In Scope
- `netascan update` downloads Wireshark manuf from canonical URL and caches to `~/.cache/netascan/oui/manuf`
- `OuiDb::from_file(path)` constructor for runtime file loading
- `OUI_DB` initialization checks cache first, falls back to embedded DB
- Embedded `data/manuf/manuf` remains as compile-time fallback (synthetic fixture)
- `reqwest` (already available, rustls-tls) used for HTTP download

### Out of Scope
- `--file` flag for custom manuf import (Phase 2)
- `--status` flag for cache inspection (Phase 2)
- Multi-source mirror fallback chain (Phase 2)
- Credential list downloads (separate concern, `src/security/` is fully stubbed)
- Version/metadata sidecar tracking (Phase 2)

## Capabilities

### New Capabilities
- `oui-database-update`: Download, cache, and runtime-load of Wireshark manuf database with embedded fallback

### Modified Capabilities
- `oui-fingerprint`: REQ-OUI-1 changes from "compile-time only via `include_dir`" to "cache-first with embedded fallback"

## Approach

1. Add `OuiDb::from_file(path)` in `src/scanner/oui.rs` — reuses existing `parse_manuf()` logic
2. Create `get_oui_db() -> OuiDb` function: tries `~/.cache/netascan/oui/manuf` → falls back to `OuiDb::from_embedded()`
3. Replace global `OUI_DB: LazyLock<OuiDb>` with `OUI_DB: LazyLock<OuiDb>` initialized via `get_oui_db()`
4. Expand `src/cli/update.rs` with `UpdateArgs` containing optional `--source <url>` flag (default: Wireshark canonical URL)
5. Wire `Commands::Update` dispatch in `src/cli/mod.rs` to call download → save → reload flow
6. Download saves to cache dir, prints entry count and source URL on success

## Affected Areas

| Area | Impact | Description |
|------|--------|-------------|
| `src/scanner/oui.rs` | Modified | Add `from_file()`, change init to cache-first |
| `src/cli/update.rs` | Modified | Expand stub to full download handler |
| `src/cli/mod.rs` | Modified | Dispatch `Commands::Update` to real handler |
| `src/error.rs` | Modified | Add download/parse error variant |
| `~/.cache/netascan/oui/manuf` | New | Runtime cache path for downloaded manuf |

## Risks

| Risk | Likelihood | Mitigation |
|------|------------|------------|
| Wireshark URL unstable or unreachable | Medium | `--source` flag lets users specify mirror; embedded fallback always works |
| Large manuf file (~7MB) increases binary if embedded | Low | Embedded file stays synthetic (6 entries); real DB lives in cache only |
| Concurrent `update` + `scan` race on OUI_DB | Low | `LazyLock` initializes once; update replaces cache file atomically (write to temp + rename) |
| Network unavailable in air-gapped environments | Medium | Embedded fallback ensures tool still works; update fails gracefully with clear message |

## Rollback Plan

1. `git revert` the change commit
2. Delete `~/.cache/netascan/oui/manuf` to force embedded fallback
3. No database migration or external state to clean up

## Dependencies

- `reqwest` v0.12 with rustls-tls (already in `Cargo.toml`)
- `dirs` crate for cache directory (already in use)
- Wireshark manuf URL: `https://code.wireshark.org/review/gitweb?p=wireshark.git;a=blob_plain;f=manuf`

## Success Criteria

- [ ] `netascan update` downloads real manuf file to `~/.cache/netascan/oui/manuf`
- [ ] Subsequent `netascan scan` uses cached DB (not embedded) for OUI lookups
- [ ] With cache deleted, tool falls back to embedded DB without error
- [ ] `cargo test` passes with zero failures
- [ ] `cargo clippy` produces zero warnings
