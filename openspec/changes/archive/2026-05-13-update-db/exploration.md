## Exploration: update-db

### Current State

**OUI Database**:
- Embedded at compile time via `include_dir!("data/manuf")` in `src/scanner/oui.rs`
- Current `data/manuf/manuf` is a **synthetic test file** (6 entries only) — not a real Wireshark database
- Parsed into `OuiDb` with three HashMaps (3/4/5-byte prefixes) via `parse_manuf()`
- Global `OUI_DB: LazyLock<OuiDb>` is initialized once at first use from embedded data
- `OuiDb::from_embedded()` reads from `include_dir` — **compile-time only, no runtime reload**

**CLI**:
- `Commands::Update` exists at `src/cli/mod.rs:131` — currently prints `"update subcommand (stub)"`
- `src/cli/update.rs` has a stub `UpdateArgs` struct (4 lines, `#[allow(dead_code)]`)

**Credential Lists**:
- `src/security/mod.rs` is a 3-line stub: "Implementation pending"
- Config has `CredentialsCheckConfig { enabled: bool, custom_list: String }` but no actual credential data files exist

**Cache Pattern**:
- `cache_dir()` in `cli/mod.rs` uses `dirs::cache_dir()` with CWD fallback
- CVE cache already uses SQLite at `~/.cache/netascan/cve.db` — established pattern
- `reqwest` (v0.12, rustls-tls) is already a dependency — HTTP download capability exists

### Affected Areas
- `src/cli/mod.rs` — dispatch `Commands::Update` to real handler
- `src/cli/update.rs` — expand from stub to full subcommand with args
- `src/scanner/oui.rs` — add `from_file()` constructor + runtime reload capability
- `src/config/mod.rs` — add update-related config section (URLs, cache paths, TTL)
- `src/error.rs` — may need new error variant for download/parse failures
- `data/manuf/manuf` — could remain as compile-time fallback

### Approaches

1. **Download + Cache (runtime override)** — Fetch Wireshark manuf from `https://code.wireshark.org/review/gitweb?p=wireshark.git;a=blob_plain;f=manuf`, save to `~/.cache/netascan/oui/manuf`, and load at runtime if present. Fall back to embedded DB.
   - Pros: Always fresh, offline fallback built-in, follows existing CVE cache pattern
   - Cons: Wireshark URLs have been unreliable (noted in codebase history), needs version/checksum tracking
   - Effort: Medium

2. **User-provided custom file** — Allow `netascan update --file /path/to/manuf` to import a user's own manuf file into cache.
   - Pros: No network dependency, supports offline/corporate environments, simple
   - Cons: User must source the file themselves, no automatic updates
   - Effort: Low

3. **Multi-source with fallback chain** — Try Wireshark primary URL → GitHub mirror → IEEE OUI API → embedded fallback. Cache with version metadata.
   - Pros: Most resilient, handles network failures gracefully
   - Cons: Complex, more maintenance burden, multiple parsers may be needed
   - Effort: High

4. **Hybrid: Download + Custom + Embedded Fallback** — Combine approaches 1+2: `netascan update` downloads from Wireshark (with retry/mirror), `netascan update --file` accepts custom, embedded DB is always the last-resort fallback. Add `netascan update --status` to show cache state.
   - Pros: Covers all use cases, follows CLI best practices, graceful degradation
   - Cons: More subcommand flags, needs careful error handling
   - Effort: Medium-High

### Recommendation

**Approach 4 (Hybrid)** is the right choice. The implementation should be phased:

**Phase 1 (MVP)**:
- `OuiDb::from_file(path)` — load from any file path
- `netascan update` — download from Wireshark URL, save to `~/.cache/netascan/oui/manuf`
- Modify `OUI_DB` initialization: check cache first, fall back to embedded
- Add `--source <url>` flag for custom download URL
- Print success with entry count and timestamp

**Phase 2**:
- `netascan update --file <path>` — import custom manuf
- `netascan update --status` — show cache info (date, entries, source)
- Version/metadata tracking (JSON sidecar: `{ "source": "...", "fetched_at": "...", "entries": N }`)
- Mirror fallback if primary URL fails

**Key design decisions**:
- OUI_DB should become a function `get_oui_db() -> OuiDb` that checks cache → embedded, NOT a static LazyLock (or LazyLock should check cache path)
- Cache path: `~/.cache/netascan/oui/manuf` (consistent with CVE cache at `~/.cache/netascan/cve.db`)
- The embedded synthetic manuf should be replaced with a minimal real subset or kept as compile-time test fixture
- Use `reqwest` (already available) with rustls-tls for downloads

### Risks
- **Wireshark URL stability**: The codebase already notes "Wireshark URLs failed" — need reliable mirror or alternative source
- **Binary size**: Full Wireshark manuf is ~7MB+ — acceptable for CLI tool but worth noting
- **Thread safety**: If `OUI_DB` becomes runtime-reloadable, need `RwLock` or similar for concurrent access
- **Credential lists**: The `update` command mentions credential lists but `src/security/` is entirely stubbed — scope creep risk if not bounded

### Ready for Proposal
Yes — sufficient codebase understanding exists. The orchestrator should tell the user that `update-db` is ready for proposal with a clear MVP scope (download + cache + runtime override) and phased approach.
