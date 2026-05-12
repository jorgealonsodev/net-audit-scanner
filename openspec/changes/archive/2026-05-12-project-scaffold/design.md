# Design: Project Scaffold

## Technical Approach

Single binary crate `netascan` (lib + bin) with `lib.rs` declaring eight public modules. `main.rs` delegates to `cli::run()` which parses clap subcommands and dispatches. Config loads from `~/.netascan/config.toml` via serde/toml with Default fallback. Python helpers communicate via JSON-over-stdin/stdout. All modules start as empty stubs that compile. Async runtime is tokio multi-threaded, initialized lazily via `OnceCell` for config.

## Architecture Decisions

### Decision: Single crate vs workspace

| Option | Tradeoff | Decision |
|--------|----------|----------|
| Single crate | Simple Cargo.toml, fast compile, easy refactoring | Chosen |
| Workspace (multi-crate) | Better isolation, parallel builds, but premature complexity | Rejected |

**Rationale**: At v0.1.0 with zero business logic, splitting into workspace members adds overhead with no benefit. Refactor to workspace when modules stabilize.

### Decision: Config path resolution

| Option | Tradeoff | Decision |
|--------|----------|----------|
| `$HOME/.netascan/config.toml` | Matches RDP §7, simple, Linux-standard | Chosen |
| XDG `~/.config/netascan/` | XDG-compliant, but conflicts with RDP | Rejected (defer) |

**Rationale**: RDP explicitly specifies `~/.netascan/`. Use `std::env::var("HOME")` (Linux-only per RDP). XDG fallback can be added later without breaking changes.

### Decision: Error handling

| Option | Tradeoff | Decision |
|--------|----------|----------|
| `thiserror` enum with `#[from]` | Structured, typed, caller-matchable | Chosen |
| `anyhow` everywhere | Flexible, but loses type info for library consumers | Rejected |

**Rationale**: Library crate needs typed errors callers can match on. Binary top-level can convert to exit codes. `anyhow` may be added later for `main.rs` ergonomics.

### Decision: Python bridge protocol

| Option | Tradeoff | Decision |
|--------|----------|----------|
| JSON over stdin/stdout | Simple, debuggable, language-agnostic | Chosen |
| gRPC | Type-safe, but over-engineered for subprocess bridge | Rejected |
| MessagePack | Binary, faster, but harder to debug | Rejected |

**Rationale**: Rust spawns Python as subprocess. Newline-delimited JSON: one request object in, one response object out. Debuggable with `print()`, no extra deps.

### Decision: Template embedding

| Option | Tradeoff | Decision |
|--------|----------|----------|
| `include_dir!` + tera | Compile-time embedded, single-binary distribution | Chosen |
| Filesystem templates | Easy iteration, but requires files deployed alongside binary | Rejected |

**Rationale**: Single-binary distribution is a design goal (RDP §3: "binario único, sin dependencias"). Templates embed at compile time.

### Decision: Async runtime initialization

| Option | Tradeoff | Decision |
|--------|----------|----------|
| tokio multi-threaded + `OnceCell<Config>` | Full async, lazy config, concurrent scanning ready | Chosen |
| tokio current-thread | Simpler, but can't scale to concurrent port scanning | Rejected |

**Rationale**: Network scanning demands concurrent I/O. Config loads once at startup into `OnceCell`, shared across tasks without locks.

## Data Flow

```
CLI (clap) ──parse──→ cli::run()
                         │
                    Config::load()
                    (OnceCell<Config>)
                         │
              ┌──────────┼──────────┐
              ▼          ▼          ▼
          scan       report      serve ──→ axum
              │          │
              ▼          ▼
    Python bridge   tera templates
    (stdin/stdout)   (include_dir!)
```

## File Changes

| File | Action | Description |
|------|--------|-------------|
| `Cargo.toml` | Create | Crate manifest: `name="netascan"`, version `0.1.0`, all deps |
| `src/main.rs` | Create | Entrypoint, `cli::run()` dispatch |
| `src/lib.rs` | Create | 8 `pub mod` declarations |
| `src/error.rs` | Create | `thiserror` error enum (`Config`, `Io` variants) |
| `src/cli/mod.rs` | Create | Clap derive: `Cli` enum with `Scan`, `Report`, `Serve`, `Update` |
| `src/config/mod.rs` | Create | `Config` struct + `Default` impl + `load()` |
| `src/scanner/mod.rs` | Create | Empty stub (doc comment) |
| `src/fingerprint/mod.rs` | Create | Empty stub (doc comment) |
| `src/cve/mod.rs` | Create | Empty stub (doc comment) |
| `src/security/mod.rs` | Create | Empty stub (doc comment) |
| `src/report/mod.rs` | Create | Empty stub (doc comment) |
| `src/server/mod.rs` | Create | Empty stub (doc comment) |
| `tests/integration.rs` | Create | Placeholder: `--version` smoke test |
| `benches/benchmark.rs` | Create | Placeholder (criterion ready) |
| `helper/requirements.txt` | Create | `python-nmap`, `shodan` |
| `helper/nmap_bridge.py` | Create | Stub: shebang, docstring, JSON protocol scaffold |
| `helper/shodan_check.py` | Create | Stub: shebang, docstring, JSON protocol scaffold |
| `clippy.toml` | Create | Pedantic lints config |
| `rustfmt.toml` | Create | `max_width=120`, `edition=2024` |
| `.gitignore` | Create | `target/`, `*.db`, `.netascan/` data dirs |

## Interfaces / Contracts

```rust
// src/config/mod.rs
#[derive(Debug, Deserialize)]
pub struct Config {
    pub scan: ScanConfig,         // default_network, port_range, timeout_ms, concurrency
    pub cve: CveConfig,           // nvd_api_key, sources, cache_ttl_hours
    pub report: ReportConfig,     // default_format, open_browser
    pub credentials_check: CredentialsCheckConfig,  // enabled, custom_list
}
impl Config {
    pub fn load() -> Result<Self, Error> { /* resolve path, parse TOML, fallback Default */ }
}

// src/cli/mod.rs
#[derive(Parser)]
#[command(name = "netascan", version)]
enum Cli {
    Scan(ScanArgs), Report(ReportArgs), Serve(ServeArgs), Update,
}
pub async fn run() -> Result<(), Error> { /* parse, load config, dispatch */ }

// src/error.rs
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Config error: {0}")] Config(String),
    #[error(transparent)] Io(#[from] std::io::Error),
}

// Python bridge: newline-delimited JSON over stdio
// Request:  {"method": "nmap_scan", "args": {"target": "..."}}
// Response: {"status": "ok", "data": {...}}
```

## Testing Strategy

| Layer | What | Approach |
|-------|------|----------|
| Unit | Config `Default` values match RDP §7 | `#[cfg(test)]` in `config/mod.rs` |
| Unit | Config `load()` returns defaults when file missing | `#[cfg(test)]` in `config/mod.rs` |
| Unit | CLI parsing all 4 subcommands | `#[cfg(test)]` in `cli/mod.rs` |
| Integration | `--version` prints `netascan 0.1.0` | `tests/integration.rs` with `assert_cmd` |
| Integration | Module reachability (`netascan::scanner` etc.) | `tests/integration.rs` |

Mock-free: no external calls exist in scaffold code.

## Migration / Rollback

No migration required. First commit on greenfield project. Rollback: `git reset --hard`.

## Open Questions

- [ ] Confirm `dirs` vs raw `$HOME` for config path — leaning toward `std::env::var("HOME")` now, XDG support later
- [ ] Decide if `include_dir!` templates directory (`src/templates/`) should be created now or deferred to report module work