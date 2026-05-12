# Proposal: Project Scaffold

## Intent

Establish the foundational project structure for `netascan` — a Rust + Python network security audit CLI. This is the FIRST change: it creates a compilable skeleton with all dependencies, module declarations, config loading infrastructure, and tooling config. No business logic.

## Scope

### In Scope
- `Cargo.toml` with all dependencies from RDP_netascan.md (tokio, pnet, reqwest, sqlx, clap, serde, tera, axum, tracing, thiserror, ipnetwork, macaddr, dirs, toml, chrono, anyhow)
- Directory structure: `src/`, `helper/`, `tests/`, `benches/`
- `src/main.rs` — minimal CLI with `--version` and `--help` via clap
- Module declarations: `scanner`, `fingerprint`, `cve`, `security`, `report`, `server`, `cli`, `config` (all empty `mod.rs` files)
- Config loading skeleton: `~/.netascan/config.toml` parsing with serde
- Testing infrastructure: `clippy.toml`, `rustfmt.toml`, `.gitignore`
- Python helper skeleton: `helper/requirements.txt`, `helper/nmap_bridge.py`, `helper/shodan_check.py`

### Out of Scope
- Actual scanning logic (network discovery, port scanning)
- CVE correlation, fingerprinting, security checks
- Report generation, web server
- Packaging (.deb, .rpm, AUR)

## Capabilities

### New Capabilities
- `project-scaffold`: Initial Rust crate structure, CLI skeleton, config loading, Python helper stubs, tooling configuration

### Modified Capabilities
- None

## Approach

Single binary crate `netascan` with internal modules. CLI uses clap derive macros. Config parsed from `~/.netascan/config.toml` via `dirs` + `toml` + `serde`. All modules declared as `pub mod` with empty implementations — compilation passes but no functionality beyond `--version`/`--help`. Python helpers are stubs with proper shebang and docstrings.

## Affected Areas

| Area | Impact | Description |
|------|--------|-------------|
| `Cargo.toml` | New | Crate manifest with all dependencies |
| `src/main.rs` | New | Entry point, clap CLI, version string |
| `src/cli/mod.rs` | New | CLI module declaration (empty) |
| `src/config/mod.rs` | New | Config loading skeleton |
| `src/scanner/mod.rs` | New | Scanner module declaration (empty) |
| `src/fingerprint/mod.rs` | New | Fingerprint module declaration (empty) |
| `src/cve/mod.rs` | New | CVE module declaration (empty) |
| `src/security/mod.rs` | New | Security module declaration (empty) |
| `src/report/mod.rs` | New | Report module declaration (empty) |
| `src/server/mod.rs` | New | Server module declaration (empty) |
| `helper/requirements.txt` | New | Python dependencies |
| `helper/nmap_bridge.py` | New | Nmap bridge stub |
| `helper/shodan_check.py` | New | Shodan check stub |
| `clippy.toml` | New | Clippy configuration |
| `rustfmt.toml` | New | Rustfmt configuration |
| `.gitignore` | New | Git ignore patterns |

## Risks

| Risk | Likelihood | Mitigation |
|------|------------|------------|
| Dependency version conflicts | Low | Use latest stable versions, cargo update after init |
| pnet requires libpcap dev headers on some distros | Medium | Document in README; not a blocker for compilation |
| Oversized initial commit | Medium | Split into 2-3 work units: (1) Cargo.toml + main.rs, (2) modules + config, (3) tooling + Python |

## Rollback Plan

Delete all created files and revert the initial commit. Since this is the first commit with no downstream dependencies, a simple `git reset --hard` or branch deletion fully rolls back.

## Dependencies

- Rust toolchain (stable)
- Python 3.10+ (for helper stubs)
- `libpcap-dev` / `libpcap-devel` system package (for pnet compilation)

## Success Criteria

- [ ] `cargo build` succeeds with zero errors
- [ ] `cargo run -- --version` prints version string
- [ ] `cargo run -- --help` shows CLI help with subcommands
- [ ] `cargo clippy` passes with zero warnings
- [ ] `cargo fmt --check` passes
- [ ] Python stubs are syntactically valid (`python3 -m py_compile`)
