# Tasks: Project Scaffold

## Review Workload Forecast

| Field | Value |
|-------|-------|
| Estimated changed lines | ~340 (20 new files, mostly stubs) |
| 400-line budget risk | Low |
| Chained PRs recommended | No |
| Suggested split | Single PR |
| Delivery strategy | ask-on-risk |
| Chain strategy | pending |

Decision needed before apply: No
Chained PRs recommended: No
Chain strategy: pending
400-line budget risk: Low

## Phase 1: Foundation (19 files)

- [x] 1.1 Create `Cargo.toml` — `name="netascan"`, version=`0.1.0`, deps: clap, tokio(full), serde(derive), thiserror, include_dir!, tera, reqwest
- [x] 1.2 Create `src/main.rs` — entrypoint calling `cli::run()`
- [x] 1.3 Create `src/lib.rs` — 8 `pub mod` declarations: scanner, fingerprint, cve, security, report, server, cli, config
- [x] 1.4 Create `src/error.rs` — `thiserror` enum with `Config(String)` and `Io` variants
- [x] 1.5 Create `src/scanner/mod.rs` — empty stub (doc comment only)
- [x] 1.6 Create `src/fingerprint/mod.rs` — empty stub (doc comment only)
- [x] 1.7 Create `src/cve/mod.rs` — empty stub (doc comment only)
- [x] 1.8 Create `src/security/mod.rs` — empty stub (doc comment only)
- [x] 1.9 Create `src/report/mod.rs` — empty stub (doc comment only)
- [x] 1.10 Create `src/server/mod.rs` — empty stub (doc comment only)
- [x] 1.11 Create `src/cli/mod.rs` — `Clap` struct with `Scan`, `Report`, `Serve`, `Update` subcommands; `run()` async fn
- [x] 1.12 Create `src/config/mod.rs` — `Config` struct (Deserialize), `Default` impl, `load()` fn reading `~/.netascan/config.toml`
- [x] 1.13 Create `tests/integration.rs` — smoke test: `--version` prints `netascan 0.1.0`
- [x] 1.14 Create `benches/benchmark.rs` — criterion placeholder
- [x] 1.15 Create `helper/requirements.txt` — `python-nmap`, `shodan`
- [x] 1.16 Create `helper/nmap_bridge.py` — shebang, docstring, JSON-over-stdio scaffold stub
- [x] 1.17 Create `helper/shodan_check.py` — shebang, docstring, JSON-over-stdio scaffold stub
- [x] 1.18 Create `rustfmt.toml` — `max_width=120`, `edition=2024`
- [x] 1.19 Create `clippy.toml` — pedantic lints config
- [x] 1.20 Create `.gitignore` — `target/`, `*.db`, `.netascan/`

## Phase 2: Config Defaults (1 module)

- [x] 2.1 Add `ScanConfig`, `CveConfig`, `ReportConfig`, `CredentialsCheckConfig` sub-structs to `src/config/mod.rs` per RDP §7; add `#[cfg(test)]` tests for defaults
- [x] 2.2 Add `#[cfg(test)]` in `src/config/mod.rs` — verify `load()` returns defaults when file missing

## Phase 3: CLI Parsing (1 module)

- [x] 3.1 Add `#[cfg(test)]` in `src/cli/mod.rs` — verify all 4 subcommands parse correctly

## Phase 4: Verification

- [x] 4.1 Run `cargo build` — all 20 files compile
- [x] 4.2 Run `cargo test` — zero failures
- [x] 4.3 Run `cargo clippy` — zero warnings
- [x] 4.4 Run `cargo fmt --check` — passes
- [x] 4.5 Run `python3 -m py_compile helper/nmap_bridge.py helper/shodan_check.py` — both pass

---

**Verification summary**: 4 commands (`cargo build && cargo test && cargo clippy && cargo fmt --check`) + Python compile check. All must exit code 0.
