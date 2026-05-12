# Project Scaffold Specification

## Purpose

Foundation for the `netascan` Rust+Python CLI. Establishes compilable skeleton, module declarations, config loading, tooling, and Python helper stubs. Zero business logic.

## Requirements

### Requirement: Cargo.toml with All Dependencies (REQ-SCAF-1)

The crate manifest MUST declare all dependencies from RDP §10 with correct versions and feature flags. `tokio` MUST include `full` features. `serde` MUST include `derive`. `reqwest` MUST NOT require default TLS features if rustls is used. The crate version MUST be `0.1.0`. The binary name MUST be `netascan`.

**Priority**: P1 | **Depends on**: None

#### Scenario: Build resolves all dependencies

- GIVEN a clean Rust toolchain with `libpcap-dev` installed
- WHEN `cargo build` is executed
- THEN all dependencies resolve and compile without errors

#### Scenario: Version and binary name are correct

- GIVEN the compiled binary
- WHEN `cargo run -- --version` is executed
- THEN the output starts with `netascan 0.1.0`

---

### Requirement: Directory Structure (REQ-SCAF-2)

The project MUST contain: `src/` with `main.rs` and `lib.rs`, `src/{scanner,fingerprint,cve,security,report,server,cli,config}/mod.rs`, `helper/`, `tests/`, `benches/`. Each subdirectory `src/{module}/` MUST contain a `mod.rs` file. `tests/` and `benches/` MUST each contain at least one placeholder file.

**Priority**: P1 | **Depends on**: None

#### Scenario: All directories and module files exist

- GIVEN the project root
- WHEN listing the directory tree
- THEN all required directories and `mod.rs` files exist under `src/`, and `tests/` and `benches/` contain at least one `.rs` file each

---

### Requirement: Minimal main.rs (REQ-SCAF-3)

`main.rs` MUST compile and expose a clap-based CLI with `--version` and `--help`. The CLI MUST define subcommand stubs for `scan`, `report`, `serve`, and `update`. The entrypoint MUST call `cli::run()`.

**Priority**: P1 | **Depends on**: REQ-SCAF-1, REQ-SCAF-2

#### Scenario: Help shows subcommands

- GIVEN the compiled binary
- WHEN `netascan --help` is executed
- THEN the output lists subcommands: `scan`, `report`, `serve`, `update`

#### Scenario: Version flag works

- GIVEN the compiled binary
- WHEN `netascan --version` is executed
- THEN the output matches `netascan 0.1.0`

---

### Requirement: Module Declarations (REQ-SCAF-4)

`lib.rs` MUST declare `pub mod` for all eight modules: `scanner`, `fingerprint`, `cve`, `security`, `report`, `server`, `cli`, `config`. Each `mod.rs` MUST compile (empty body or doc comment only). The crate MUST export modules publicly so integration tests can reach them.

**Priority**: P1 | **Depends on**: REQ-SCAF-2

#### Scenario: All modules compile and are reachable

- GIVEN the project structure
- WHEN `cargo build` is executed
- THEN all eight modules compile and are accessible via `netascan::scanner`, etc.

---

### Requirement: Config Skeleton (REQ-SCAF-5)

`config.rs` (via `config/mod.rs`) MUST define a `Config` struct deserializable from `~/.netascan/config.toml` using `serde`. It MUST provide sensible defaults matching RDP §7 (scan, cve, report, credentials_check sections). If the config file is missing, `Config::load()` MUST return defaults without error.

**Priority**: P2 | **Depends on**: REQ-SCAF-1, REQ-SCAF-4

#### Scenario: Load config from file

- GIVEN `~/.netascan/config.toml` exists with `[scan] default_network = "192.168.0.0/24"`
- WHEN `Config::load()` is called
- THEN the returned `Config` has `scan.default_network` equal to `"192.168.0.0/24"`

#### Scenario: Default config when file missing

- GIVEN no `~/.netascan/config.toml` exists
- WHEN `Config::load()` is called
- THEN a `Config` with all default values is returned, with `scan.default_network = "auto"`

---

### Requirement: Testing Infrastructure (REQ-SCAF-6)

The project MUST include `rustfmt.toml`, `clippy.toml`, and `.gitignore`. `cargo test` MUST pass with zero failures. `cargo clippy` MUST produce zero warnings. `cargo fmt --check` MUST pass.

**Priority**: P1 | **Depends on**: REQ-SCAF-3, REQ-SCAF-4

#### Scenario: CI checks pass

- GIVEN the project scaffold
- WHEN `cargo test && cargo clippy && cargo fmt --check` is executed
- THEN all commands exit with code 0

---

### Requirement: Python Helper Structure (REQ-SCAF-7)

`helper/` MUST contain `requirements.txt` (with `python-nmap` and `shodan`), `nmap_bridge.py`, and `shodan_check.py`. Each `.py` file MUST have a shebang line, module docstring, and a syntactically valid function stub. `python3 -m py_compile` MUST pass for each file.

**Priority**: P2 | **Depends on**: None

#### Scenario: Python stubs are syntactically valid

- GIVEN the `helper/` directory
- WHEN `python3 -m py_compile helper/nmap_bridge.py` and `python3 -m py_compile helper/shodan_check.py` are executed
- THEN both compile without syntax errors

---

### Requirement: Strict TDD Ready (REQ-SCAF-8)

When this change is applied, `cargo test` MUST pass. The project MUST be ready for strict TDD: `#[cfg(test)]` modules exist where needed, `tests/` integration test placeholder compiles, and `cargo test` exit code is 0.

**Priority**: P1 | **Depends on**: REQ-SCAF-3, REQ-SCAF-4, REQ-SCAF-6

#### Scenario: TDD cycle works

- GIVEN the project after this change
- WHEN a developer writes a failing test and runs `cargo test`
- THEN the test is discovered and reported as failed (not a compilation error)