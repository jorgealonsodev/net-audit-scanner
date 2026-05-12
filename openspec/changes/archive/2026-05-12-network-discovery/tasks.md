# Tasks: network-discovery

## Review Workload Forecast

| Field | Value |
|-------|-------|
| Estimated changed lines | ~800 total (~560 additions, ~240 deletions of stub) |
| 400-line budget risk | Medium |
| Chained PRs recommended | Yes |
| Suggested split | PR 1 → PR 2 → PR 3 |
| Delivery strategy | ask-on-risk |
| Chain strategy | pending — decision needed before apply |

Decision needed before apply: Yes
Chained PRs recommended: Yes
Chain strategy: stacked-to-main|feature-branch-chain|size-exception|pending
400-line budget risk: Medium

## Phase 1: Foundation — Models + Error Types

### Work Unit: PR 1 — `models.rs` + `capabilities.rs` + error variants

**Goal**: Pure data types and platform detection. No business logic. Testable in isolation.
**Base**: `main`
**Verification**: `cargo test --lib` (unit tests pass, no integration tests run)

- [ ] **1.1** Create `src/scanner/models.rs` — define `DiscoveredHost`, `DiscoveryMethod`, `Capabilities`, `ArpEntry`, `PingResult` structs with derive(Debug, Clone, Serialize). Include `MacAddress` type alias from `macaddr`. (TDD: write struct shape tests first — compile fail, then derive) — ~40 lines
- [ ] **1.2** Add `Permission`, `InterfaceNotFound`, `Discovery` variants to `src/error.rs`. Add `Discovery` to `ScanConfig` if used. — ~15 lines
- [ ] **1.3** Create `src/scanner/capabilities.rs` — implement `detect_permissions()` using `libc::geteuid()` + `capability` crate check; `resolve_network("auto" | CIDR)` using `ipnetwork`; `expand_cidr()` to produce `Vec<IpAddr>` excluding network/broadcast. Gate `#[cfg(target_os = "linux")]` for raw-socket checks. Add `#[cfg(test)]` with property-based edge cases (/24, /32, /16 warning, /31 all-host). — ~200 lines
- [ ] **1.4** Update `src/scanner/mod.rs` — re-export `Scanner`, `DiscoveredHost`, `DiscoveryMethod`, `Capabilities`. Add `pub mod capabilities; pub mod models;`. — ~10 lines

## Phase 2: Core Implementation — Discovery Orchestrator

### Work Unit: PR 2 — `discovery.rs` with all probes + merge logic

**Goal**: Scanner struct owns config, runs ICMP/TCP/ARP concurrently via `tokio::join!`, merges and deduplicates results.
**Base**: PR 1 branch
**Verification**: `cargo test --lib` (including arp parsing tests, merge dedup tests)

- [ ] **2.1** Create `src/scanner/discovery.rs` — `Scanner` struct with `ScanConfig` owned field. Implement `Scanner::new(config: ScanConfig) -> Self` and `discover_network(network: &IpNetwork, caps: &Capabilities) -> Result<Vec<DiscoveredHost>>`. — ~50 lines
- [ ] **2.2** Implement `icmp_sweep(ips, semaphore) -> Vec<PingResult>` using `pnet`ICMP packet builder + socket. Skip entirely if `!caps.can_icmp`. Bounded concurrency via semaphore. 2s timeout. — ~80 lines (TDD: mock socket, test timeout behavior)
- [ ] **2.3** Implement `tcp_sweep(ips, ports, semaphore) -> Vec<PingResult>` using `tokio::net::TcpStream::connect_timeout`. Ports: 22, 80, 443. Parallel ports per host using `FuturesUnordered`. 1s timeout. Return first success per host. — ~80 lines
- [ ] **2.4** Implement `arp_parse() -> Vec<ArpEntry>` with `#[cfg(target_os = "linux")]`. Read `/proc/net/arp`, split whitespace, validate 6 columns, return entries. On parse failure log warning and return empty. `#[cfg(not(target_os = "linux"))]` returns empty. — ~60 lines
- [ ] **2.5** Implement `merge(ping_results, arp_entries) -> Vec<DiscoveredHost>` — deduplicate by IP (prefer ICMP over TCP, prefer MAC from ARP). Resolve hostname via reverse DNS (`tokio::net::lookup_addr`) async. — ~60 lines
- [ ] **2.6** Run all three probes via `tokio::join!` inside `discover_network`. Gate ICMP behind `caps.can_icmp`. Print warning via `tracing::warn!` for unavailable ICMP. — ~30 lines

## Phase 3: CLI Wiring

### Work Unit: PR 3 — scan command handler + table output

**Goal**: Wire `Scanner` into CLI, replace stub, produce formatted table to stdout.
**Base**: PR 2 branch
**Verification**: `cargo test --lib` + `cargo build`

- [ ] **3.1** Update `src/cli/scan.rs` — add `format_hosts_table(hosts: &[DiscoveredHost]) -> String` producing aligned plain-text table with columns: IP, MAC, Hostname, Method. — ~60 lines
- [ ] **3.2** Update `src/cli/mod.rs` — replace `println!("scan subcommand (stub)")` with `Scanner::new(config).discover(&args.network).await?` and pipe result to `format_hosts_table`. Import `crate::scanner::Scanner`. — ~30 lines
- [ ] **3.3** Verify `netascan scan --network 127.0.0.1/32` exits 0 with `#[test]` using `assert_cmd`. Add `tests/scanner_tests.rs` with `#[ignore]` marker on root-required integration tests. — ~60 lines
- [ ] **3.4** Add `libc` dependency to `Cargo.toml` (needed for `geteuid`). Check `pnet` ICMP raw socket support — if `libpcap-dev` is build requirement, add note to README or CI. — ~5 lines

## Phase 4: Verification + Cleanup

### Work Unit: PR 3 (continued) — final checks

**Verification**: `cargo test` passes, `cargo build --release` succeeds, no lints via `cargo clippy`

- [ ] **4.1** Run full `cargo test` — all unit tests pass, integration tests marked `#[ignore]` if they need root. — verification only
- [ ] **4.2** Run `cargo clippy -- -D warnings` — fix any lint complaints. — ~20 lines cleanup
- [ ] **4.3** Update `src/scanner/mod.rs` doc comment — remove "Implementation pending" stub note, document module purpose. — ~5 lines

## Implementation Order Rationale

1. **Models first** (PR 1) — all other phases depend on `DiscoveredHost`, `DiscoveryMethod`, `Capabilities`. Pure data, no async, easy to test.
2. **Capabilities** (PR 1) — `detect_permissions()` and `resolve_network()` are required before the orchestrator can make branching decisions (ICMP gate, graceful degradation).
3. **Discovery orchestrator** (PR 2) — consumes models + capabilities. Probes are independent and run concurrently; this is the core logic.
4. **CLI wiring** (PR 3) — thin layer, depends on everything above. Produces visible output for the first time.

## Next Step

Ready for `sdd-apply` once user confirms chain strategy (`stacked-to-main` vs `feature-branch-chain`).