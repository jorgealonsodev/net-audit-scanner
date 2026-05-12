# Tasks: port-scanner

## Review Workload Forecast

| Field | Value |
|-------|-------|
| Estimated changed lines | ~430–500 |
| 400-line budget risk | Medium |
| Chained PRs recommended | No |
| Suggested split | Single PR (feature is cohesive) |
| Delivery strategy | ask-on-risk |
| Chain strategy | pending |

Decision needed before apply: No
Chained PRs recommended: No
Chain strategy: pending
400-line budget risk: Medium

## Suggested Work Units

| Unit | Goal | Likely PR | Notes |
|------|------|-----------|-------|
| 1 | Models + port list + service detection (types, ports.rs, services.rs, scan_ports) | PR 1 | Base feature branch; TDD tests included |
| 2 | CLI wiring + config (--port-range, banner_timeout_ms, --full fix) | PR 1 (same) | Same PR — logically part of the same feature |

(Chained PRs not needed; feature is cohesive and self-contained. Medium risk but single feature team can review together.)

## Phase 1: Types & Data Models (~60 lines)

- [ ] 1.1 **`src/scanner/models.rs`**: Add `OpenPort` struct (`port: u16`, `service: ServiceType`, `banner: Option<String>`, `protocol: Protocol`, `is_insecure: bool`), `ServiceType` enum (Http, Https, Ssh, Telnet, Ftp, Rtsp, Mqtt, Upnp, Smtp, Dns, Unknown(String)), `Protocol` enum (Tcp). Change `DiscoveredHost.open_ports: Vec<u16>` → `Vec<OpenPort>`. Update all existing tests (Vec<u16> → Vec<OpenPort> in test fixtures).
  - Verification: `cargo test scanner::models::tests`

## Phase 2: Port List Resolution (~100 lines + tests)

- [ ] 2.1 **`src/scanner/ports.rs`** (new file): Define const slices `PORT_LIST_TOP_100`, `PORT_LIST_TOP_1000`, `PORT_LIST_IOT_CRITICAL`. Implement `resolve_port_list(range: &str) -> Vec<u16>` that parses "top-100", "top-1000" and always merges IoT critical ports.
  - Verification: `cargo test scanner::ports::tests`

- [ ] 2.2 **`src/scanner/ports.rs`**: Write TDD tests: top-100 contains expected ports, top-1000 extends top-100, IoT ports always merged regardless of range, dedup removes duplicates.
  - Verification: `cargo test`

## Phase 3: Banner Grabbing & Service Detection (~150 lines + tests)

- [ ] 3.1 **`src/scanner/services.rs`** (new file): Implement `grab_banner(ip: IpAddr, port: u16, timeout: Duration) -> Option<String>` using tokio TcpStream with deadline read of up to 256 bytes.
  - Verification: `cargo test scanner::services::tests`

- [ ] 3.2 **`src/scanner/services.rs`**: Implement `classify_service(port: u16, banner: &Option<String>) -> ServiceType` using port-first lookup table + banner string matching (SSH "SSH-", HTTP "HTTP/", FTP "220").
  - Verification: `cargo test scanner::services::tests`

- [ ] 3.3 **`src/scanner/services.rs`**: Implement `is_insecure(service: &ServiceType, port: u16, banner: &Option<String>, other_ports: &[OpenPort]) -> bool`: flag Telnet, FTP, HTTP(80) when 443 absent on same host, IoT ports (MQTT 1883, UPnP 1900, RTSP 554).
  - Verification: `cargo test scanner::services::tests`

- [ ] 3.4 Write TDD tests for all three functions covering banner timeout (no panic on unreachable), service classification per port, insecure flagging rules.
  - Verification: `cargo test scanner::services::tests`

## Phase 4: Scanner Orchestrator Integration (~100 lines + tests)

- [ ] 4.1 **`src/scanner/discovery.rs`**: Add `pub async fn scan_ports(&self, hosts: Vec<DiscoveredHost>, caps: &Capabilities) -> Vec<DiscoveredHost>` method: flat Semaphore(concurrency), probe each (host, port) from resolved port list, grab banner, classify service, set insecure flag, return enriched hosts.
  - Verification: `cargo test scanner::discovery::tests`

- [ ] 4.2 **`src/scanner/discovery.rs`**: Add full-scan warning for networks > /31 (REQ-DISC-11): log warning when network prefix < 31 (i.e., network is larger than /31).
  - Verification: `cargo test scanner::discovery::tests`

- [ ] 4.3 **`src/scanner/mod.rs`**: Re-export `OpenPort`, `ServiceType`, `Protocol` from models; export `scan_ports` from discovery; add `pub mod ports; pub mod services;`.
  - Verification: `cargo build`

## Phase 5: Config + CLI Wiring (~50 lines)

- [ ] 5.1 **`src/config/mod.rs`**: Add `banner_timeout_ms: u64` field to `ScanConfig` (default: 500).
  - Verification: `cargo test config::tests`

- [ ] 5.2 **`src/cli/scan.rs`**: Add `--port-range` argument (`String`, default from config).
  - Verification: `cargo test cli::tests`

- [ ] 5.3 **`src/cli/mod.rs`**: In `Commands::Scan`, fix hardcoded `"top-1000"` → use `args.port_range` from config; call `scanner.scan_ports()` after `discover_network()`; pass `banner_timeout_ms` from config.
  - Verification: `cargo test cli::tests`

## Phase 6: Integration & Verification

- [ ] 6.1 Run full test suite: `cargo test` — all 55 existing tests + new tests must pass.
  - Verification: `cargo test 2>&1 | tail -20`

- [ ] 6.2 Verify JSON serialization of `DiscoveredHost` with new `open_ports: Vec<OpenPort>` — existing JSON tests in models.rs updated.
  - Verification: `cargo test scanner::models`

- [ ] 6.3 Verify CLI help reflects new `--port-range` flag.
  - Verification: `cargo run -- scan --help | grep port-range`
