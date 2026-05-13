# Tasks: Device Fingerprint — TTL + Banner OS Hints

## Review Workload Forecast

| Field | Value |
|-------|-------|
| Estimated changed lines | ~150–200 |
| 400-line budget risk | Low |
| Chained PRs recommended | No |
| Suggested split | Single PR |
| Delivery strategy | auto-chain |
| Chain strategy | stacked-to-main |

Decision needed before apply: No
Chained PRs recommended: No
Chain strategy: stacked-to-main
400-line budget risk: Low

### Suggested Work Units

| Unit | Goal | Likely PR | Notes |
|------|------|-----------|-------|
| 1 | Full device-fingerprint implementation | PR 1 | All 4 phases in one PR; stacked to main |

## Phase 1: Model (DiscoveredHost + os_hint field)

- [ ] 1.1 RED: Add `os_hint: Option<String>` to `DiscoveredHost` struct — write failing test for JSON round-trip with `os_hint: None` and `os_hint: Some("Linux")`
- [ ] 1.2 GREEN: Add `os_hint: Option<String>` field to `DiscoveredHost` in `src/scanner/models.rs`
- [ ] 1.3 REFACTOR: Ensure serialization/deserialization works cleanly

## Phase 2: Fingerprint Module — TTL + Banner Inference

- [ ] 2.1 RED: Write unit tests for `ttl_to_os_hint()` covering all TTL ranges (60–64→Linux/macOS, 120–128→Windows, 250–254→FreeBSD, <32→None)
- [ ] 2.2 GREEN: Implement `ttl_to_os_hint(ttl: u8) -> Option<&'static str>` in `src/fingerprint/mod.rs`
- [ ] 2.3 REFACTOR: Verify edge cases (TTL=32, 65, 129, 255)
- [ ] 4.1 RED: Write unit tests for `infer_os_from_banner()` covering Ubuntu, Debian, RHEL/CentOS, Windows, FreeBSD, Cisco IOS, generic Linux, no-match cases
- [ ] 4.2 GREEN: Implement `infer_os_from_banner(banner: &str) -> Option<String>` in `src/fingerprint/mod.rs`
- [ ] 4.3 REFACTOR: Clean up pattern matching order, ensure banner priority semantics

## Phase 3: Discovery Integration

- [ ] 3.1 RED: Write integration test for `PingResult` with `ttl_hint` field
- [ ] 3.2 GREEN: Extend `PingResult` with `ttl_hint: Option<String>` field in `src/scanner/discovery.rs`
- [ ] 3.3 GREEN: Add TTL extraction to `icmp_sweep()` using `extract_ttl_from_ip_header()` helper
- [ ] 3.4 GREEN: Update `merge_results()` to set `os_hint` from `ttl_hint`
- [ ] 3.5 REFACTOR: Verify `icmp_sweep()` still compiles and TTL extraction is isolated

## Phase 4: Banner Hint Integration + Verification

- [ ] 4.1 RED: Write test: host with TTL hint "Linux/macOS" + banner "Ubuntu" resolves to "Ubuntu Linux"
- [ ] 4.2 GREEN: After `scan_ports()` populates banners, call `infer_os_from_banner()` on each `OpenPort.banner` and override `os_hint` if found
- [ ] 4.3 REFACTOR: Extract `apply_os_hints()` helper to keep `scan_ports()` clean
- [ ] 4.4 Run `cargo test` — all tests pass
- [ ] 4.5 Run `cargo clippy` — no warnings
- [ ] 4.6 Verify `cargo fmt` — no formatting issues