# Tasks: device-enrichment

## Review Workload Forecast

| Field | Value |
|-------|-------|
| Estimated changed lines | 450–600 |
| 400-line budget risk | High |
| Chained PRs recommended | Yes |
| Suggested split | PR 1 (foundation + SNMP) → PR 2 (mDNS + MacVendors + pipeline) |
| Delivery strategy | ask-on-risk |
| Chain strategy | stacked-to-main |

Decision needed before apply: Yes
Chained PRs recommended: Yes
Chain strategy: stacked-to-main
400-line budget risk: High

### Suggested Work Units

| Unit | Goal | Likely PR | Notes |
|------|------|-----------|-------|
| 1 | Models + EnrichmentConfig + SNMP | PR 1 | Base: main. Includes unit tests for SNMP. |
| 2 | mDNS + MacVendors + pipeline wiring | PR 2 | Base: PR 1 branch. Includes integration tests + Docker warning. |

## Phase 1: Foundation

- [x] 1.1 Add `Protocol::Udp` variant to `src/scanner/models.rs`; update `Display` and serde impls
- [x] 1.2 Add `device_model: Option<String>` field to `DiscoveredHost` in `src/scanner/models.rs`
- [x] 1.3 Update JSON serialization and HTML report template to include `device_model`
- [x] 1.4 Add `mdns-sd = "0.11"` and `async-snmp = "0.3"` to `Cargo.toml`
- [x] 1.5 Create `src/enrichment/mod.rs` with `EnrichmentConfig` struct and `enrich_devices` stub

## Phase 2: SNMP

- [x] 2.1 Create `src/enrichment/snmp.rs` — `snmp_probe(ip, config) -> Option<SnmpResult>` with 1s UDP timeout
- [x] 2.2 Implement OID queries for `sysDescr` (1.3.6.1.2.1.1.1.0) and `sysName` (1.3.6.1.2.1.1.5.0)
- [x] 2.3 Apply SNMP results to host fields using priority rules (overwrite only if field is empty)
- [x] 2.4 All SNMP errors absorbed: `tracing::debug!` only, no propagation

## Phase 3: mDNS

- [ ] 3.1 Create `src/enrichment/mdns.rs` — `mdns_query(ip, config) -> Option<MdnsResult>` with 2s window
- [ ] 3.2 Implement passive listen + active PTR query (`_services._dns-sd._udp.local`)
- [ ] 3.3 Parse PTR/A records → `hostname`; parse TXT `model=` → `device_model`
- [ ] 3.4 Emit `tracing::warn!` at enrichment startup if Docker bridge network detected
- [ ] 3.5 All mDNS errors absorbed: `tracing::debug!` only

## Phase 4: MacVendors API

- [ ] 4.1 Create `src/enrichment/mac_vendor.rs` — `lookup(mac) -> Option<String>` using existing `reqwest`
- [ ] 4.2 Implement sequential rate limiter: `sleep(Duration::from_secs(1))` between calls
- [ ] 4.3 Only call API when `mac_api_enabled` AND `host.vendor.is_none()`
- [ ] 4.4 HTTP 4xx/5xx absorbed: `tracing::debug!` only

## Phase 5: Wiring & Integration

- [ ] 5.1 Implement `enrich_devices` in `mod.rs`: `JoinSet` per host for SNMP+mDNS, then sequential MacVendors
- [ ] 5.2 Add `--mac-api` flag to `clap` args in `src/cli/mod.rs`
- [ ] 5.3 Build `EnrichmentConfig` from CLI args in `src/cli/mod.rs`
- [ ] 5.4 Insert `[3/5] Enriching device info...` step in CLI pipeline

## Phase 6: Testing

- [ ] 6.1 Unit test `snmp.rs`: mock timeout (T-ENR-1c), mock closed port (T-ENR-1d)
- [ ] 6.2 Unit test `snmp.rs`: sysDescr populates `os_hint` (T-ENR-1a), sysName populates `hostname` (T-ENR-1b)
- [ ] 6.3 Unit test `mdns.rs`: PTR → hostname (T-ENR-2a), TXT model= → device_model (T-ENR-2b), timeout (T-ENR-2c)
- [ ] 6.4 Unit test `mac_vendor.rs`: `--mac-api` absent → no call (T-ENR-3a); OUI present → no call (T-ENR-3c); API 429 non-fatal (T-ENR-3d)
- [ ] 6.5 Integration test: all enrichment fails → scan result returned normally (T-ENR-6a)
- [ ] 6.6 Integration test: 10 hosts concurrent enrichment completes within ~2.5s (T-ENR-7a)
- [ ] 6.7 Verify `device_model` appears in JSON output (T-ENR-4a) and `Protocol::Udp` compiles (T-ENR-5a)
