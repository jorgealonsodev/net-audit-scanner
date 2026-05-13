# Tasks: oui-fingerprint

## Review Workload Forecast

| Field | Value |
|-------|-------|
| Estimated changed lines | 300–380 |
| 400-line budget risk | Low |
| Chained PRs recommended | No |
| Suggested split | Single PR |
| Delivery strategy | ask-on-risk |
| Chain strategy | stacked-to-main (not expected to be needed) |

Decision needed before apply: No
Chained PRs recommended: No
Chain strategy: stacked-to-main
400-line budget risk: Low

## Phase 1: Foundation — OUI Database & Data Layer

- [ ] 1.1 Create `data/manuf` with Wireshark OUI/manuf database (~200KB, one manuf entry per line, e.g. `00:00:0C/30 Apple/30\tApple, Inc.`). Test file with at least 5 known entries covering 3-byte, 4-byte, 5-byte prefixes.
- [ ] 1.2 Create `src/scanner/oui.rs` with `OuiDb` struct — three `HashMap<[u8; N], String>` fields (prefix3, prefix4, prefix5). Implement `OuiDb::from_embedded()` using `include_dir!` to embed `data/manuf`. Implement `parse_manuf(content: &str) -> OuiDb` parsing each line (skip comments/blank). Implement `lookup(&self, mac: &MacAddr6) -> Option<&str>` doing longest-prefix-match (5→4→3). Implement `enrich_oui(db: &OuiDb, hosts: &mut [DiscoveredHost])`. Define `pub static OUI_DB: LazyLock<OuiDb>`.
- [ ] 1.3 Add `pub mod oui;` and re-exports (`OuiDb`, `OUI_DB`, `enrich_oui`) to `src/scanner/mod.rs`.
- [ ] 1.4 Add `vendor: Option<String>` field to `DiscoveredHost` in `src/scanner/models.rs`.

## Phase 2: Pipeline Integration

- [ ] 2.1 Add `vendor: None` to `DiscoveredHost` construction in `merge_results()` in `src/scanner/discovery.rs`.
- [ ] 2.2 In `src/cli/mod.rs`, after `scanner.scan_ports(hosts)` call, call `crate::scanner::enrich_oui(&crate::scanner::OUI_DB, &mut hosts)` before output.

## Phase 3: CLI Output — Vendor Column

- [ ] 3.1 Update `format_hosts_table()` in `src/cli/scan.rs` — add `Vendor` column between MAC and Hostname. Compute width from vendor strings. Render vendor from `host.vendor.as_deref().unwrap_or("-")`.
- [ ] 3.2 Add vendor field to the JSON output path via existing `serde_json` serialization (no code change needed — `Option<String>` serializes automatically).

## Phase 4: Unit Tests

- [ ] 4.1 Write RED test in `src/scanner/oui.rs` `#[cfg(test)]` mod: `parse_manuf_parses_3byte_prefix`, `parse_manuf_parses_4byte_prefix`, `parse_manuf_parses_5byte_prefix`, `parse_manuf_skips_comments_and_blank_lines`, `parse_manuf_handles_malformed_lines`.
- [ ] 4.2 Write RED test: `oui_db_lookup_finds_3byte_exact`, `oui_db_lookup_finds_4byte_fallback`, `oui_db_lookup_finds_5byte_exact`, `oui_db_lookup_unknown_returns_none`, `oui_db_lookup_longest_prefix_wins`.
- [ ] 4.3 Write RED test: `enrich_oui_populates_vendor_for_mac_hosts`, `enrich_oui_leaves_vendor_none_for_no_mac`, `enrich_oui_mutates_in_place`.
- [ ] 4.4 GREEN all tests. Run `cargo test --lib oui` to verify.
- [ ] 4.5 Write RED test in `src/cli/scan.rs`: `format_hosts_table_includes_vendor_column` with a host that has a vendor string.
- [ ] 4.6 GREEN table vendor test. Run `cargo test scan`.

## Phase 5: Integration Smoke Test

- [ ] 5.1 Add `tests/fixtures/manuf.txt` fixture with known MAC→vendor entries (e.g. `00:00:0C/30 Apple`, `00:1B:63:84/28 Apple Inc`).
- [ ] 5.2 Write `#[test]` in `src/scanner/oui.rs` that calls `parse_manuf()` on fixture content and verifies lookup for each prefix length.
- [ ] 5.3 Run full test suite: `cargo test --lib`. All tests must pass.

## Phase 6: TSDoc & Commit-Unit Checklist

- [ ] 6.1 Add module-level `//!` docs to `src/scanner/oui.rs` describing OUI enrichment, the 3-HashMap design, and lookup algorithm.
- [ ] 6.2 Document `enrich_oui()` preconditions (call after scan_ports, requires MAC populated by ARP discovery).
- [ ] 6.3 Verify `cargo doc --lib` passes without warnings.
- [ ] 6.4 Verify the build: `cargo build --release` succeeds.

## Implementation Order

1. **Phase 1 first** — oui.rs and manuf data are dependencies for everything else. Without them, nothing else compiles.
2. **Phase 2 second** — models.rs and discovery.rs changes are small but required before the CLI wiring.
3. **Phase 3 third** — CLI table output is the user-visible deliverable.
4. **Phase 4–5 last** — TDD tests prove correctness; integration smoke test validates the full pipeline.

## Relevant Files

- `src/scanner/oui.rs` — new, core OUI DB logic
- `data/manuf` — new, Wireshark manuf database
- `src/scanner/models.rs` — add vendor field to DiscoveredHost
- `src/scanner/discovery.rs` — initialize vendor=None in merge_results
- `src/scanner/mod.rs` — re-export oui module
- `src/cli/mod.rs` — pipeline integration (enrich_oui call)
- `src/cli/scan.rs` — add Vendor column to table
- `tests/fixtures/manuf.txt` — new test fixture