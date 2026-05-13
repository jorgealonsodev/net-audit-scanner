## Verification Report

**Change**: oui-fingerprint
**Version**: 1.0 (specs/oui-fingerprint/spec.md)
**Mode**: Strict TDD

### Completeness

| Metric | Value |
|--------|-------|
| Tasks total | 21 |
| Tasks complete | 21 |
| Tasks incomplete | 0 |
| Requirements | 5 |
| Scenarios | 23 |

**Task completion**: ✅ 21/21 tasks across 6 phases. All phases committed with conventional commits (3f2f83c Phase 1 → ea8166c Phase 2 → cd638f3 Phase 3 → b1468c0 Phase 5 → d06ef11 Phase 6). Phase 4 unit tests were written inline with Phases 1-3 as part of TDD cycle.

### Build & Tests Execution

**Build**: ✅ Passed
```
$ cargo build --release
    Finished `release` profile [optimized] target(s) in 1.20s
```

**Tests**: ✅ 127 passed / ❌ 0 failed / ⚠️ 7 ignored
```
running 120 tests (unittests lib)
test result: ok. 120 passed; 0 failed; 0 ignored

running 4 tests (CLI integration)
test result: ok. 4 passed; 0 failed; 7 ignored

running 1 test (report integration)
test result: ok. 1 passed; 0 failed

running 1 test (scanner integration)
test result: ok. 1 passed; 0 failed

running 1 test (doctest — oui.rs enrich_oui)
test result: ok. 1 passed; 0 failed
```

7 ignored tests are network-dependent (TCP probes), unrelated to OUI.

**Clippy**: ✅ Clean (0 warnings, 0 errors)
```
$ cargo clippy
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 1.63s
```

**Docs**: ✅ Pass (1 pre-existing warning in `src/scanner/ports.rs:101` — unclosed HTML tag `<u16>` — outside change scope)
```
$ cargo doc --lib
    Finished `dev` profile [unoptimized + debuginfo] target(s)
```

### Spec Compliance Matrix

| Req | Scenario | Test | Result |
|-----|----------|------|--------|
| REQ-OUI-1 | Lazy initialization | OUI_DB static (oui.rs:185) — doctest compiles, no runtime lazy-init test | ⚠️ PARTIAL |
| REQ-OUI-1 | Valid entries indexed | `parse_manuf_parses_3byte_prefix` / `_4byte_` / `_5byte_` | ✅ COMPLIANT |
| REQ-OUI-1 | Malformed lines skipped | `parse_manuf_handles_malformed_lines` | ✅ COMPLIANT |
| REQ-OUI-1 | Empty manuf file | `from_embedded()` guard (oui.rs:53-55) — no dedicated test | ⚠️ PARTIAL |
| REQ-OUI-1 | Unicode preserved | Rust String inherently Unicode-safe; no explicit non-ASCII test | ⚠️ PARTIAL |
| REQ-OUI-2 | OUI-only match | `oui_db_lookup_finds_3byte_exact` | ✅ COMPLIANT |
| REQ-OUI-2 | MA-S most specific | `oui_db_lookup_finds_5byte_exact` + algorithmic ordering (5→4→3) | ✅ COMPLIANT |
| REQ-OUI-2 | MA-M overrides OUI | `oui_db_lookup_longest_prefix_wins` | ✅ COMPLIANT |
| REQ-OUI-2 | No match | `oui_db_lookup_unknown_returns_none` | ✅ COMPLIANT |
| REQ-OUI-2 | No MAC address | `enrich_oui_leaves_vendor_none_for_no_mac` | ✅ COMPLIANT |
| REQ-OUI-3 | Matched MAC | `enrich_oui_populates_vendor_for_mac_hosts` | ✅ COMPLIANT |
| REQ-OUI-3 | Unmatched MAC | `enrich_oui_mutates_in_place` (hosts[1] unmatched) | ✅ COMPLIANT |
| REQ-OUI-3 | No MAC | `enrich_oui_leaves_vendor_none_for_no_mac` | ✅ COMPLIANT |
| REQ-OUI-3 | Mixed batch | `enrich_oui_mutates_in_place` (1 match + 1 no-match) | ✅ COMPLIANT |
| REQ-OUI-3 | Empty list | Implicit: for-loop over empty slice → zero lookups | ⚠️ PARTIAL |
| REQ-OUI-4 | Vendor serialized | `discovered_host_vendor_serializes` | ✅ COMPLIANT |
| REQ-OUI-4 | Null vendor serialized | `discovered_host_serializes_to_json` (vendor: None → null) | ✅ COMPLIANT |
| REQ-OUI-4 | Backward deserialization | `discovered_host_deserializes_from_json` (JSON without vendor key) | ✅ COMPLIANT |
| REQ-OUI-5 | Vendor in table | `format_hosts_table_includes_vendor_column` | ✅ COMPLIANT |
| REQ-OUI-5 | Missing vendor in table | `format_hosts_table_missing_vendor_shows_dash` | ✅ COMPLIANT |
| REQ-OUI-5 | Vendor in JSON | `discovered_host_vendor_serializes` + serde auto-serialization | ✅ COMPLIANT |
| REQ-OUI-5 | Null vendor in JSON | `discovered_host_serializes_to_json` (vendor: None) | ✅ COMPLIANT |
| REQ-OUI-5 | HTML report renders vendor | Template `report.html.tera:38` has `{{ host.vendor }}` — no runtime render test | ⚠️ PARTIAL |

**Compliance summary**: 19/23 scenarios COMPLIANT, 4/23 PARTIAL, 0 UNTESTED, 0 FAILING

### Correctness (Static Evidence)

| Requirement | Status | Notes |
|------------|--------|-------|
| REQ-OUI-1: Embedded OUI Database | ✅ Implemented | `OuiDb` struct with 3 HashMaps, `from_embedded()` via `include_dir!`, `LazyLock<OuiDb>` static at oui.rs:185 |
| REQ-OUI-2: MAC Prefix Lookup | ✅ Implemented | `lookup(&self, mac: &MacAddr6) -> Option<&str>` at oui.rs:63 — ordered 5→4→3 fallback, O(1) per lookup |
| REQ-OUI-3: Pipeline Enrichment | ✅ Implemented | `enrich_oui()` at oui.rs:174, called at cli/mod.rs:84 AFTER `scan_ports()` (line 81) and BEFORE output (lines 87-91) |
| REQ-OUI-4: Vendor Field | ✅ Implemented | `vendor: Option<String>` at models.rs:61, default `None` in `merge_results()` at discovery.rs:499 |
| REQ-OUI-5: CLI/Report Integration | ✅ Implemented | Vendor column in `format_hosts_table()` at scan.rs:61/89/120, JSON via serde auto, HTML via `{{ host.vendor }}` at report.html.tera:38 |

### Coherence (Design)

| Decision | Followed? | Notes |
|----------|-----------|-------|
| Three HashMaps with byte-array keys | ✅ Yes | `prefix3: HashMap<[u8;3], String>` etc. (oui.rs:37-39) |
| Longest-prefix-match: 5→4→3 | ✅ Yes | `lookup()` at oui.rs:67-78 tries key5→key4→key3 |
| Round prefix masks to byte boundaries | ✅ Yes | `prefix_hex.split('/').next()` strips mask (oui.rs:110), no bit-level masking |
| `enrich_oui` after `scan_ports` | ✅ Yes | cli/mod.rs:81 `scan_ports()`, then line 84 `enrich_oui()` |
| `LazyLock<OuiDb>` initialization | ✅ Yes | oui.rs:185, uses `std::sync::LazyLock` (stable Rust 2024) |
| OuiDb in `scanner/oui.rs`, not `fingerprint/` | ✅ Yes | File at `src/scanner/oui.rs`, stub `fingerprint/mod.rs` untouched |
| Backward-compatible JSON | ✅ Yes | `vendor: Option<String>` with `#[serde(default)]` implicit, test `discovered_host_deserializes_from_json` confirms |

### TDD Compliance

| Check | Result | Details |
|-------|--------|---------|
| TDD Evidence reported | ✅ | Found in apply-progress — 21-row TDD Cycle Evidence table |
| All tasks have tests | ✅ | 21/21 tasks have test evidence (7 data/structural tasks marked N/A appropriately) |
| RED confirmed (tests exist) | ✅ | All 9 test files referenced in TDD table exist in codebase |
| GREEN confirmed (tests pass) | ✅ | All 127 tests pass on execution (0 failures) |
| Triangulation adequate | ✅ | 10 tasks use "✅ N cases" (2-4 cases each), 11 tasks use "➖ Single/N/A" (structural/data tasks) |
| Safety Net for modified files | ✅ | Modified files (scan.rs: 117/117, oui.rs: 102/102) verified as safety-net baseline |

**TDD Compliance**: 6/6 checks passed

### Test Layer Distribution

| Layer | Tests | Files | Tools |
|-------|-------|-------|-------|
| Unit | 120 | 7 | cargo test --lib |
| Integration (CLI) | 4 | 1 | cargo test --test cli_tests |
| Integration (scanner) | 1 | 1 | cargo test --test scanner_tests |
| Integration (report) | 1 | 1 | cargo test --test report_tests |
| Doc-test | 1 | 1 | cargo test --doc |
| **Total** | **127** | **11** | cargo test |

### Assertion Quality

| File | Line | Assertion | Issue | Severity |
|------|------|-----------|-------|----------|
| src/cli/scan.rs | 275-279 | `assert!(output.contains("Vendor"))` + `assert!(output.contains("192.168.1.2"))` | Test named `missing_vendor_shows_dash` but does not assert "-" renders in vendor position — only checks header exists and IP row exists | WARNING |

**Assertion quality**: 0 CRITICAL, 1 WARNING

### Issues Found

**CRITICAL**: None

**WARNING**:
1. **Assertion weakness in `format_hosts_table_missing_vendor_shows_dash`** (scan.rs:275-279): Test name says "shows dash" but assertions only verify the "Vendor" header and IP presence — not that "-" actually renders in the vendor column. The code path is correct (`unwrap_or("-")`) but the test doesn't prove it.

**SUGGESTION**:
1. **Empty manuf file scenario untested** (REQ-OUI-1.4): `from_embedded()` has a guard (`if content.is_empty()`) but no dedicated test for it. Add a test with `parse_manuf("")` verifying zero entries, no panic.
2. **Empty list scenario untested** (REQ-OUI-3.5): `enrich_oui` with empty vec not explicitly tested. Add a test: `enrich_oui(&db, &mut [])` — verify no panic, vec unchanged.
3. **Unicode vendor names not explicitly tested** (REQ-OUI-1.5): While Rust String handles Unicode inherently, adding a test with a non-ASCII vendor name (e.g. "Märklin" or "株式会社") would strengthen confidence.
4. **HTML template rendering not runtime-tested** (REQ-OUI-5.5): Template has `{{ host.vendor }}` but no render test. Add a test using Tera to render with a host that has vendor.
5. **Lazy initialization not runtime-tested** (REQ-OUI-1.1): No test accesses `OUI_DB` directly to verify lazy init doesn't panic. The doctest uses `no_run`. Consider a runtime test or remove `no_run`.

### Verdict

**PASS WITH WARNINGS**

All 127 tests pass. Zero build/clippy/doc errors. All 21 tasks complete. All 5 requirements implemented per design. 19/23 scenarios have COMPLIANT status with passing tests. 4 PARTIAL scenarios are structurally correct but lack dedicated runtime tests (all SUGGESTION-level gaps, no behavior regressions). 1 WARNING for weak assertion in `format_hosts_table_missing_vendor_shows_dash`. OUI enrichment pipeline is correctly positioned after port scanning and before output.
