# Proposal: MAC OUI Fingerprinting

## Intent

MAC addresses from ARP are opaque hex strings. Report template already references `{{ host.vendor }}` — a field that doesn't exist. This change turns raw MACs into vendor intelligence for device classification.

## Scope

### In Scope
- Embed Wireshark `manuf` DB at compile time via `include_dir` (already a dependency)
- `OuiDb` struct with `HashMap<[u8; 3], String>` for O(1) vendor lookup
- Multi-length prefixes: 3-byte (OUI), 4-byte (MA-M), 5-byte (MA-S)
- `vendor: Option<String>` on `DiscoveredHost`
- `enrich_oui()` pipeline step after `scan_ports()`
- Vendor column in CLI table + JSON output

### Out of Scope
- `update` subcommand (stub exists, future change)
- Banner/OS fingerprinting (separate capabilities)
- IPv6 OUI lookup

## Capabilities

### New Capabilities
- `oui-fingerprint`: MAC OUI lookup — vendor ID from Wireshark manuf with compile-time embed, multi-length prefix matching, pipeline integration

### Modified Capabilities
- None (report template already references `host.vendor`; no spec-level change)

## Approach

Compile-time embed `manuf` (~200KB, ~30K entries) via `include_dir!()`. Parse into `OuiDb` at first access via `LazyLock`. Lookup: extract first 3 bytes → O(1) HashMap. MA-M/MA-S handled by ordered fallback (5→4→3 bytes). Enrichment is a pure function called once after `scan_ports()`. Pattern follows `ports.rs` + `services.rs`.

## Affected Areas

| Area | Impact | Description |
|------|--------|-------------|
| `src/scanner/oui.rs` | NEW | OuiDb, manuf parsing, vendor lookup |
| `data/manuf` | NEW | Wireshark manuf file (~200KB) |
| `src/scanner/models.rs` | Modified | `vendor: Option<String>` on DiscoveredHost |
| `src/scanner/discovery.rs` | Modified | `enrich_oui()` call after `scan_ports()` |
| `src/scanner/mod.rs` | Modified | `pub mod oui`, re-exports |
| `src/cli/scan.rs` | Modified | Vendor column in table + JSON |

## Risks

| Risk | Likelihood | Mitigation |
|------|------------|------------|
| Binary size +1-2MB | Certain | Acceptable for CLI tool |
| Stale OUI data | Medium | `update` stub for future refresh |
| MA-M/MA-S ambiguity | Low | Ordered lookup (5→4→3) with test coverage |

## Rollback Plan

Revert commit. `vendor` is `Option<String>` — null for no-MAC hosts. No schema migration, no data loss.

## Dependencies

- `include_dir` v0.7 — already in Cargo.toml
- `macaddr` — already in Cargo.toml
- Wireshark `manuf` — bundled in `data/manuf`

## Success Criteria

- [ ] OUI lookup returns vendor for known MAC prefixes
- [ ] `enrich_hosts()` populates `vendor` for hosts with MACs
- [ ] CLI table shows Vendor column; JSON includes `vendor` field
- [ ] Report template renders vendor without errors
- [ ] All existing tests pass
- [ ] New tests: OUI parsing, lookup, MA-M/MA-S prefix handling
