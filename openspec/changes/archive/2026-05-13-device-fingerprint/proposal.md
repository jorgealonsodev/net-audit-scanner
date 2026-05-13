# Proposal: Device Fingerprint — TTL + Banner OS Hints

## Intent

`src/fingerprint/mod.rs` is a 3-line stub. Users scanning a network see hosts with no OS context. This change adds lightweight OS hints (~50 lines) using data already available from ICMP replies and TCP banners — no new deps, no extra network I/O.

## Scope

### In Scope
- Add `os_hint: Option<String>` to `DiscoveredHost` model
- Extract TTL from ICMP echo replies in `icmp_sweep()`
- Add `infer_os_from_banner(banner: &str) -> Option<String>` for banner-based OS hints
- Populate `os_hint` during host merge from TTL + banner signals

### Out of Scope
- TCP stack fingerprinting (window size, TCP options)
- nmap-style active OS detection (crafted probes, signature DB)
- MAC-based OS inference (OUI already covers vendor, not OS)
- Confidence scoring or multi-signal fusion

## Capabilities

### New Capabilities
- `device-fingerprint`: OS hint detection via TTL analysis and banner pattern matching

### Modified Capabilities
- `network-discovery`: `DiscoveredHost` gains `os_hint` field; merge logic populates it

## Approach

Two passive signals, zero extra I/O:
1. **TTL extraction**: Parse IP header TTL from existing pnet ICMP reply packets. Round down to nearest standard initial TTL (64→Linux/macOS, 128→Windows, 254→FreeBSD).
2. **Banner patterns**: Match known OS substrings in SSH/HTTP/FTP banners (e.g., "Ubuntu", "Windows", "Debian").

Both signals feed `os_hint` on `DiscoveredHost`. Banner takes priority when available (more specific than TTL).

## Affected Areas

| Area | Impact | Description |
|------|--------|-------------|
| `src/scanner/models.rs` | Modified | Add `os_hint: Option<String>` to `DiscoveredHost` |
| `src/scanner/discovery.rs` | Modified | Extract TTL in `icmp_sweep()`, pass through to `merge_results()` |
| `src/fingerprint/mod.rs` | New | `infer_os_from_banner()` function + TTL→OS mapping |
| `src/scanner/services.rs` | Unchanged | Banner text already captured; fingerprint module consumes it |

## Risks

| Risk | Likelihood | Mitigation |
|------|------------|------------|
| macOS indistinguishable from Linux (both TTL=64) | High | Label as "Linux/macOS"; banner may disambiguate |
| TTL misclassification beyond 64 hops | Low | Flag TTL < 32 as "unknown" |
| Banner spoofing | Low | Label output as "hint", not definitive |

## Rollback Plan

Revert the single commit: remove `os_hint` field from `DiscoveredHost`, delete `infer_os_from_banner()`, restore `icmp_sweep()` TTL parsing. No schema migrations, no data format breaks (field is `Option`).

## Dependencies

- None — uses existing `pnet` for packet parsing, no new crates

## Success Criteria

- [ ] `DiscoveredHost` serializes/deserializes with `os_hint` field
- [ ] `infer_os_from_banner()` correctly identifies Ubuntu, Windows, Debian from SSH banners
- [ ] TTL extraction returns correct OS hint for TTL values 64, 128, 254
- [ ] No new dependencies in `Cargo.toml`
- [ ] All existing tests pass
