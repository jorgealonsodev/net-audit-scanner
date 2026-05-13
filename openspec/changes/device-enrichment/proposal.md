# Proposal: device-enrichment

## Intent

Extend `netascan` with a post-scan enrichment pipeline that identifies device models and hostnames using three complementary sources: SNMP probing, mDNS passive/active queries, and a MacVendors API fallback. This gives operators richer inventory context without breaking existing scan behavior.

## Scope

| Area | Change |
|------|--------|
| `src/enrichment/` | New module: `mod.rs`, `snmp.rs`, `mdns.rs`, `mac_vendor.rs` |
| `src/scanner/models.rs` | Add `device_model: Option<String>` to `DiscoveredHost`; add `Protocol::Udp` variant |
| `src/cli/mod.rs` | New pipeline step `[3/5] Enriching device info` after OUI lookup |
| `Cargo.toml` | Add `mdns-sd`, `async-snmp` crates |

## Approach

### SNMP
- Always attempted on every discovered host
- UDP port 161, community `public`, 1s timeout
- OIDs: `sysDescr` (→ `os_hint`), `sysName` (→ `hostname`)
- Non-fatal: errors logged at `debug` level, scan continues

### mDNS
- Passive listen + active query per host, 2s window
- Populates `hostname` (from PTR/A records) and `device_model` (from TXT records)
- Runs concurrently for all hosts via `tokio::task::JoinSet`
- **Risk**: fails silently in Docker bridge networks — user warned at startup if Docker bridge is detected

### MacVendors API
- Opt-in via `--mac-api` CLI flag
- Called only when local OUI lookup returns no vendor
- Rate-limited: 1 request/second (`tokio::time::sleep`)
- Populates `vendor` field (already exists on `DiscoveredHost`)

### Pipeline Integration
- New `EnrichmentConfig` struct passed from CLI args
- Enrichment step runs after OUI lookup, before report generation
- All enrichment errors are non-fatal

## Out of Scope

- SNMP write operations
- SNMPv3 authentication
- mDNS service advertisement
- Paid MacVendors API tiers

## Rollback Plan

Feature is additive. Removing `src/enrichment/` and reverting `models.rs` + `cli/mod.rs` restores prior behavior with no data loss.
