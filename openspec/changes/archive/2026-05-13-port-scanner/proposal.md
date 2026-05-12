# Proposal: Port Scanner + Service Detection

## Intent

Phase 2 of the MVP: after discovering live hosts, scan their TCP ports, grab banners, classify services, and flag insecure protocols.

## Scope

### In Scope
- TCP port scanning (async tokio connect, configurable concurrency/timeout)
- Embedded port lists: top-100, top-1000 (nmap-based), IoT critical (always merged)
- Banner grabbing (≤256 bytes after TCP connect)
- Service detection: HTTP, SSH, Telnet, FTP, RTSP, MQTT, UPnP, unknown
- Insecure flagging: Telnet (23), FTP (21), HTTP, IoT vulnerable (37777, 34567)
- `OpenPort` struct replaces `Vec<u16>` → `Vec<OpenPort>` in `DiscoveredHost`
- CLI: `--full` (1-65535), `--no-cve`, `port_range` from config

### Out of Scope
- OUI fingerprinting, CVE correlation, report generation, nmap integration, UDP scanning

## Capabilities

### New Capabilities
- `port-scanning`: TCP scanning, banner grabbing, service classification, insecure flagging

### Modified Capabilities
- `network-discovery`: `DiscoveredHost.open_ports` type changes; pipeline extends with port scan step

## Approach

1. **`src/scanner/ports.rs`** (new): const port arrays, `resolve_port_list()` always merges IoT critical
2. **`src/scanner/services.rs`** (new): `grab_banner()`, `classify_service()`, `is_insecure()`
3. **`src/scanner/models.rs`** (mod): Add `OpenPort`, `ServiceType`, `Protocol`; change `open_ports` type
4. **`src/scanner/discovery.rs`** (mod): Add `scan_ports(hosts, port_list)` — async TCP connect + banner + classify
5. **`src/cli/scan.rs`** (mod): Wire `--full` to port list resolver
6. **`src/cli/mod.rs`** (mod): Pipeline: discovery → port scan → output

## Affected Areas

| Area | Impact | Description |
|------|--------|-------------|
| `src/scanner/models.rs` | Modified | Add `OpenPort`, `ServiceType`, `Protocol`; change `open_ports` type |
| `src/scanner/ports.rs` | New | Embedded port lists + resolver |
| `src/scanner/services.rs` | New | Banner grabbing, service classification |
| `src/scanner/discovery.rs` | Modified | Add `scan_ports()` method |
| `src/scanner/mod.rs` | Modified | Re-export new types |
| `src/cli/scan.rs` | Modified | Wire `--full`, extend output |
| `src/cli/mod.rs` | Modified | Integrate port scan pipeline |

## Risks

| Risk | Likelihood | Mitigation |
|------|------------|------------|
| Full scan on /24 too slow | High | Warn if network > /31 |
| Banner grab hangs | Medium | 500ms per-banner timeout |
| Breaking `open_ports` type | Medium | Update all tests; verify serialization |

## Rollback Plan

Revert `port-scanner` change. Restore `open_ports: Vec<u16>`. Remove `ports.rs`, `services.rs`, `OpenPort`.

## Dependencies

- `network-discovery` (archived) — provides `Scanner`, `DiscoveredHost`
- Tokio (already in Cargo.toml)

## Success Criteria

- [ ] `OpenPort` serializes correctly
- [ ] Port list resolver correct; IoT critical always merged
- [ ] Banner grab ≤256 bytes within timeout
- [ ] Service classification identifies all target services
- [ ] Insecure flagging marks Telnet, FTP, HTTP, 37777, 34567
- [ ] `--full` triggers full range scan
- [ ] All tests pass, clippy clean, fmt clean
