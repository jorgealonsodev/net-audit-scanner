# Proposal: Network Discovery

## Intent

Implement the first real feature of `netascan`: discovering live hosts on the local network. Users need `netascan scan --network auto` to work end-to-end — auto-detecting the local subnet, finding hosts via ICMP/TCP/ARP, and outputting a deduplicated host list. Non-root users must still get useful results via graceful degradation.

## Scope

### In Scope
- **Permission detection**: Check root/CAP_NET_RAW, report available capabilities
- **Auto-detect local network**: Parse interfaces via pnet, compute primary CIDR
- **CIDR expansion**: Convert CIDR to individual IP list
- **Ping sweep**: ICMP echo (privileged) + TCP connect fallback (non-privileged)
- **ARP table reading**: Parse `/proc/net/arp` for MAC addresses (no root needed)
- **Scanner orchestrator**: Merge results from all discovery methods, deduplicate by IP
- **CLI integration**: Wire `--network auto` and `--network 192.168.1.0/24` into `scan` handler
- **Graceful degradation**: Non-root users get TCP sweep + ARP parsing only
- **Host model**: `DiscoveredHost { ip, mac, hostname, method }`

### Out of Scope
- Port scanning (next change)
- OUI/fingerprinting (next change)
- CVE correlation (next change)
- Report generation (next change)
- nmap integration

## Capabilities

### New Capabilities
- `network-discovery`: Host discovery via ICMP/TCP/ARP, CIDR resolution, permission-aware execution, orchestrator merging, CLI `scan --network` integration

### Modified Capabilities
- None

## Approach

Layered discovery with permission-aware fallback:

1. **Privilege check** at startup → determines ICMP availability
2. **Network resolution**: `auto` → pnet interfaces → primary non-loopback CIDR; explicit CIDR → parse directly
3. **Parallel discovery**: ICMP sweep (root) + TCP connect sweep (all) + ARP table parse (all) run concurrently via tokio
4. **Merge & deduplicate**: Orchestrator collects results, keyed by IP, prefers richest data (MAC from ARP, method from first responder)
5. **Output**: Print table to stdout; return `Vec<DiscoveredHost>` for future pipeline stages

## Affected Areas

| Area | Impact | Description |
|------|--------|-------------|
| `src/scanner/mod.rs` | Modified | Re-export discovery types and orchestrator |
| `src/scanner/discovery.rs` | New | Core discovery: ICMP, TCP, ARP, CIDR expansion |
| `src/scanner/models.rs` | New | `DiscoveredHost`, `DiscoveryMethod`, `Capabilities` types |
| `src/scanner/orchestrator.rs` | New | Merge/deduplicate results from parallel discovery |
| `src/scanner/permissions.rs` | New | Root/CAP_NET_RAW detection |
| `src/scanner/network.rs` | New | Interface parsing, CIDR auto-detection via pnet |
| `src/cli/scan.rs` | Modified | Wire discovery execution into scan handler |
| `src/error.rs` | Modified | Add `Permission` and `Discovery` error variants |
| `Cargo.toml` | Modified | Add `libc` dependency for capability checks |

## Risks

| Risk | Likelihood | Mitigation |
|------|------------|------------|
| pnet raw socket requires libpcap-dev | High | Already a scaffold dependency; document in README |
| ICMP requires root — silent failure on non-root | Medium | Graceful degradation to TCP+ARP; warn user |
| CIDR /16+ produces huge IP lists (65k hosts) | Medium | Warn on large ranges; respect concurrency limit from config |
| `/proc/net/arp` not available on macOS/BSD | Medium | Gate ARP parsing to Linux; skip gracefully on other OS |
| Oversized PR (>400 lines) | Medium | Split into 2 commits: models+permissions first, then discovery+orchestrator |

## Rollback Plan

`git revert` the merge commit for this change. All new files are under `src/scanner/`; CLI changes are additive (scan handler was a stub). No existing behavior is modified beyond replacing the stub print with real logic.

## Dependencies

- `libc` crate (for `geteuid()` and capability checks) — add to `Cargo.toml`
- Existing: `pnet`, `ipnetwork`, `macaddr`, `tokio` (already in scaffold)

## Success Criteria

- [ ] `cargo build` succeeds with zero warnings
- [ ] `cargo test` passes (unit tests for CIDR expansion, merge/dedup, permission check)
- [ ] `netascan scan --network auto` discovers hosts on local network (root)
- [ ] `netascan scan --network 192.168.1.0/24` works with explicit CIDR
- [ ] Non-root execution falls back to TCP+ARP with a warning message
- [ ] Output includes IP, MAC (when available), hostname (when available), and discovery method
- [ ] `cargo clippy` passes with zero warnings
