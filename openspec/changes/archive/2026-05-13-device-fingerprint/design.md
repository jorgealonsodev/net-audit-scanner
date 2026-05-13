# Design: Device Fingerprint — TTL + Banner OS Hints

## Architecture

```
src/fingerprint/mod.rs          # infer_os_from_banner(), ttl_to_os_hint()
src/scanner/models.rs           # DiscoveredHost gains os_hint field
src/scanner/discovery.rs        # icmp_sweep() extracts TTL; merge_results() populates os_hint
src/scanner/services.rs         # Unchanged — banner already captured
```

## Data Flow

```
ICMP Reply (pnet) ──► extract TTL ──► ttl_to_os_hint() ──┐
                                                          ├──► DiscoveredHost.os_hint
TCP Banner (grab_banner) ──► infer_os_from_banner() ─────┘
```

## TTL Extraction from ICMP Replies

The existing `icmp_sweep()` receives raw IP packets via pnet's `TransportChannelType::Layer3`. The reply bytes contain the full IP header followed by the ICMP payload.

### IP Header Layout (IPv4)
```
Byte 0:    Version (4 bits) + IHL (4 bits) → IHL × 4 = header length
Byte 8:    TTL (1 byte)
Bytes 12-15: Source IP
Bytes 16-19: Destination IP
```

The TTL is at byte offset 8 in the IP header. The IHL at byte 0 (lower nibble) tells us the header length in 32-bit words (typically 5 = 20 bytes).

### Implementation in `icmp_sweep()`

Currently, `icmp_sweep()` receives `reply_bytes` from the pnet iterator. The first bytes are the IP header. We extract:

```rust
fn extract_ttl_from_ip_header(packet: &[u8]) -> Option<u8> {
    if packet.len() < 20 {
        return None;
    }
    let ihl = (packet[0] & 0x0F) as usize * 4;
    if packet.len() < ihl + 8 {
        return None;
    }
    Some(packet[ihl + 8])  // TTL is at offset 8 within IP header
}
```

Wait — pnet's `icmp_packet_iter` returns the ICMP payload, not the raw IP packet. We need to check what `reply_bytes` actually contains. Looking at the current code:

```rust
let reply_bytes: Vec<u8> = reply.packet().to_vec();
```

The `reply` is an `IcmpPacket` from the Layer3 channel. Layer3 channels return the full IP packet (IP header + ICMP payload). So `reply_bytes[0]` is the IP header start, and `reply_bytes[8]` is the TTL.

Actually, pnet's Layer3 behavior: the packet returned starts at the IP header. So TTL is at `reply_bytes[8]` directly (standard IPv4 header, IHL=5).

### TTL → OS Mapping

```rust
pub fn ttl_to_os_hint(ttl: u8) -> Option<&'static str> {
    match ttl {
        60..=64 => Some("Linux/macOS"),
        120..=128 => Some("Windows"),
        250..=254 => Some("FreeBSD"),
        _ => None, // Too many hops or unknown initial TTL
    }
}
```

## Banner-Based OS Inference

```rust
pub fn infer_os_from_banner(banner: &str) -> Option<String> {
    let lower = banner.to_lowercase();

    // Linux distros (check before generic "linux")
    if lower.contains("ubuntu") {
        return Some("Ubuntu Linux".into());
    }
    if lower.contains("debian") {
        return Some("Debian Linux".into());
    }
    if lower.contains("centos") || lower.contains("red hat") || lower.contains("rhel") {
        return Some("RHEL/CentOS Linux".into());
    }

    // Windows
    if lower.contains("microsoft") || lower.contains("windows") {
        return Some("Windows".into());
    }

    // FreeBSD
    if lower.contains("freebsd") {
        return Some("FreeBSD".into());
    }

    // Generic Linux (SSH banners often contain "Linux")
    if lower.contains("linux") {
        return Some("Linux".into());
    }

    // Cisco IOS
    if lower.contains("cisco") || lower.contains("ios") {
        return Some("Cisco IOS".into());
    }

    None
}
```

## Integration Point: `merge_results()`

The `merge_results()` function currently builds `DiscoveredHost` without `os_hint`. After this change:

1. `icmp_sweep()` returns `PingResult` with an optional `ttl_hint: Option<String>` field
2. Banners are available on `OpenPort` after `scan_ports()` runs
3. `merge_results()` (or a post-merge step) resolves the final `os_hint`:
   - Banner hint takes priority over TTL hint
   - If only TTL hint exists, use it
   - If neither, `os_hint` is `None`

### Option A: Extend `PingResult` with TTL hint
Add `ttl_hint: Option<String>` to `PingResult`. `merge_results()` uses it to set `os_hint` on the host. Banner-based hints are applied later in `scan_ports()` or a dedicated `apply_fingerprint()` step.

### Option B: Post-merge fingerprint pass (chosen)
Keep `PingResult` unchanged. After `merge_results()` and `scan_ports()`, a new `apply_os_hints(hosts)` function:
- Extracts TTL hints from a cached ICMP response map
- Scans all `OpenPort.banner` values through `infer_os_from_banner()`
- Merges signals per host (banner > TTL)

**Decision**: Option A is simpler — extend `PingResult` with `ttl_hint`, set `os_hint` during merge. Banner hints are applied in a second pass after `scan_ports()` populates banners. This avoids restructuring the entire pipeline.

## Sequence: Host Discovery with OS Hints

```
1. icmp_sweep() → PingResult { ip, alive, rtt_ms, ttl_hint }
2. tcp_sweep()  → PingResult { ip, alive, rtt_ms, ttl_hint: None }
3. merge_results() → DiscoveredHost { ..., os_hint: ttl_hint }
4. scan_ports() → DiscoveredHost { ..., open_ports: [OpenPort { banner }] }
5. apply_banner_hints() → for each host, scan banners, override os_hint if found
```

Step 5 can be integrated into `scan_ports()` itself — after building each `OpenPort`, check its banner through `infer_os_from_banner()` and update the host's `os_hint` if a match is found.

## Test Strategy

- Unit tests for `ttl_to_os_hint()` covering all ranges and edge cases
- Unit tests for `infer_os_from_banner()` with real-world banner strings
- Integration test: `DiscoveredHost` serialization round-trip with `os_hint`
- Existing tests updated to include `os_hint: None` in struct literals
