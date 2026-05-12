# Network Discovery Specification

## Purpose

Discover live hosts via ICMP, TCP, and ARP with permission-aware fallback.

## Requirements

### REQ-DISC-1: Permission Detection

| Field | Value |
|-------|-------|
| Statement | Detect root/CAP_NET_RAW and report capabilities (ICMP, raw sockets, ARP). |
| Priority | P1 |
| Depends on | None |

- GIVEN process runs as root → `Capabilities { icmp: true, raw_sockets: true, arp_table: true }`
- GIVEN non-root without CAP_NET_RAW → `Capabilities { icmp: false, raw_sockets: false, arp_table: true }`
- GIVEN non-root with CAP_NET_RAW → `icmp: true, raw_sockets: true`

---

### REQ-DISC-2: Auto-detect Local Network

| Field | Value |
|-------|-------|
| Statement | `--network auto` selects first non-loopback IPv4 interface CIDR. Explicit CIDR bypasses detection. Error if no interface found. |
| Priority | P1 |
| Depends on | REQ-DISC-1 |

- GIVEN `eth0` with `192.168.1.42/24` → `resolve_network("auto")` returns `192.168.1.0/24`
- GIVEN only loopback → `resolve_network("auto")` returns error
- GIVEN `--network 10.0.0.0/16` → returns `10.0.0.0/16` directly

---

### REQ-DISC-3: CIDR Expansion

| Field | Value |
|-------|-------|
| Statement | Convert CIDR to host IPs, exclude network/broadcast. /31 and /32 include all per RFC 3021. Warn on />/16. |
| Priority | P1 |
| Depends on | None |

- GIVEN `192.168.1.0/24` → 254 IPs (.1 through .254)
- GIVEN `192.168.1.1/32` → `[192.168.1.1]`
- GIVEN `10.0.0.0/8` → warning emitted, list still returned

---

### REQ-DISC-4: ICMP Ping Sweep

| Field | Value |
|-------|-------|
| Statement | Send ICMP echo to all IPs concurrently (bounded). 2s timeout. Record responders as `method: Icmp`. |
| Priority | P1 |
| Depends on | REQ-DISC-1, REQ-DISC-3 |

- GIVEN ICMP available, host `.10` responds → yielded with `method: Icmp`
- GIVEN ICMP available, host `.99` silent 2s → not yielded

---

### REQ-DISC-5: TCP Connect Probe

| Field | Value |
|-------|-------|
| Statement | TCP connect to ports 22, 80, 443. Connect or RST = live host. 1s timeout. `method: Tcp`. |
| Priority | P1 |
| Depends on | REQ-DISC-3 |

- GIVEN host `.10` runs SSH → yielded with `method: Tcp`
- GIVEN host `.20` alive, RST on all ports → yielded with `method: Tcp`
- GIVEN host `.30` offline, timeout → not yielded

---

### REQ-DISC-6: ARP Table Reading

| Field | Value |
|-------|-------|
| Statement | Parse `/proc/net/arp` for IP-MAC mappings. Gate to Linux (`#[cfg(target_os = "linux")]`). Parse failures log warning, return empty. |
| Priority | P2 |
| Depends on | None |

- GIVEN `/proc/net/arp` has entry `.1` → MAC `aa:bb:cc:dd:ee:ff` → mapping yielded
- GIVEN non-Linux OS → empty list, no panic

---

### REQ-DISC-7: Scanner Orchestrator

| Field | Value |
|-------|-------|
| Statement | Run all available methods concurrently, merge and deduplicate by IP (prefer MAC from ARP, hostname from reverse DNS). |
| Priority | P1 |
| Depends on | REQ-DISC-1, REQ-DISC-4, REQ-DISC-5, REQ-DISC-6 |

- GIVEN ICMP `.10`, TCP `.10`+`.20`, ARP `.10` with MAC → `.10` once (MAC from ARP, method Icmp), `.20` with method Tcp
- GIVEN all methods yield nothing → empty `Vec<DiscoveredHost>`, not error

---

### REQ-DISC-8: CLI Integration

| Field | Value |
|-------|-------|
| Statement | `scan --network <CIDR|auto>` runs discovery pipeline. Output table: IP, MAC, Hostname, Method. |
| Priority | P1 |
| Depends on | REQ-DISC-2, REQ-DISC-7 |

- GIVEN root, typical network → `netascan scan --network auto` prints table with 4 columns
- GIVEN any privilege → `netascan scan --network 192.168.1.0/24` runs against that range

---

### REQ-DISC-9: Graceful Degradation

| Field | Value |
|-------|-------|
| Statement | Non-root gets TCP+ARP results. Print warning listing unavailable methods. Never error solely for missing privilege. |
| Priority | P1 |
| Depends on | REQ-DISC-1, REQ-DISC-7 |

- GIVEN non-root on Linux → warning "ICMP sweep unavailable", TCP+ARP results returned
- GIVEN root, responsive network → no warning, ICMP results included