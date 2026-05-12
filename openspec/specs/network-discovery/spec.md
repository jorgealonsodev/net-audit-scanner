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
| Statement | Run all available discovery methods concurrently, merge and deduplicate by IP (prefer MAC from ARP, hostname from reverse DNS). After discovery, invoke port scanning on each host to populate open_ports with OpenPort records including service classification and insecure flagging. Full pipeline: discovery → port scan → classification → flagging. |
| Priority | P1 |
| Depends on | REQ-DISC-1, REQ-DISC-4, REQ-DISC-5, REQ-DISC-6 |

(Previously: Discovery only — run all probes concurrently, merge and deduplicate. No port scanning step.)

#### Scenario: Full pipeline with port scan

- GIVEN ICMP finds `.10`, TCP finds `.10`+`.20`, ARP provides MAC for `.10`
- WHEN discover_network completes
- THEN `.10` and `.20` each have Vec<OpenPort> populated by port scanning

#### Scenario: No hosts discovered — no port scan

- GIVEN all discovery methods yield nothing
- WHEN discover_network completes
- THEN empty `Vec<DiscoveredHost>`, no port scan executed

#### Scenario: Discovery only still works

- GIVEN ICMP `.10` responds, TCP `.10` responds, ARP `.10` with MAC
- WHEN discovery + port scan runs
- THEN `.10` appears once (MAC from ARP, method Merged) with populated open_ports

---

### REQ-DISC-8: CLI Integration

| Field | Value |
|-------|-------|
| Statement | `scan --network <CIDR|auto>` runs the full pipeline (discovery → port scan → classification → flagging). `--full` scans all 65535 ports. `--no-cve` skips CVE lookup. Port list resolution uses ScanConfig.port_range ("top-100", "top-1000", or custom range). Output table: IP, MAC, Hostname, Method, Ports. |
| Priority | P1 |
| Depends on | REQ-DISC-2, REQ-DISC-7 |

(Previously: Discovery only. Output table: IP, MAC, Hostname, Method. --full flag existed but was ignored; port_range was hardcoded to "top-1000".)

#### Scenario: Default scan output

- GIVEN root, typical network
- WHEN `netascan scan --network auto` runs
- THEN table shows columns: IP, MAC, Hostname, Method, Ports

#### Scenario: Explicit CIDR

- GIVEN any privilege
- WHEN `netascan scan --network 192.168.1.0/24` runs
- THEN scan runs against that range with resolved port list

#### Scenario: --full flag wired

- GIVEN `netascan scan --network 192.168.1.0/24 --full`
- WHEN port list is resolved
- THEN all 65535 ports are scanned (plus IoT ports)

#### Scenario: port_range from config

- GIVEN ScanConfig.port_range = "top-100"
- WHEN `netascan scan` runs without --full
- THEN port list resolves to top-100 + IoT ports

---

### REQ-DISC-9: Graceful Degradation

| Field | Value |
|-------|-------|
| Statement | Non-root gets TCP+ARP results. Print warning listing unavailable methods. Never error solely for missing privilege. |
| Priority | P1 |
| Depends on | REQ-DISC-1, REQ-DISC-7 |

- GIVEN non-root on Linux → warning "ICMP sweep unavailable", TCP+ARP results returned
- GIVEN root, responsive network → no warning, ICMP results included

---

### REQ-DISC-10: OpenPort Data Model

| Field | Value |
|-------|-------|
| Statement | DiscoveredHost.open_ports MUST change from `Vec<u16>` to `Vec<OpenPort>`. OpenPort MUST contain port (u16), service (ServiceType), banner (Option<String>), protocol (Protocol), is_insecure (bool). ServiceType and Protocol MUST derive Serialize, Deserialize, Clone, Debug. |
| Priority | P1 |
| Depends on | port-scanning REQ-PS-4 |

#### Scenario: OpenPort serializes to JSON

- GIVEN OpenPort { port: 22, service: SSH, banner: Some("SSH-2.0-..."), protocol: Tcp, is_insecure: false }
- WHEN serialized to JSON
- THEN result is a valid JSON object with fields: port, service, banner, protocol, is_insecure

#### Scenario: Empty open_ports backward compatible

- GIVEN DiscoveredHost constructed with open_ports: vec![]
- WHEN compiled after type change
- THEN compilation succeeds (Vec<OpenPort> accepts empty vec)

---

### REQ-DISC-11: Full Scan Warning

| Field | Value |
|-------|-------|
| Statement | When --full flag is set and the target network has a prefix smaller than /31 (i.e., more than 2 host addresses), the system MUST emit a warning about scan duration. |
| Priority | P2 |
| Depends on | REQ-DISC-8 |

#### Scenario: Large network warning

- GIVEN `--full --network 192.168.1.0/24`
- WHEN CLI parses arguments
- THEN a warning is emitted: scanning 65535 ports on 254 hosts may take significant time

#### Scenario: Small network no warning

- GIVEN `--full --network 192.168.1.0/31`
- WHEN CLI parses arguments
- THEN no warning is emitted