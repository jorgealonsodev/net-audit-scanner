# Delta for Network Discovery

## ADDED Requirements

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

## MODIFIED Requirements

### Requirement: REQ-DISC-7 Scanner Orchestrator

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

### Requirement: REQ-DISC-8 CLI Integration

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