# Port Scanning Specification

## Purpose

TCP port scanning, banner grabbing, service classification, and insecure protocol flagging for discovered hosts.

## Requirements

### REQ-PS-1: Embedded Port Lists

| Field | Value |
|-------|-------|
| Statement | The system SHALL embed top-100, top-1000 (nmap-based), and IoT critical port lists as compile-time constants. IoT critical ports (37777, 34567, 554, 8554, 1883, 8883, 8080, 37111, 8081, 28594, 60001) MUST always be merged into any resolved port list. |
| Priority | P1 |
| Depends on | None |

#### Scenario: Top-100 resolution

- GIVEN port_range is "top-100"
- WHEN resolve_port_list is called
- THEN result contains exactly 100 base ports plus all IoT ports, deduplicated and sorted

#### Scenario: Top-1000 resolution

- GIVEN port_range is "top-1000" (default)
- WHEN resolve_port_list is called
- THEN result contains 1000 base ports plus IoT ports, deduplicated

#### Scenario: Full range resolution

- GIVEN --full flag is set
- WHEN resolve_port_list is called
- THEN result contains ports 1 through 65535 plus IoT ports, deduplicated

#### Scenario: Custom port range

- GIVEN port_range is "22-25,80,443"
- WHEN resolve_port_list is called
- THEN result contains {22,23,24,25,80,443} plus IoT ports

#### Scenario: IoT ports always included

- GIVEN any port_range value
- WHEN resolve_port_list is called
- THEN port 37777 (Dahua) and 34567 (HiSilicon) are present in the result

---

### REQ-PS-2: TCP Port Scanning

| Field | Value |
|-------|-------|
| Statement | For each discovered host, the system MUST attempt TCP connect to each port in the resolved list. Concurrency MUST be bounded by ScanConfig.concurrency. Each attempt MUST use ScanConfig.timeout_ms. |
| Priority | P1 |
| Depends on | REQ-PS-1 |

#### Scenario: Open port detected

- GIVEN host 192.168.1.10 has port 22 open
- WHEN scan_ports completes
- THEN OpenPort { port: 22, ... } appears in results

#### Scenario: No open ports

- GIVEN host has no open ports in scan list
- WHEN scan_ports completes
- THEN open_ports field is an empty Vec

#### Scenario: Connection timeout

- GIVEN a port that does not respond within timeout_ms
- WHEN scan_ports completes
- THEN that port is omitted (not an error)

---

### REQ-PS-3: Banner Grabbing

| Field | Value |
|-------|-------|
| Statement | After successful TCP connect, the system MUST read up to 256 bytes with a 500ms read timeout. Banner text MUST be stored in OpenPort.banner. |
| Priority | P1 |
| Depends on | REQ-PS-2 |

#### Scenario: Banner captured

- GIVEN port 22 responds with "SSH-2.0-OpenSSH_8.9\r\n"
- WHEN banner grab executes
- THEN OpenPort.banner is Some("SSH-2.0-OpenSSH_8.9\r\n")

#### Scenario: No initial data

- GIVEN port 80 sends no data within 500ms
- WHEN banner grab executes
- THEN OpenPort.banner is None

#### Scenario: Long banner truncated

- GIVEN port sends 500 bytes immediately
- WHEN banner grab executes
- THEN OpenPort.banner contains exactly the first 256 bytes

---

### REQ-PS-4: Service Detection

| Field | Value |
|-------|-------|
| Statement | The system MUST classify each open port by ServiceType enum: HTTP, HTTPS, SSH, Telnet, FTP, RTSP, MQTT, UPnP, SMTP, DNS, Unknown. Port number is the primary signal; banner content refines classification. |
| Priority | P1 |
| Depends on | REQ-PS-3 |

#### Scenario: Port-based classification

- GIVEN port 22 open → service = SSH
- GIVEN port 1883 open → service = MQTT
- GIVEN port 21 open → service = FTP

#### Scenario: Banner-based refinement

- GIVEN port 8080 open with "HTTP" in banner → service = HTTP
- GIVEN port 8080 open with "RTSP" in banner → service = RTSP

#### Scenario: Unknown service

- GIVEN port 55555 open with unrecognizable banner → service = Unknown

---

### REQ-PS-5: Insecure Protocol Flagging

| Field | Value |
|-------|-------|
| Statement | The system MUST set OpenPort.is_insecure = true for: Telnet (23), FTP (21), HTTP (80 when port 443 is absent on same host), and IoT-specific ports 37777 (Dahua) and 34567 (HiSilicon). |
| Priority | P1 |
| Depends on | REQ-PS-4 |

#### Scenario: Telnet flagged insecure

- GIVEN host has port 23 open → is_insecure = true

#### Scenario: HTTP without HTTPS flagged

- GIVEN host has port 80 open but not 443 → port 80 is_insecure = true

#### Scenario: HTTP with HTTPS not flagged

- GIVEN host has both port 80 and 443 open → port 80 is_insecure = false

#### Scenario: IoT ports flagged

- GIVEN host has port 37777 open → is_insecure = true
- GIVEN host has port 34567 open → is_insecure = true