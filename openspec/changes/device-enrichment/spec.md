# Spec: device-enrichment

## Requirements

### REQ-ENR-1: SNMP Probe

- System MUST probe UDP port 161 with SNMPv2c community `public`
- Timeout: 1 second per host
- OIDs queried: `1.3.6.1.2.1.1.1.0` (sysDescr), `1.3.6.1.2.1.1.5.0` (sysName)
- `sysDescr` result populates `DiscoveredHost.os_hint` (overrides fingerprint result only if currently empty)
- `sysName` result populates `DiscoveredHost.hostname` (overrides only if currently empty)
- Failure is non-fatal; logged at `tracing::debug!`

### REQ-ENR-2: mDNS Discovery

- System MUST perform passive listen + active query (PTR `_services._dns-sd._udp.local`) per host
- Window: 2 seconds
- PTR/A records populate `DiscoveredHost.hostname` (overrides only if currently empty)
- TXT `model=` key populates `DiscoveredHost.device_model`
- All hosts queried concurrently via `tokio::task::JoinSet`
- Failure is non-fatal; logged at `tracing::debug!`
- If Docker bridge network is detected at startup, emit `tracing::warn!` about mDNS multicast limitations

### REQ-ENR-3: MacVendors API Fallback

- System MUST only call the API when `--mac-api` flag is present AND OUI lookup returned no vendor
- Rate limit: maximum 1 request per second (enforced with `tokio::time::sleep(Duration::from_secs(1))`)
- API endpoint: `https://api.macvendors.com/{mac}`
- Response populates `DiscoveredHost.vendor`
- HTTP 4xx/5xx responses are non-fatal; logged at `tracing::debug!`

### REQ-ENR-4: `device_model` Field

- `DiscoveredHost` struct MUST have field `device_model: Option<String>`
- Field MUST be serialized to JSON output and HTML report
- Default value: `None`

### REQ-ENR-5: `Protocol::Udp` Variant

- `Protocol` enum in `src/scanner/models.rs` MUST include a `Udp` variant
- Existing `Tcp` variant behavior unchanged
- `Protocol::Udp` used in SNMP port representation

### REQ-ENR-6: Non-Fatal Enrichment

- ANY enrichment error (network timeout, DNS failure, API error) MUST NOT abort the scan
- Errors MUST be logged at `tracing::debug!` level
- Partial enrichment results (e.g., SNMP succeeds, mDNS fails) MUST be accepted

### REQ-ENR-7: Bounded Concurrent Execution

- SNMP and mDNS enrichment per host MUST run concurrently using `tokio::task::JoinSet`
- Each task MUST be bounded by its respective timeout (SNMP: 1s, mDNS: 2s)
- MacVendors requests MUST be sequential (rate-limit constraint)
- Total enrichment step MUST complete within `max(mDNS_timeout) + n_hosts * mac_api_delay` worst case

## Test Scenarios

| ID | Req | Scenario | Expected |
|----|-----|----------|----------|
| T-ENR-1a | ENR-1 | SNMP responds with sysDescr | `os_hint` updated |
| T-ENR-1b | ENR-1 | SNMP responds with sysName | `hostname` updated |
| T-ENR-1c | ENR-1 | SNMP times out (1s) | No crash, debug log |
| T-ENR-1d | ENR-1 | SNMP port closed | No crash, debug log |
| T-ENR-2a | ENR-2 | mDNS returns PTR record | `hostname` updated |
| T-ENR-2b | ENR-2 | mDNS returns TXT `model=` | `device_model` updated |
| T-ENR-2c | ENR-2 | mDNS window expires with no reply | No crash, debug log |
| T-ENR-3a | ENR-3 | `--mac-api` absent | API never called |
| T-ENR-3b | ENR-3 | `--mac-api` present, OUI empty | API called, vendor updated |
| T-ENR-3c | ENR-3 | `--mac-api` present, OUI has vendor | API NOT called |
| T-ENR-3d | ENR-3 | API returns 429 | Non-fatal, debug log |
| T-ENR-4a | ENR-4 | Host with device_model serialized | JSON contains `device_model` key |
| T-ENR-5a | ENR-5 | Protocol::Udp used for SNMP | Compiles, no regression |
| T-ENR-6a | ENR-6 | All enrichment fails | Scan result returned normally |
| T-ENR-7a | ENR-7 | 10 hosts enriched concurrently | Completes within ~2s (mDNS bound) |
