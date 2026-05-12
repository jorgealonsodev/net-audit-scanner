# Design: Port Scanner + Service Detection

## Technical Approach

Extend the existing `Scanner` struct with an async `scan_ports()` method that takes `Vec<DiscoveredHost>` and returns enriched hosts with `Vec<OpenPort>` replacing `Vec<u16>`. Three new concerns split into two files: `ports.rs` (const port lists + resolver) and `services.rs` (banner grab + service classification + insecure flagging). New types (`OpenPort`, `ServiceType`, `Protocol`) live in `models.rs` alongside existing models. The concurrency model uses a flat `Semaphore` across all port probes — simpler to implement, avoids per-host starvation, and reuses the pattern from `tcp_sweep()`. Banner grabbing reads up to 256 bytes with a 500ms deadline after connect. Service detection is port-first lookup table, refined by banner content where available.

## Architecture Decisions

### Decision: Port lists — const slices with Vec dedup

| Option | Tradeoff | Decision |
|--------|----------|----------|
| `const PORT_LIST: &[u16]` slices, merge via `Vec::extend` + `sort` + `dedup` | Zero-dep, compile-time embedded, easy to read/maintain | **Chosen** |
| `phf` map for port → service | Faster lookup but overkill for ≤65535 entries, adds dep | Rejected |

**Rationale**: Port lists are static data. `const` slices compile inline, no heap allocation for the base lists. Merging is `O(n log n)` once per scan — negligible. `phf` adds a dependency for a one-time sort+dedup that's fast enough. IoT critical ports are always merged into the resolved list.

### Decision: Concurrency — flat global semaphore

| Option | Tradeoff | Decision |
|--------|----------|----------|
| Flat `Semaphore(concurrency)` across all `(host, port)` probes | Simple, fair scheduling, consistent with `tcp_sweep()` pattern | **Chosen** |
| Two-level: per-host semaphore × N hosts | More complex, avoids starving single host, but adds bookkeeping for marginal gain | Rejected |

**Rationale**: The existing `tcp_sweep()` uses a single semaphore. Consistency matters. A two-level model adds complexity (nested `Arc<Semaphore>`, per-host limits) without measurable benefit for ≤1000 probes on a /24 network. Flat semaphore is what the codebase already does.

### Decision: Banner timeout — separate from connect timeout

| Option | Tradeoff | Decision |
|--------|----------|----------|
| 500ms banner timeout (separate from `timeout_ms` connect) | Decouples two concerns; slow-connect hosts don't eat banner budget | **Chosen** |
| Shared timeout covering both connect + banner | Simpler but penalizes slow networks, unpredictable behavior | Rejected |

**Rationale**: Connect and banner-grab have different latency profiles. A LAN host connects in <5ms but a service may send a banner slowly. Separate timeouts let users tune connect aggressiveness independently of banner patience.

### Decision: Service classification — port lookup + string matching

| Option | Tradeoff | Decision |
|--------|----------|----------|
| Static `const` lookup table `(port, service)`, banner refinement via `str::contains` (case-insensitive) | Zero-dep, covers known ports, banner catches HTTP/SSH/FTP hello strings | **Chosen** |
| Regex on banner | More flexible but adds `regex` crate for 5 patterns | Rejected |

**Rationale**: We need to classify ~10 services. Banners follow predictable patterns: SSH starts with "SSH-", HTTP responses contain "HTTP/", FTP has "220" greeting. `str::contains` with `.to_ascii_lowercase()` is sufficient. Regex is overkill.

### Decision: `open_ports` type change — `Vec<u16>` → `Vec<OpenPort>`

| Option | Tradeoff | Decision |
|--------|----------|----------|
| Change `open_ports: Vec<u16>` to `Vec<OpenPort>` in `DiscoveredHost` | Breaking change, but `open_ports` was always populated empty or with discovery-only ports | **Chosen** |
| Add separate `detailed_ports: Vec<OpenPort>` field alongside | No breaking change, but duplicate data, confusing API | Rejected |

**Rationale**: Current `open_ports` is set to `vec![]` by `merge_results()` and the TCP sweep TODO notes it's not integrated. This is the right moment to change the type. Existing tests that construct `DiscoveredHost` with `open_ports: vec![22, 80]` get trivial migration to `open_ports: vec![]` (discovery-only) or explicit `OpenPort` structs for port-scan tests.

## Data Flow

```
CLI (scan subcommand)
        │
        ▼
  Scanner::new(config)
        │
        ├── discover_network() → Vec<DiscoveredHost>
        │
        ▼
  resolve_port_list(config.port_range, args.full, args.port_range)
        │  ──→ PORT_LIST_TOP_100 | PORT_LIST_TOP_1000 | 1..65535 | custom
        │  ──→ always merge IOT_CRITICAL_PORTS
        │
        ▼
  scan_ports(hosts, port_list, concurrency, timeout_ms, banner_timeout_ms)
        │
        ├─ for each host ── for each port ──→ TcpStream::connect_with_timeout
        │                                            │
        │                                            ├── connect OK ──→ grab_banner()
        │                                            │                    └── timeout(500ms, read ≤256 bytes)
        │                                            │
        │                                            └── connect fail ──→ skip (port closed/filtered)
        │
        ├─ classify_service(port, banner) ──→ ServiceType
        │
        ├─ is_insecure(port, service, host_has_https) ──→ bool
        │
        ▼
  Vec<DiscoveredHost> (enriched with Vec<OpenPort>)
        │
        ▼
  format_hosts_table() → stdout
```

## File Changes

| File | Action | Description |
|------|--------|-------------|
| `src/scanner/ports.rs` | Create | `PORT_LIST_TOP_100`, `PORT_LIST_TOP_1000`, `IOT_CRITICAL_PORTS` const slices; `resolve_port_list()` that merges + dedups |
| `src/scanner/services.rs` | Create | `grab_banner()`, `classify_service()`, `is_insecure()`, `KNOWN_PORTS` lookup table |
| `src/scanner/models.rs` | Modify | Add `OpenPort`, `ServiceType`, `Protocol`; change `open_ports` from `Vec<u16>` to `Vec<OpenPort>` |
| `src/scanner/discovery.rs` | Modify | Add `scan_ports()` method; fix `tcp_sweep` TODO to populate `open_ports` |
| `src/scanner/mod.rs` | Modify | Re-export `ports`, `services` modules and new types |
| `src/cli/scan.rs` | Modify | Add `--port-range` arg; pass `full`/`port_range` to scanner |
| `src/cli/mod.rs` | Modify | Wire port scan step after discovery; fix hardcoded `"top-1000"` |
| `src/config/mod.rs` | Modify | Add `banner_timeout_ms` field to `ScanConfig` |

## Interfaces / Contracts

```rust
// src/scanner/models.rs — additions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenPort {
    pub port: u16,
    pub service: ServiceType,
    pub banner: Option<String>,
    pub protocol: Protocol,
    pub is_insecure: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ServiceType {
    Http, Https, Ssh, Telnet, Ftp, Rtsp, Mqtt, Upnp, Smtp, Dns, Unknown(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Tcp,
}

// DiscoveredHost.open_ports changes type:
pub open_ports: Vec<OpenPort>,  // was Vec<u16>

// src/scanner/ports.rs
pub const PORT_LIST_TOP_100: &[u16] = &[...];
pub const PORT_LIST_TOP_1000: &[u16] = &[...];
pub const IOT_CRITICAL_PORTS: &[u16] = &[...];

pub fn resolve_port_list(range: &str, full: bool, custom_range: Option<&str>) -> Vec<u16>;

// src/scanner/services.rs
pub async fn grab_banner(stream: &mut TcpStream, timeout_ms: u64) -> Option<String>;
pub fn classify_service(port: u16, banner: &Option<String>) -> ServiceType;
pub fn is_insecure(port: u16, service: &ServiceType, host_has_https: bool) -> bool;

// src/scanner/discovery.rs — new method
impl Scanner {
    pub async fn scan_ports(
        &self,
        hosts: Vec<DiscoveredHost>,
        ports: &[u16],
        caps: &Capabilities,
    ) -> Result<Vec<DiscoveredHost>, Error>;
}

// src/cli/scan.rs — new arg
pub struct ScanArgs {
    // ...existing...
    /// Custom port range (e.g., "22,80,443" or "1-1024")
    #[arg(long)]
    pub port_range: Option<String>,
}

// src/config/mod.rs — addition
pub struct ScanConfig {
    pub banner_timeout_ms: u64,  // default 500
}
```

## Testing Strategy

| Layer | What | Approach |
|-------|------|----------|
| Unit | `resolve_port_list("top-100", false, None)` returns 100 ports + IoT | `#[cfg(test)]` in `ports.rs` |
| Unit | `resolve_port_list("top-1000", false, None)` returns 1000+ ports (IoT merged, deduped) | `#[cfg(test)]` in `ports.rs` |
| Unit | `classify_service(22, &Some("SSH-2.0"))` → `Ssh` | `#[cfg(test)]` in `services.rs` |
| Unit | `classify_service(8080, &None)` → `Http` (port-first) | `#[cfg(test)]` in `services.rs` |
| Unit | `classify_service(8080, &Some("HTTP/1.1 200"))` → `Http` (banner refines) | `#[cfg(test)]` in `services.rs` |
| Unit | `is_insecure(23, &Telnet, false)` → true | `#[cfg(test)]` in `services.rs` |
| Unit | `is_insecure(80, &Http, false)` → true; `is_insecure(80, &Http, true)` → false | `#[cfg(test)]` in `services.rs` |
| Unit | `OpenPort` serialization roundtrip | `#[cfg(test)]` in `models.rs` |
| Integration | Port scan against localhost with `TcpListener` on known port | `tokio::test` spawning listener, then `scan_ports()` |
| Integration | Banner grab reads known response | `tokio::test` — listener sends "SSH-2.0-OpenSSH_8.9\r\n" |
| Integration | CLI `netascan scan --network 127.0.0.1/32 --full` exits 0 | `assert_cmd` integration test |

## Migration / Rollout

**Breaking change**: `DiscoveredHost.open_ports` type changes from `Vec<u16>` to `Vec<OpenPort>`. All tests constructing `DiscoveredHost` must update. The `tcp_sweep` TODO (`// TODO: integrate with DiscoveredHost.open_ports`) is resolved by this change. Migration is mechanical: replace `open_ports: vec![22, 80]` with `open_ports: vec![]` in discovery-only tests, or construct `OpenPort` structs in port-scan tests.

**CLI change**: `--full` flag already exists in `ScanArgs` but is ignored. Wire it. Add `--port-range` for custom ranges. Fix hardcoded `"top-1000"` string in `cli/mod.rs:47`.

No database migration required. No feature flags needed.

## Open Questions

- [x] Port list format: const slices chosen (zero-dep, reasonable lookup speed)
- [x] Concurrency: flat global semaphore chosen (consistent with existing pattern)
- [x] Banner timeout: separate from connect timeout (500ms default)
- [x] Service detection: simple string matching (no regex dep)
- [x] IoT ports: always merged (per proposal: "always merged")
- [ ] Should `ServiceType::Unknown` carry the port number instead of wrapping a `String`? Current design uses `Unknown(String)` for unrecognized service names from banners — could simplify to `Unknown` with no payload, since port number is already in `OpenPort.port`.