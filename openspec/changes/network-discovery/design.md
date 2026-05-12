# Design: Network Discovery

## Technical Approach

Scanner struct owns a `ScanConfig` (by value — single-owner lifecycle). Discovery runs three probes concurrently via `tokio::join!`, merges results by IP, and returns `Vec<DiscoveredHost>`. Non-root users skip ICMP and receive a warning — TCP connect + ARP still produce useful output. Module is split into `discovery.rs` (orchestrator + ICMP/TCP/ARP logic), `capabilities.rs` (permission + interface detection), and `models.rs` (data types). CLI handler formats output as a plain-text table to stdout; structured JSON goes through the report module in a future change.

## Architecture Decisions

### Decision: Scanner struct — owned config vs Arc

| Option | Tradeoff | Decision |
|--------|----------|----------|
| Owned `ScanConfig` | Single owner, no lock overhead, simple lifetime | **Chosen** |
| `Arc<ScanConfig>` | Shareable, but Scanner lives on one task during `discover_network` | Rejected |

**Rationale**: `discover_network` is a single async call. Scanner doesn't need shared config across concurrent tasks — the probes borrow `&self` inside one `tokio::join!` scope. Owned value is simpler and zero-cost.

### Decision: TCP probe — parallel ports per host

| Option | Tradeoff | Decision |
|--------|----------|----------|
| Parallel ports per host (futures + `FuturesUnordered`) | Fast per host, matches ICMP behavior | **Chosen** |
| Sequential ports per host | Simpler, but ~25× slower for 25 ports per host | Rejected |

**Rationale**: ICMP sends one probe per host. TCP should mirror that speed. Probe up to 7 common ports (22, 23, 80, 443, 554, 8080, 8443) per host in parallel — host is considered "up" on first successful connect. Each connect has the same `timeout_ms` from config.

### Decision: ARP parser — manual string split

| Option | Tradeoff | Decision |
|--------|----------|----------|
| Manual `split_whitespace()` on each line | Zero-dep, `/proc/net/arp` format is fixed columnar, handles kernel variations by column index | **Chosen** |
| Regex | Readable, but another dep for trivial parsing, regex crate adds compile time | Rejected |

**Rationale**: `/proc/net/arp` has a fixed 4-column format: `IP address HW type Flags HW address Mask Device`. `split_whitespace()` with column-index validation handles kernel format variations reliably. Regex is overkill.

### Decision: Output format — plain-text table now, JSON via report module later

| Option | Tradeoff | Decision |
|--------|----------|----------|
| Plain-text table to stdout | Immediate, matches RDP "scan outputs to console", no serde needed for MVP | **Chosen** |
| JSON to stdout | Structured, but report module owns JSON output per RDP §4.6 | Rejected (defer) |

**Rationale**: RDP §4.6 designates the report module for JSON/HTML. The `scan` command prints a readable table. `DiscoveredHost` implements `Serialize` so future report integration is zero-cost.

### Decision: File split — 3 files in scanner/

| Option | Tradeoff | Decision |
|--------|----------|----------|
| `discovery.rs` + `capabilities.rs` + `models.rs` | Logical grouping, each < 300 LOC, keeps mod.rs lean | **Chosen** |
| `ping.rs` + `arp.rs` + `tcp_probe.rs` + `orchestrator.rs` + … | Over-granular for ~800 total LOC, navigability cost | Rejected |
| Single `discovery.rs` | Too large, mixes concerns | Rejected |

**Rationale**: `models.rs` is pure data (testable in isolation). `capabilities.rs` is pure platform detection (testable with mocks). `discovery.rs` holds all probe logic + orchestrator. Splitting probes into separate files would scatter ~50-line functions across files, hurting readability.

## Data Flow

```
CLI (scan subcommand)
        │
        ▼
  Scanner::new(config)
        │
        ├── capabilities.rs ── detect_permissions() → Capabilities
        │                         resolve_network("auto" | CIDR) → IpNetwork
        │
        ▼
  discover_network(IpNetwork, Capabilities)
        │
        ├─ tokio::spawn ── icmp_sweep(ips, semaphore) ──→ Vec<PingResult>
        │                    (skip if !Capabilities::can_icmp)
        │
        ├─ tokio::spawn ── tcp_sweep(ips, ports, semaphore) ──→ Vec<PingResult>
        │
        ├─ tokio::spawn ── arp_parse() ──→ Vec<ArpEntry>
        │
        ▼
  orchestrator::merge(ping_results, arp_entries) → Vec<DiscoveredHost>
        │
        ▼
  fmt::format_hosts_table(hosts) → stdout
```

## File Changes

| File | Action | Description |
|------|--------|-------------|
| `src/scanner/mod.rs` | Modify | Re-export `Scanner`, `DiscoveredHost`, `DiscoveryMethod`, `Capabilities` |
| `src/scanner/models.rs` | Create | `DiscoveredHost`, `DiscoveryMethod`, `Capabilities`, `ArpEntry`, `PingResult` |
| `src/scanner/capabilities.rs` | Create | `detect_permissions()`, `resolve_network()`, CIDR expansion |
| `src/scanner/discovery.rs` | Create | `Scanner` struct, `discover()`, `discover_network()`, ICMP/TCP/ARP probes, merge logic |
| `src/cli/scan.rs` | Modify | Replace stub with `Scanner` invocation and table output |
| `src/cli/mod.rs` | Modify | Import config, pass `ScanArgs` fields into `Scanner` |
| `src/error.rs` | Modify | Add `Permission`, `InterfaceNotFound`, `Discovery` variants |
| `Cargo.toml` | Modify | Add `libc` dependency |

## Interfaces / Contracts

```rust
// src/scanner/models.rs
#[derive(Debug, Clone, Serialize)]
pub struct DiscoveredHost {
    pub ip: IpAddr,
    pub mac: Option<MacAddress>,
    pub hostname: Option<String>,
    pub method: DiscoveryMethod,
}

#[derive(Debug, Clone, Serialize)]
pub enum DiscoveryMethod { Icmp, Tcp, Arp }

#[derive(Debug, Clone)]
pub struct Capabilities {
    pub can_icmp: bool,     // root or CAP_NET_RAW
    pub can_arp: bool,       // /proc/net/arp readable
}

#[derive(Debug)]
pub struct ArpEntry {
    pub ip: IpAddr,
    pub mac: MacAddress,
    pub device: String,
}

#[derive(Debug)]
pub struct PingResult {
    pub ip: IpAddr,
    pub method: DiscoveryMethod,
    pub latency: Option<Duration>,
}

// src/scanner/capabilities.rs
pub fn detect_permissions() -> Capabilities;
pub fn resolve_network(input: &str) -> Result<IpNetwork, Error>;
pub fn expand_cidr(network: &IpNetwork) -> Vec<IpAddr>;

// src/scanner/discovery.rs
pub struct Scanner {
    config: ScanConfig,
}

impl Scanner {
    pub fn new(config: ScanConfig) -> Self;
    pub async fn discover(&self, network_input: &str) -> Result<Vec<DiscoveredHost>, Error>;
    pub async fn discover_network(&self, network: &IpNetwork, caps: &Capabilities)
        -> Result<Vec<DiscoveredHost>, Error>;
}

// src/error.rs — new variants added
pub enum Error {
    // ...existing...
    #[error("Permission denied: {0}")]
    Permission(String),
    #[error("No suitable network interface found")]
    InterfaceNotFound,
    #[error("Discovery error: {0}")]
    Discovery(String),
}

// src/cli/scan.rs — updated handler
pub struct ScanArgs { /* existing fields unchanged */ }

fn format_hosts_table(hosts: &[DiscoveredHost]) -> String;
```

## Testing Strategy

| Layer | What | Approach |
|-------|------|----------|
| Unit | `expand_cidr("/24")` produces correct IP list | `#[cfg(test)]` in `capabilities.rs` |
| Unit | `expand_cidr("/16")` warns on large ranges | `#[cfg(test)]` — check stderr output |
| Unit | `parse_arp_line()` on sample `/proc/net/arp` content | `#[cfg(test)]` in `discovery.rs` with `#[cfg(target_os = "linux")]` |
| Unit | `merge()` deduplicates by IP, prefers ICMP over TCP | `#[cfg(test)]` in `discovery.rs` |
| Unit | `DiscoveredHost` serialization roundtrip | `#[cfg(test)]` in `models.rs` |
| Unit | `resolve_network("192.168.1.0/24")` parses correctly | `#[cfg(test)]` in `capabilities.rs` |
| Integration | `Scanner::discover("auto")` on loopback (root) | `tests/scanner_tests.rs` — `#[ignore]` (needs root) |
| Integration | `Scanner::discover("auto")` degrades gracefully (non-root) | `tests/scanner_tests.rs` |
| Integration | CLI `netascan scan --network 127.0.0.1/32` exits 0 | `tests/cli_tests.rs` with `assert_cmd` |

## Migration / Rollout

No migration required. All changes are additive — the scan handler was a stub (`println!("scan subcommand (stub)")`), replaced with real logic. `cargo build` + `cargo test` must pass before merge.

## Open Questions

- [ ] Should `libc::geteuid()` be gated behind `#[cfg(unix)]` with a fallback stub for CI on other platforms? Leaning yes — test on Linux, compile-check on others.
- [ ] ICMP ping implementation: `pnet::datalink` raw socket requires `libpcap-dev` at build time. Verify CI has this dependency or add a build-lndicate in `Cargo.toml`.