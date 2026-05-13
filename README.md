# netascan

Network security audit CLI. Discovers devices on your LAN, fingerprints services, checks for known CVEs, tests default credentials, and generates HTML/JSON reports — all from a single command.

```
netascan scan --network 192.168.1.0/24
```

---

## Quick start

```bash
# Build
cargo build --release

# Scan your local network (auto-detects interface)
./target/release/netascan scan

# Scan a specific range and open an HTML report
./target/release/netascan scan --network 192.168.1.0/24 --report html

# View the most recent scan as a report
./target/release/netascan report --last

# Start the web dashboard (upload + browse reports)
./target/release/netascan serve
```

> **Requires root / CAP_NET_RAW** for ICMP sweep. Without it, netascan falls back to TCP + ARP discovery.

---

## Commands

### `scan`

Discover hosts, scan ports, enrich with CVEs and vendor info, test default credentials, and output results.

| Flag | Default | Description |
|------|---------|-------------|
| `--network` / `-n` | `auto` | CIDR range or `auto` to detect from the active interface |
| `--target` | — | Single IP for in-depth scan |
| `--port-range` | `top-1000` | Port set: `top-1000`, `full` (1–65535), or a custom range |
| `--full` | off | Equivalent to `--port-range full` |
| `--concurrency` | 512 | Max parallel connections |
| `--timeout-ms` | 1500 | TCP connect timeout (ms) |
| `--banner-timeout-ms` | 500 | Banner grab timeout (ms) |
| `--report` / `-r` | `html` | Output format: `html` or `json` (file) plus table to stdout |
| `--json` | off | Print JSON to stdout instead of table |
| `--no-cve` | off | Skip CVE enrichment |
| `--no-update` | off | Use embedded OUI database instead of cached |

### `report`

Generate or view a report from a saved scan.

```bash
netascan report --last              # most recent scan
netascan report --format html       # html (default) or json
```

### `serve`

Local web dashboard on `http://localhost:3000`. Upload a scan JSON and browse the HTML report in-browser.

```bash
netascan serve
netascan serve --port 8080
```

### `update`

Refresh the OUI (vendor) database used for MAC fingerprinting.

```bash
netascan update
netascan update --source https://your-mirror.example.com/manuf
```

---

## What a scan does

```
discover hosts (ICMP + ARP + TCP)
    ↓
scan ports (top-1000 by default)
    ↓
grab banners → infer OS hint (TTL + banner)
    ↓
enrich with OUI vendor data
    ↓
enrich with CVE data (NVD API, cached in ~/.cache/netascan/cve.db)
    ↓
test default credentials (HTTP Basic, FTP, Telnet)
    ↓
persist to ~/.cache/netascan/scans/
    ↓
output (table / JSON / HTML report)
```

---

## Configuration

Config file: `~/.config/netascan/config.toml` (created with defaults on first run).

```toml
[scan]
default_network    = "auto"
port_range         = "top-1000"
timeout_ms         = 1500
banner_timeout_ms  = 500
concurrency        = 512

[cve]
nvd_api_key        = ""          # optional — raises NVD rate limit
cache_ttl_hours    = 24

[report]
default_format     = "html"
open_browser       = false

[credentials_check]
enabled            = true
custom_list        = ""          # path to a custom credentials file
```

**NVD API key** (optional but recommended): get one at <https://nvd.nist.gov/developers/request-an-api-key> and set it in the config or as `NVD_API_KEY` env var.

---

## Scan persistence

Every scan is saved as JSON under `~/.cache/netascan/scans/`. Use `report --last` to load the most recent one without re-scanning.

---

## Requirements

| Requirement | Notes |
|-------------|-------|
| Rust 2024 edition | `rustup update stable` |
| Root / CAP_NET_RAW | ICMP sweep only. TCP+ARP fallback works without. |
| Internet access | CVE enrichment via NVD API (optional, skippable with `--no-cve`) |

---

## Development

```bash
cargo test                  # run all tests
cargo clippy --all-targets  # lint
cargo bench                 # benchmarks (criterion)
```

Tests that require network access are marked `#[ignore]` and skipped by default.

---

## License

MIT
