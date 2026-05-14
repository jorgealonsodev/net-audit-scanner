---
layout: default
title: User Guide
nav_order: 2
---

# netascan User Guide

## Overview

`netascan` is a fast network security auditing CLI that discovers devices on your LAN, fingerprints services, enriches results with SNMP/mDNS/vendor data, checks for known CVEs, tests for default credentials, and generates actionable reports — all from a single command.

Designed for system administrators and security engineers, it outputs results as an aligned terminal table, machine-readable JSON, or a rich standalone HTML report.

---

## Installation

### Pre-built binaries (recommended)

Download from the [Releases page](https://github.com/jorgealonsodev/net-audit-scanner/releases).

**Linux:**
```bash
tar -xzf netascan-v0.2.0-x86_64-unknown-linux-gnu.tar.gz
sudo mv netascan /usr/local/bin/
```

**macOS:**
```bash
tar -xzf netascan-v0.2.0-aarch64-apple-darwin.tar.gz
sudo mv netascan /usr/local/bin/
```

**Debian / Ubuntu (.deb):**
```bash
sudo dpkg -i netascan-v0.2.0-amd64.deb
```

### Build from source

Requires Rust stable and `libpcap-dev` on Linux.

```bash
sudo apt-get install -y libpcap-dev   # Linux only
cargo build --release
sudo mv target/release/netascan /usr/local/bin/
```

---

## Quick Reference

| Command | Description |
|---------|-------------|
| `scan`  | Discover hosts, enrich device info, check CVEs, test credentials, output results. |
| `report` | Generate or view a report from a previously saved scan. |
| `serve` | Start a local web dashboard to browse scan reports in your browser. |
| `update` | Refresh the local MAC OUI (vendor) database. |

---

## Commands

### scan

The core pipeline of `netascan`. Runs in five labeled stages:

```
[1/5] Host discovery   — ICMP sweep + ARP + TCP connect
[2/5] Port scanning    — configurable range, banner grabbing, OS hint
[3/5] Device enrichment — OUI + SNMP + mDNS + MacVendors API
[4/5] CVE enrichment   — NVD REST API v2, SQLite cache (24h TTL)
[5/5] Credential checks — HTTP Basic, FTP, Telnet default creds
```

#### Examples

```bash
# Auto-scan your network (requires root for ICMP)
sudo netascan scan

# Scan a specific subnet, output JSON to stdout
sudo netascan scan --network 192.168.1.0/24 --json

# Fast scan: top-100 ports, skip CVEs, disable MacVendors API
sudo netascan scan --port-range top-100 --no-cve --no-mac-api

# Full port scan on a single host
sudo netascan scan --target 10.0.0.5 --full

# Preserve NVD_API_KEY env var under sudo
sudo -E netascan scan
```

#### Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--network`, `-n` | `auto` | CIDR range or `auto` to detect from the active interface. |
| `--target` | — | Single IP for in-depth scan. |
| `--concurrency` | `512` | Max parallel network probes. |
| `--timeout-ms` | `1500` | TCP connection timeout (ms). |
| `--banner-timeout-ms` | `500` | Banner grab timeout (ms). |
| `--port-range` | `top-1000` | Port set: `top-100`, `top-1000`, `full` (1–65535), or custom (e.g. `80-443`). |
| `--full` | off | Shorthand for `--port-range full`. |
| `--report`, `-r` | `html` | Report format written to file: `html` or `json`. |
| `--json` | off | Print results to stdout as JSON instead of a table. |
| `--no-cve` | off | Skip CVE enrichment (faster). |
| `--no-update` | off | Use the embedded OUI database instead of the cached one. |
| `--no-mac-api` | off | Disable MacVendors API lookup. Enabled by default — no key or registration needed for ≤ 1000 req/day. |

---

### report

View or convert historical scan results without re-scanning.

#### Examples

```bash
netascan report --last                          # view most recent scan
netascan report --input my-scan.json --format html
```

#### Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--last` | off | Load the most recently saved scan from `~/.cache/netascan/scans/`. |
| `--input`, `-i` | — | Path to a JSON scan file, or `-` to read from stdin. |
| `--format`, `-f` | `html` | Output format: `html` or `json`. |
| `--output`, `-o` | stdout | Output file path. |

---

### serve

Starts a local web dashboard. Upload `.json` scan files and browse them as interactive HTML reports.

#### Examples

```bash
netascan serve                    # http://127.0.0.1:7070
netascan serve --port 8080 --bind 0.0.0.0
```

#### Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--port`, `-p` | `7070` | Port to bind to. |
| `--bind` | `127.0.0.1` | IP address to bind to. |

---

### update

Refreshes the OUI database used to map MAC addresses to vendor names.

```bash
netascan update
netascan update --source https://your-mirror.example.com/manuf
```

| Flag | Default | Description |
|------|---------|-------------|
| `--source` | Wireshark Manuf URL | Custom URL for the `manuf` database. |

---

## Device Enrichment

Starting in v0.2.0, `netascan` runs three enrichment sources concurrently after OUI lookup:

### SNMP (v2c, raw UDP)
Probes UDP port 161 with community string `public`. Reads `sysDescr` (device description) and `sysName` (hostname). Implemented with manual BER encoding — no external SNMP crate required.

### mDNS
Uses `mdns-sd` to resolve `.local` hostnames and device model strings. Runs for up to 2 seconds per scan. Fails silently on Docker bridge networks with a user warning.

### MacVendors API
Calls `https://api.macvendors.com/{mac}` as a fallback when OUI lookup returns no result. **No API key or registration required** for up to 1,000 requests/day at 1 req/s. Rate limiting is enforced automatically.

To disable: `--no-mac-api`  
For higher limits (paid plan): set `MAC_VENDORS_API_KEY` in your config or environment.

---

## Configuration File

`~/.netascan/config.toml` is created automatically on first run. On the first `netascan scan`, any missing optional API keys are prompted interactively — press Enter to skip.

```toml
[scan]
default_network   = "auto"
port_range        = "top-1000"
timeout_ms        = 1500
banner_timeout_ms = 500
concurrency       = 512

[cve]
# Free key at https://nvd.nist.gov/developers/request-an-api-key
# Without it: 5 req/30s. With it: 50 req/30s.
nvd_api_key       = ""
sources           = ["nvd", "circl"]
cache_ttl_hours   = 24

[report]
default_format    = "html"
open_browser      = true

[credentials_check]
enabled           = true
custom_list       = ""    # path to a custom credentials file

[enrichment]
snmp_enabled      = true
mdns_enabled      = true
# MacVendors API: enabled by default, no key needed up to 1000 req/day.
# Paid plan key: https://macvendors.com/api
mac_api_enabled   = true
mac_vendors_api_key = ""
snmp_community    = "public"
snmp_timeout_ms   = 1000
mdns_timeout_ms   = 2000
```

---

## Environment Variables

| Variable | Description |
|----------|-------------|
| `NVD_API_KEY` | NVD API key. Use `sudo -E` to preserve under sudo. |
| `MAC_VENDORS_API_KEY` | MacVendors paid plan key (optional). |
| `RUST_LOG` | Log verbosity (e.g. `RUST_LOG=debug`). Silent by default. |

---

## Output Formats

1. **Table (stdout):** Aligned columns — IP, MAC, Vendor, Hostname, Method, RTT, CVEs.
2. **HTML report:** Standalone file with summary, host cards, port details, CVE badges, and credential findings.
3. **JSON:** Full structured output with all fields. Suitable for piping into other tools.

**Example host JSON:**
```json
{
  "ip": "192.168.1.10",
  "mac": "AA:BB:CC:DD:EE:FF",
  "hostname": "printer.local",
  "device_model": "HP LaserJet Pro",
  "vendor": "HP Inc.",
  "os_hint": "Linux/macOS",
  "method": "icmp",
  "rtt_ms": 4,
  "open_ports": [
    {
      "port": 9100,
      "service": "unknown",
      "protocol": "tcp",
      "banner": "PJL ready",
      "is_insecure": false,
      "cves": []
    }
  ],
  "security_findings": []
}
```

---

## Security Checks

`netascan` tests discovered services against a built-in list of default credentials:

- **HTTP Basic Auth** — common `admin:admin`, `admin:password` combinations
- **FTP** — anonymous login + default credentials
- **Telnet** — default factory logins

Findings are attached to the host as `SecurityFinding` objects and surfaced in both the table and HTML report with a `CRITICAL` label.

To disable: set `enabled = false` in `[credentials_check]` config.

---

## OS Fingerprinting

`os_hint` is populated using two signals:

1. **TTL analysis** — ICMP echo reply TTL maps to OS families: 64 → Linux/macOS, 128 → Windows, 255 → Network device. (Linux-only; skipped on macOS.)
2. **Banner strings** — SSH, HTTP, and FTP banners are scanned for OS keywords (e.g. `Ubuntu`, `Windows`, `RouterOS`).

---

## Scan Persistence

- **Location:** `~/.cache/netascan/scans/`
- **Format:** timestamped `.json` files + `last.json` symlink
- **Retention:** up to 10 files; oldest are pruned automatically
- **Usage:** `netascan report --last` loads the most recent scan without re-scanning

---

## Troubleshooting

| Problem | Likely cause | Solution |
|---------|-------------|----------|
| No hosts found | Wrong CIDR or missing privileges | Run with `sudo`. Verify `--network` matches your subnet. |
| CVE enrichment slow | NVD rate limiting (no API key) | Get a free key at nvd.nist.gov and add it to config. |
| NVD_API_KEY not picked up under sudo | sudo strips env vars | Use `sudo -E netascan scan`. |
| mDNS returns no results | Docker bridge network | Expected. mDNS multicast doesn't cross bridge interfaces. |
| Permission denied (ICMP) | Missing `CAP_NET_RAW` | Run as root, or rely on TCP/ARP fallback. |
| Credential checks timing out | High latency | Increase `timeout_ms` in config. |

---

## Appendix: Full DiscoveredHost JSON Schema

```json
{
  "ip": "192.168.1.10",
  "mac": "AA:BB:CC:DD:EE:FF",
  "hostname": "router.local",
  "device_model": "UniFi Dream Machine",
  "method": "icmp",
  "rtt_ms": 12,
  "vendor": "Ubiquiti Networks Inc.",
  "os_hint": "Linux/macOS",
  "open_ports": [
    {
      "port": 80,
      "service": "http",
      "protocol": "tcp",
      "banner": "Server: nginx/1.18.0",
      "is_insecure": true,
      "cves": [
        {
          "cve_id": "CVE-2021-23017",
          "description": "nginx resolver vulnerability",
          "severity": "high",
          "score": 7.7,
          "published": "2021-06-01"
        }
      ]
    }
  ],
  "security_findings": [
    {
      "check_type": "default_credential",
      "severity": "critical",
      "port": 80,
      "service": "http",
      "description": "Found default credentials: admin:admin",
      "target_ip": "192.168.1.10"
    }
  ]
}
```
