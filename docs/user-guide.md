---
layout: default
title: User Guide
nav_order: 2
---

# netascan User Guide

## Overview
`netascan` is a fast, specialized network security auditing tool that discovers devices, fingerprints services, checks for CVE vulnerabilities, and tests for default credentials. Designed for system administrators and security engineers, it outputs actionable insights as aligned terminal tables, machine-readable JSON, or rich HTML reports.

## Installation
Build `netascan` from source using `cargo`. The tool uses ICMP probes for the fastest and most accurate host discovery, which requires elevated privileges.

```bash
cargo build --release
sudo ./target/release/netascan scan
```

If run without `root` or `CAP_NET_RAW` capabilities, `netascan` gracefully falls back to slower TCP-based and ARP-based discovery methods.

## Quick Reference
| Command | Description |
|---------|-------------|
| `scan` | Run a network sweep, port scan, vulnerability check, and output the results. |
| `report` | Generate or view a formatted report from a previously saved scan. |
| `serve` | Start a local web dashboard to upload and analyze scan reports in your browser. |
| `update` | Refresh the local MAC OUI (vendor) database used for hardware fingerprinting. |

## Commands

### scan
The `scan` command is the core engine of `netascan`. It follows a strict pipeline: ICMP/TCP host discovery → port scanning → OS and service fingerprinting → vendor OUI lookup → CVE vulnerability enrichment → default credential testing → report output.

#### Examples

**Auto-scan your current network with an HTML report (Happy path):**
```bash
sudo netascan scan
```

**Scan a specific subnet and output to JSON:**
```bash
sudo netascan scan --network 192.168.1.0/24 --json
```

**Perform a fast, deep scan of a single host without CVE lookups:**
```bash
sudo netascan scan --target 10.0.0.5 --full --no-cve
```

#### Flags

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--network`, `-n` | String | `auto` | Network range in CIDR notation (e.g., `10.0.0.0/24`). `auto` detects the active interface. |
| `--target` | String | None | Specific target IP to scan in depth, bypassing network sweeps. |
| `--concurrency` | Integer | `512` | Maximum number of concurrent network probes. |
| `--timeout-ms` | Integer | `1500` | TCP connection timeout per probe in milliseconds. |
| `--banner-timeout-ms` | Integer | `500` | Service banner grab timeout in milliseconds. |
| `--json` | Boolean | `false` | Output the results to `stdout` as JSON instead of an aligned table. |
| `--no-cve` | Boolean | `false` | Skip the NVD CVE vulnerability lookup for faster results. |
| `--full` | Boolean | `false` | Scan all 65,535 ports instead of the default top-1000. |
| `--port-range` | String | `top-1000` | Which ports to scan: `top-100`, `top-1000`, `full`, or custom (e.g., `80-443`). |
| `--report`, `-r` | String | `html` | The report format to generate (`html` or `json`). |
| `--no-update` | Boolean | `false` | Force `netascan` to skip the cache and use the embedded OUI database. |

### report
The `report` command allows you to view historical scans without actively pinging the network again.

#### Examples

**Open the last successful scan report:**
```bash
netascan report --last
```

**Convert an existing JSON scan file into an HTML report:**
```bash
netascan report --input my-scan.json --format html
```

#### Flags

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--format`, `-f` | String | `html` | The output format to generate (`html` or `json`). |
| `--output`, `-o` | String | None | Output file path. Defaults to `stdout` if omitted. |
| `--last` | Boolean | `false` | Automatically load the most recently saved scan from `~/.cache/netascan/scans/`. |
| `--input`, `-i` | String | None | Input file path (JSON scan result), or `-` to read from `stdin`. |

### serve
Starts a local web dashboard allowing you to upload `.json` scan results and browse them interactively. 

#### Examples

**Start the dashboard on the default port:**
```bash
netascan serve
```

**Start the dashboard on a custom port and interface:**
```bash
netascan serve --bind 0.0.0.0 --port 8080
```

#### Flags

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--port`, `-p` | Integer | `7070` | The port to bind the web server to. |
| `--bind` | String | `127.0.0.1`| The IP address to bind the web server to. |

### update
Updates the local OUI (Organizationally Unique Identifier) database used for mapping MAC addresses to vendor names. Run this occasionally to ensure new hardware is correctly identified.

#### Examples

**Update the vendor database from the default Wireshark repository:**
```bash
netascan update
```

#### Flags

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--source` | String | Wireshark Manuf | Custom URL source to download the `manuf` database from. |

## Configuration File
Configuration defaults are stored in `~/.config/netascan/config.toml`. The file is created automatically on the first run. 

To increase your CVE lookup rate limits, get a free API key from the [NVD Developer Portal](https://nvd.nist.gov/developers/request-an-api-key) and add it to `nvd_api_key`.

```toml
[scan]
# Network range to target if no arguments are provided.
default_network = "auto"
# Default port range rule.
port_range = "top-1000"
# Global probe timeout in milliseconds.
timeout_ms = 1500
# Timeout specific to grabbing service banners in milliseconds.
banner_timeout_ms = 500
# Max in-flight connections.
concurrency = 512

[cve]
# Your NVD API key to bypass strict rate limits.
nvd_api_key = "your-api-key-here"
# Upstream CVE source providers.
sources = ["nvd", "circl"]
# How long to keep CVE checks cached locally.
cache_ttl_hours = 24

[report]
# Default file format when none is provided via CLI.
default_format = "html"
# Automatically open HTML reports in your system browser.
open_browser = true

[credentials_check]
# Attempt default credentials against discovered services.
enabled = true
# Optional custom password list path to use instead of the embedded defaults.
custom_list = ""
```

## Output Formats
`netascan` provides three main ways to view results:
1. **Table (Stdout):** An aligned, human-readable terminal table showing IPs, MACs, vendors, hostnames, and CVE counts.
2. **HTML Report:** A rich, interactive, standalone HTML file written to your filesystem.
3. **JSON:** Machine-readable data containing the complete network topology, open ports, and vulnerabilities.

**Example JSON snippet of a DiscoveredHost:**
```json
{
  "ip": "192.168.1.10",
  "mac": "AA:BB:CC:DD:EE:FF",
  "hostname": "fileserver.local",
  "method": "icmp",
  "open_ports": [
    {
      "port": 22,
      "service": "ssh",
      "banner": "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1"
    }
  ],
  "vendor": "Cisco Systems",
  "os_hint": "Ubuntu Linux",
  "security_findings": []
}
```

## Security Checks
During port scanning, `netascan` actively tests known services for common security misconfigurations. 

- **HTTP Basic Auth:** Tests typical `admin/admin` combinations over standard HTTP paths.
- **FTP:** Checks for anonymous login and default credentials.
- **Telnet:** Checks for default factory logins.

If a credential check succeeds, it attaches a `SecurityFinding` to the host in the final output.

**Disable credential checking:** 
If you want a purely passive scan, you can disable this behavior by setting `enabled = false` under the `[credentials_check]` section in your `config.toml`.

## OS Fingerprinting
`netascan` uses a dual-approach to lightweight OS fingerprinting. Results populate the `os_hint` field in the report.

1. **TTL (Time To Live):** By evaluating the initial TTL in ICMP echo replies, `netascan` categorizes hosts into broad families (e.g., Linux/macOS for TTL 64, Windows for TTL 128, FreeBSD for TTL 255).
2. **Service Banners:** `netascan` reads the textual banners exposed by SSH, HTTP, and FTP services to refine the operating system (e.g., finding "Ubuntu" inside an SSH banner string).

## Scan Persistence
All completed scans are automatically persisted locally. 
- **Location:** `~/.cache/netascan/scans/`
- **Retention:** `netascan` keeps up to 10 timestamped scan files. Older files are pruned automatically.
- **Usage:** You can revisit the latest scan at any time without re-running the network sweep using the `netascan report --last` command.

## Troubleshooting

| Problem | Likely Cause | Solution |
|---------|-------------|----------|
| **No hosts found** | Missing privileges or wrong CIDR. | Run with `sudo`. Verify `--network` matches your actual subnet. |
| **CVE enrichment is slow** | Hitting NVD API rate limits. | Request an NVD API key and set it in `config.toml`. |
| **Permission denied (ICMP)**| Missing `CAP_NET_RAW` cap. | Run as root or rely on the slower TCP/ARP fallback. |
| **Credential checks timing out**| High network latency. | Increase `timeout_ms` in configuration. |

## Environment Variables

| Variable | Description |
|----------|-------------|
| `NVD_API_KEY` | Overrides the NVD API key set in `config.toml` for CVE enrichment. |
| `RUST_LOG` | Controls internal log verbosity (e.g., `export RUST_LOG=debug` or `info`). |

## Appendix: JSON Schema
Below is an annotated example of a complete `DiscoveredHost` JSON object.

```json
{
  "ip": "192.168.1.10",              // Parsed IPv4 or IPv6 address
  "mac": "AA:BB:CC:DD:EE:FF",        // Hardware address from ARP (optional)
  "hostname": "router.local",        // Resolved via reverse DNS (optional)
  "method": "icmp",                  // Discovery type (icmp, tcp, arp)
  "rtt_ms": 12,                      // Network latency in milliseconds
  "vendor": "Ubiquiti Networks Inc", // OUI database match for the MAC address
  "os_hint": "Linux/macOS",          // Inferred OS based on TTL and banners
  "open_ports": [
    {
      "port": 80,                    // Port number (1-65535)
      "service": "http",             // Mapped ServiceType (http, https, ssh, etc.)
      "banner": "Server: nginx/1.18" // Captured network text response (optional)
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
  ],
  "cve_matches": [
    {
      "cve_id": "CVE-2021-12345",
      "severity": "high",
      "description": "Vulnerability in nginx 1.18 allowing bypass...",
      "cvss_score": 7.5
    }
  ]
}
```
