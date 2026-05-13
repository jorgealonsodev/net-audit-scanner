---
layout: home
title: Home
nav_order: 1
---

# netascan

![netascan](assets/net-audit-scan.png)

Network security audit CLI. Discovers devices on your LAN, fingerprints services, checks for known CVEs, tests default credentials, and generates HTML/JSON reports — all from a single command.

```bash
sudo netascan scan --network 192.168.1.0/24
```

## Installation

### Debian / Ubuntu (.deb)

```bash
wget https://github.com/jorgealonsodev/net-audit-scanner/releases/latest/download/netascan-v0.1.0-amd64.deb
sudo dpkg -i netascan-v0.1.0-amd64.deb
```

### Pre-built binary (Linux / macOS)

Download from the [Releases page](https://github.com/jorgealonsodev/net-audit-scanner/releases).

```bash
tar -xzf netascan-*.tar.gz
sudo mv netascan /usr/local/bin/
```

### Build from source

```bash
sudo apt-get install -y libpcap-dev   # Linux only
cargo build --release
sudo mv target/release/netascan /usr/local/bin/
```

## Quick start

```bash
# Auto-detect network and scan
sudo netascan scan

# Specific range, HTML report
sudo netascan scan --network 192.168.1.0/24 --report html

# View last scan
netascan report --last

# Web dashboard
netascan serve
```

> **Requires root / CAP_NET_RAW** for ICMP sweep. Without it, netascan falls back to TCP + ARP.

---

[Read the full User Guide](user-guide){: .btn .btn-primary }
