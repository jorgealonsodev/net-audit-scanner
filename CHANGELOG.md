# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

---

## [0.2.0] — 2026-05-14

### Added
- **Device enrichment pipeline** — SNMP, mDNS, and MacVendors run concurrently per discovered host.
- **Raw UDP SNMP v2c client** — manual BER encoding/decoding; reads `sysDescr` and `sysName` with no external SNMP crate.
- **mDNS resolution** via `mdns-sd` crate — resolves hostnames and device models; fails silently on Docker bridge networks with a user warning.
- **MacVendors API fallback** — opt-in via `--mac-api` flag; rate-limited to 1 req/s to respect free tier.
- `Protocol::Udp` variant in scanner models.
- `device_model` field on `DiscoveredHost`.
- `EnrichmentConfig` with sane defaults (SNMP/mDNS on, MacVendors off, 1s/2s timeouts).
- `mac_vendors_api_key` field in `EnrichmentConfig` (saved to `~/.netascan/config.toml`).
- **First-run API key prompt** — on first `netascan scan`, missing `NVD_API_KEY` and `MAC_VENDORS_API_KEY` are requested interactively (TTY-only, non-blocking, each key skippable with Enter). Keys are persisted to `~/.netascan/config.toml`.
- `.env.example` with all supported environment variables and documentation URLs.

### Changed
- Progress messages now use `[1/5]…[5/5]` markers via `eprintln!`; tracing is silent by default (`RUST_LOG` opt-in).

---

## [0.1.0] — 2026-05-13

### Added
- **Network discovery** — ARP, ICMP sweep, and TCP SYN/connect probing via `pnet`.
- **Port scanning** — configurable port range (`top-1000` default, `--full` for all 65535, `--port-range` for custom).
- **Banner grabbing** — connects to open TCP ports and captures service banners.
- **OUI vendor lookup** — embedded Wireshark OUI database, updated via `netascan update`.
- **OS fingerprinting** — TTL-based OS hint (`Linux`, `Windows`, `iOS/macOS`, `Network device`); Linux-only ICMP TTL extraction.
- **CVE enrichment** — NVD REST API v2 client with SQLite cache (24 h TTL); `NVD_API_KEY` env var raises rate limit from 5 to 50 req/30 s.
- **Banner parser + CPE builder** — extracts service versions from banners and maps them to CPE 2.3 strings for CVE lookup.
- **Default credential checks** — tests HTTP Basic/Digest, FTP, and Telnet against a built-in list of common credentials.
- **HTML report generation** — Tera template with scan summary, host cards, open ports, CVE severity badges, and credential findings.
- **JSON output** — `--json` flag outputs structured scan results to stdout.
- **Scan persistence** — results saved to `~/.netascan/scans/` as JSON; `--last` flag loads the most recent scan.
- **Web dashboard** — `netascan serve` starts a local Axum server with the HTML report at `http://localhost:3000`.
- **`netascan update`** — downloads a fresh OUI database from a configurable URL.
- **GitHub Actions CI** — Ubuntu + macOS matrix with `libpcap` dependency; all tests required to pass.
- **Release workflow** — builds `x86_64-linux` tarball, `aarch64-apple-darwin` tarball, and `.deb` package on tag push; uploads to GitHub Releases.
- **GitHub Pages docs** — Jekyll site with `just-the-docs` theme at `https://jorgealonsodev.github.io/net-audit-scanner`.
- **CVE cache path fix under sudo** — resolves path via `SUDO_USER` to avoid writing to `/root/.cache`.

[Unreleased]: https://github.com/jorgealonsodev/net-audit-scanner/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/jorgealonsodev/net-audit-scanner/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/jorgealonsodev/net-audit-scanner/releases/tag/v0.1.0
