# Design: device-enrichment

## Module Structure

```
src/enrichment/
├── mod.rs          — public API: enrich_devices(hosts, config) → Vec<DiscoveredHost>
├── snmp.rs         — SNMP probe logic
├── mdns.rs         — mDNS passive + active query logic
└── mac_vendor.rs   — MacVendors API client with rate limiter
```

## Public API

```rust
// src/enrichment/mod.rs
pub async fn enrich_devices(
    hosts: Vec<DiscoveredHost>,
    config: &EnrichmentConfig,
) -> Vec<DiscoveredHost>
```

Single entry point. Returns enriched hosts (same order). Never returns an error — all failures are absorbed internally.

## EnrichmentConfig

```rust
pub struct EnrichmentConfig {
    pub snmp_enabled: bool,          // always true unless disabled by test
    pub mdns_enabled: bool,          // always true unless disabled by test
    pub mac_api_enabled: bool,       // --mac-api flag
    pub snmp_timeout_ms: u64,        // default 1000
    pub mdns_timeout_ms: u64,        // default 2000
    pub snmp_community: String,      // default "public"
}

impl Default for EnrichmentConfig { ... }
```

Built in `src/cli/mod.rs` from `clap` args.

## Concurrency Model

```
enrich_devices(hosts, config)
  └─ for each host → JoinSet::spawn(enrich_one(host, config))
       └─ enrich_one:
            ├─ tokio::spawn snmp_probe(host.ip, config)   [1s timeout via tokio::time::timeout]
            ├─ tokio::spawn mdns_query(host.ip, config)   [2s timeout via tokio::time::timeout]
            └─ join both, merge results into host
  └─ JoinSet::join_all → collect results

  if mac_api_enabled:
    for host in results (sequential):
      if host.vendor.is_none():
        mac_vendor::lookup(host.mac).await
        sleep(1s)
```

MacVendors is intentionally sequential after the concurrent enrichment to respect rate limits.

## Field Population Priority

| Field | Priority Order |
|-------|---------------|
| `hostname` | 1. mDNS PTR/A, 2. SNMP sysName, 3. existing value (keep) |
| `os_hint` | 1. SNMP sysDescr, 2. existing fingerprint value (keep) |
| `device_model` | 1. mDNS TXT `model=`, 2. None |
| `vendor` | 1. existing OUI value, 2. MacVendors API (if --mac-api and OUI empty) |

"Keep" means: only overwrite if the target field is currently `None` or empty string.

## Error Handling

All enrichment errors follow this contract:
```rust
match result {
    Ok(value) => { /* apply to host */ }
    Err(e) => { tracing::debug!("enrichment failed for {ip}: {e}"); }
}
```

No `?` propagation out of enrichment functions. Every public function returns `Option<T>` or a pre-absorbed result.

## Protocol::Udp

```rust
// src/scanner/models.rs
pub enum Protocol {
    Tcp,
    Udp,   // ← new variant
}
```

Used in SNMP port representation. `Display` impl updated (`"udp"`). Serde representation: `"udp"`.

## Pipeline Integration (src/cli/mod.rs)

```
[1/5] Discovering hosts ...
[2/5] Fingerprinting services ...
[3/5] Enriching device info ...   ← new step
[4/5] Checking CVEs ...
[5/5] Generating report ...
```

`EnrichmentConfig` built from `clap` args, passed to `enrich_devices`.

## Cargo.toml Additions

```toml
mdns-sd = "0.11"
async-snmp = "0.3"
```

## Docker Warning

At enrichment startup, if `/proc/net/if_inet6` contains only Docker bridge prefixes (172.17.x.x), emit:
```
tracing::warn!("mDNS multicast may not work in Docker bridge networks. Use --network host for accurate results.");
```
