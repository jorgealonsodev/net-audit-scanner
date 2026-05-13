# Design: MAC OUI Fingerprinting

## Technical Approach

Compile-time embed the Wireshark `manuf` database via `include_dir!` (already a dependency). Parse into an `OuiDb` struct with three `HashMap`s keyed by fixed byte-array prefixes (3/4/5 bytes). Lookup uses longest-prefix-match: try 5-byte → 4-byte → 3-byte, return first hit. Enrichment is a pure function called once in the CLI pipeline after `scan_ports()`. Pattern follows `services.rs` — pure functions, no state mutation on `OuiDb`.

## Architecture Decisions

### Decision: Three HashMaps with byte-array keys vs single HashMap with Vec<u8>

| Option | Tradeoff | Decision |
|--------|----------|----------|
| Three HashMaps (`[u8;3]`, `[u8;4]`, `[u8;5]`) | Fixed-size keys, O(1) each, simple code | **Chosen** |
| Single `HashMap<Vec<u8>, String>` | Handles arbitrary prefix lengths but slower hashing, no compile-time size | Rejected |
| Trie structure | Elegant longest-prefix-match, complex implementation | Overkill for ~30K entries |

**Rationale**: Fixed byte-array keys get compile-time size, trivial `Hash`/`Eq`, and zero allocations on lookup. The ordered 5→4→3 fallback is 3 HashMap lookups worst case — negligible for a CLI tool scanning dozens of hosts.

### Decision: Round prefix masks to byte boundaries

| Option | Tradeoff | Decision |
|--------|----------|----------|
| Round down to byte boundary (e.g. `/28` → 4-byte exact match) | Slightly more specific matching (better for device ID), trivial code | **Chosen** |
| Bit-level masking (e.g. mask 4th byte to top nibble for `/28`) | Exact IEEE spec compliance, complex masking logic | Rejected |

**Rationale**: Rounding to byte boundaries means `/28` entries match their full 4-byte prefix exactly. This is *more* specific, never less — always safe for device identification. The Wireshark manuf file's `/28` entries already have the canonical 4th byte, so we match that byte exactly. Same logic for `/36` → 5-byte exact match.

### Decision: OuiDb lives in `scanner/oui.rs`, not `fingerprint/mod.rs`

**Chosen**: `src/scanner/oui.rs`
**Rejected**: `src/fingerprint/mod.rs` (existing stub)

**Rationale**: The enrichment step is called in the scan pipeline alongside `scan_ports()` and `merge_results()`. The `fingerprint` module is a future home for broader fingerprinting (banner analysis, OS detection). OUI lookup belongs with the scanner pipeline it integrates into. The existing `fingerprint/mod.rs` stub stays as-is for future expansion.

### Decision: LazyLock for OuiDb initialization

| Option | Tradeoff | Decision |
|--------|----------|----------|
| `std::sync::LazyLock<OuiDb>` | Zero-cost init on first access, no runtime args needed | **Chosen** |
| `OnceCell` | Slightly more verbose, same behavior | Rejected |
| Init in `main()` | Pollutes main, couples scanner internals to CLI | Rejected |

**Rationale**: `LazyLock` is stable in Rust 2024 edition (which this project uses). The manuf data is embedded at compile time, so no runtime arguments are needed. First `OUI_DB` access triggers one-time parse.

### Decision: Missing/corrupt manuf data at build time

**Chosen**: Compile fails (hard error from `include_dir!`)
**Rejected**: Runtime fallback to empty database

**Rationale**: If `data/manuf` is absent, `include_dir!` fails at compile time — there's no silent degradation. A corrupt format (malformed lines) is handled gracefully: skip the line, continue parsing. This mirrors `parse_arp_content` which silently skips bad lines.

## Data Flow

```
┌─────────────┐
│ data/manuf  │ ← compile-time include_dir!()
│  (embedded) │
└──────┬──────┘
       │  LazyLock::new(OuiDb::from_embedded)
       ▼
┌─────────────┐
│   OuiDb     │ ← prefix3, prefix4, prefix5 HashMaps
└──────┬──────┘
       │
       │  OUI_DB.lookup(&mac) → Option<&str>
       ▼
┌──────────────────────────────────────────────┐
│  CLI Pipeline: discover → scan_ports → enrich │
│                                              │
│  enrich_oui(&OUI_DB, &mut [DiscoveredHost]) │
│       ↓ for each host with mac               │
│       host.vendor = oui_db.lookup(mac)       │
└──────────────────────────────────────────────┘
```

## File Changes

| File | Action | Description |
|------|--------|-------------|
| `src/scanner/oui.rs` | Create | `OuiDb` struct, `from_embedded()`, `parse_manuf()`, `lookup()`, `enrich_oui()`, `OUI_DB` static |
| `data/manuf` | Create | Wireshark manuf database (~200KB, ~30K entries) |
| `src/scanner/models.rs` | Modify | Add `vendor: Option<String>` field to `DiscoveredHost` |
| `src/scanner/discovery.rs` | Modify | Add `vendor: None` to `DiscoveredHost` construction in `merge_results` |
| `src/scanner/mod.rs` | Modify | Add `pub mod oui`, re-export `OuiDb`, `OUI_DB`, `enrich_oui` |
| `src/cli/mod.rs` | Modify | Call `enrich_oui(&OUI_DB, &mut hosts)` after `scan_ports()` |
| `src/cli/scan.rs` | Modify | Add Vendor column to `format_hosts_table()`, included automatically in JSON via serde |

## Interfaces / Contracts

```rust
// src/scanner/oui.rs

use std::sync::LazyLock;
use macaddr::MacAddr6;

/// Compile-time embedded Wireshark manuf directory.
static MANUF_DIR: include_dir::Dir<'_> = include_dir::include_dir!("$CARGO_MANIFEST_DIR/data");

/// OUI database parsed from the embedded Wireshark manuf file.
pub struct OuiDb {
    prefix3: HashMap<[u8; 3], String>,  // /24 OUI prefixes (~28K entries)
    prefix4: HashMap<[u8; 4], String>,  // /25-/32 MA-M prefixes
    prefix5: HashMap<[u8; 5], String>,  // /33-/48 MA-S prefixes
}

/// Global OuiDb instance, initialized on first access.
pub static OUI_DB: LazyLock<OuiDb> = LazyLock::new(OuiDb::from_embedded);

impl OuiDb {
    /// Parse the embedded manuf file into an OuiDb.
    /// Skips malformed lines gracefully.
    pub fn from_embedded() -> Self;

    /// Look up vendor for a MAC address.
    /// Tries longest prefix first: 5-byte → 4-byte → 3-byte.
    /// Returns None if no match (or MAC is None).
    pub fn lookup(&self, mac: &MacAddr6) -> Option<&str>;
}

/// Parse manuf-format content into an OuiDb.
/// Format: PREFIX\tSHORT_NAME\tFULL_NAME
/// Lines starting with '#' are comments; empty lines are skipped.
fn parse_manuf(content: &str) -> OuiDb;

/// Enrich a list of discovered hosts with vendor information.
/// Mutates `host.vendor` for hosts that have a MAC address.
pub fn enrich_oui(db: &OuiDb, hosts: &mut [DiscoveredHost]);
```

```rust
// src/scanner/models.rs — change to DiscoveredHost

pub struct DiscoveredHost {
    pub ip: IpAddr,
    pub mac: Option<macaddr::MacAddr6>,
    pub hostname: Option<String>,
    pub vendor: Option<String>,      // ← NEW
    pub method: DiscoveryMethod,
    pub open_ports: Vec<OpenPort>,
    pub rtt_ms: Option<u128>,
}
```

```rust
// src/cli/mod.rs — pipeline integration (in run())

let mut hosts = scanner.scan_ports(hosts).await;
crate::scanner::enrich_oui(&crate::scanner::OUI_DB, &mut hosts);
```

## Testing Strategy

| Layer | What to Test | Approach |
|-------|-------------|----------|
| Unit | `parse_manuf` handles 3/4/5-byte prefixes, comments, empty lines, malformed entries | Inline test manuf strings, assert correct HashMap population |
| Unit | `OuiDb::lookup` returns correct vendor for known MACs, None for unknown | Construct small `OuiDb` with known entries, verify 5→4→3 fallback |
| Unit | `enrich_oui` populates `vendor` on hosts with MACs, leaves `None` for hosts without | Build `Vec<DiscoveredHost>` with mixed MAC/no-MAC, verify enrichment |
| Unit | `OUI_DB` global can be initialized without panic | Smoke test in test binary |
| Integration | Full pipeline: discover → scan_ports → enrich_oui produces hosts with vendor field | Use fixture ARP data + mock scanner (if available) |

## Migration / Rollout

No migration required. `vendor: Option<String>` defaults to `None` for all existing code paths. `merge_results` initializes it to `None`. Backward-compatible with existing JSON consumers — new field is nullable.

## Open Questions

- [ ] Should `lookup` return the short name or full vendor name from manuf? (Recommendation: full name, as it's more useful for reports)