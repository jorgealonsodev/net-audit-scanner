# OUI Fingerprint Specification

## Purpose

Vendor identification from MAC addresses via compile-time embedded Wireshark manuf database, enriching DiscoveredHost records for device classification.

## Requirements

### REQ-OUI-1: Embedded OUI Database

| Field | Value |
|-------|-------|
| Statement | The system MUST embed the Wireshark manuf database at compile time via `include_dir` and parse it into `OuiDb` at first access via `LazyLock`. |
| Priority | P1 |
| Depends on | None |

#### Scenario: Lazy initialization
- GIVEN manuf file in `data/` → WHEN binary starts → THEN `OuiDb` inits on first lookup

#### Scenario: Valid entries indexed
- GIVEN manuf with 3/4/5-byte entries → WHEN parsed → THEN all valid entries indexed

#### Scenario: Malformed lines skipped
- GIVEN invalid manuf lines → WHEN parsed → THEN warnings logged, valid lines indexed

#### Scenario: Empty manuf file
- GIVEN empty manuf → WHEN initialized → THEN zero entries, no panic

#### Scenario: Unicode preserved
- GIVEN Unicode vendor name → WHEN returned → THEN original chars preserved

---

### REQ-OUI-2: MAC Prefix Lookup

| Field | Value |
|-------|-------|
| Statement | MAC lookup MUST use ordered fallback: 5-byte (MA-S) → 4-byte (MA-M) → 3-byte (OUI). Each HashMap lookup MUST be O(1). |
| Priority | P1 |
| Depends on | REQ-OUI-1 |

#### Scenario: OUI-only match
- GIVEN MAC matching only 3-byte entry → THEN 3-byte vendor returned

#### Scenario: MA-S most specific
- GIVEN MAC matching 5-byte and 3-byte → THEN 5-byte vendor returned

#### Scenario: MA-M overrides OUI
- GIVEN MAC matching 4-byte and 3-byte → THEN 4-byte vendor returned

#### Scenario: No match
- GIVEN MAC with no matching prefix → THEN `None` returned

#### Scenario: No MAC address
- GIVEN `mac: None` → THEN `None` returned, no HashMap access

---

### REQ-OUI-3: Pipeline Enrichment

| Field | Value |
|-------|-------|
| Statement | `enrich_oui()` MUST run after `scan_ports()`, setting only the `vendor` field. Hosts without MAC receive `None`. |
| Priority | P1 |
| Depends on | REQ-OUI-2 |

#### Scenario: Matched MAC
- GIVEN MAC matching known prefix → THEN `vendor = Some("Name")`

#### Scenario: Unmatched MAC
- GIVEN MAC matching no prefix → THEN `vendor = None`

#### Scenario: No MAC
- GIVEN `mac: None` → THEN `vendor = None`, no lookup

#### Scenario: Mixed batch
- GIVEN 10 hosts (7 with MAC, 3 without) → THEN 7 lookups, all 10 have vendor set

#### Scenario: Empty list
- GIVEN empty vec → THEN empty vec returned, zero lookups

---

### REQ-OUI-4: DiscoveredHost Vendor Field

| Field | Value |
|-------|-------|
| Statement | `DiscoveredHost` MUST include `vendor: Option<String>`. Default `None`. Must deserialize backward-compatibly. |
| Priority | P1 |
| Depends on | None |

#### Scenario: Vendor serialized
- GIVEN `vendor: Some("Cisco")` → THEN JSON has `"vendor": "Cisco"`

#### Scenario: Null vendor serialized
- GIVEN `vendor: None` → THEN JSON has `"vendor": null`

#### Scenario: Backward deserialization
- GIVEN JSON without `"vendor"` key → THEN `vendor` defaults to `None`

---

### REQ-OUI-5: CLI and Report Integration

| Field | Value |
|-------|-------|
| Statement | CLI table MUST show Vendor column. JSON MUST include `vendor`. HTML report MUST render `host.vendor`. |
| Priority | P1 |
| Depends on | REQ-OUI-4 |

#### Scenario: Vendor in table
- GIVEN `vendor: Some("Dahua")` → THEN "Dahua" in Vendor column

#### Scenario: Missing vendor in table
- GIVEN `vendor: None` → THEN "-" in Vendor column

#### Scenario: Vendor in JSON
- GIVEN `vendor: Some("Cisco")` → THEN `"vendor": "Cisco"` in output

#### Scenario: Null vendor in JSON
- GIVEN `vendor: None` → THEN `"vendor": null` in output

#### Scenario: HTML report renders vendor
- GIVEN host with vendor → THEN vendor value in report Vendor column