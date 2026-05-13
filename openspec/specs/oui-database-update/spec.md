# Spec: oui-database-update

## Purpose

Download, cache, and runtime-load the Wireshark manuf OUI database with embedded fallback.

## Requirements

### REQ-UPD-1: OUI Database Download

`netascan update` MUST download the Wireshark manuf database from the canonical URL and cache it locally.

#### Scenario: Download success

- GIVEN network connectivity and valid manuf URL
- WHEN `netascan update` runs
- THEN file downloads to `~/.cache/netascan/manuf` atomically (tmp + rename)
- AND entry count and source URL printed to stdout

#### Scenario: Download failure → embedded fallback

- GIVEN network unavailable or URL unreachable
- WHEN `netascan update` runs
- THEN error message printed to stderr, process exits non-zero
- AND existing cache preserved, embedded DB still available for scans

---

### REQ-UPD-2: Atomic Cache Write

The download handler MUST write to a temporary file and rename atomically, ensuring no partial files remain on failure.

#### Scenario: Successful atomic write

- GIVEN successful download → WHEN content written to `.tmp` → THEN atomic rename replaces previous cache

#### Scenario: Download interrupted mid-stream

- GIVEN partial download fails → WHEN write to `.tmp` fails → THEN `.tmp` deleted, existing cache untouched

---

### REQ-UPD-3: Cache-First OUI Initialization

`OUI_DB` MUST try loading from cache first; if absent or unreadable, MUST fall back to embedded.

#### Scenario: Cache hit

- GIVEN `~/.cache/netascan/manuf` exists and is valid → WHEN `OUI_DB` initializes → THEN cached file loaded

#### Scenario: Cache miss

- GIVEN no cached manuf file → WHEN `OUI_DB` initializes → THEN embedded DB loaded, no error

#### Scenario: Corrupted cache

- GIVEN cached manuf unreadable or invalid → WHEN `OUI_DB` initializes → THEN warning logged, embedded DB used

---

### REQ-UPD-4: Skip Cache with --no-update

`netascan scan --no-update` MUST skip cache and use the embedded OUI database regardless of cache state.

#### Scenario: --no-update forces embedded

- GIVEN cached manuf exists → WHEN `netascan scan --no-update` runs → THEN embedded DB used, cache ignored