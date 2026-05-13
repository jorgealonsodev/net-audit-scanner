# Scan Persistence — Delta Spec

## REQ-PERS-1: Scan Auto-Save

| Field | Value |
|-------|-------|
| Statement | The system MUST automatically save completed scan results as a JSON file in `~/.cache/netascan/scans/` after CVE enrichment and before CLI output. The filename MUST be `<ISO-8601-timestamp>.json` (e.g., `2026-05-13T10-30-00Z.json`). The file MUST contain a `ScanRecord` wrapper with `id`, `started_at`, `completed_at`, `network`, `cli_args`, `host_count`, `total_cves`, and `hosts` (the `Vec<DiscoveredHost>`). Save failures MUST log a warning but MUST NOT abort the scan or prevent stdout output. |
| Priority | P0 |

- **Happy path**: GIVEN a successful scan → WHEN scan completes → THEN JSON file created in scans directory with all metadata
- **Empty scan**: GIVEN zero hosts discovered → THEN file still saved with `host_count: 0` and empty `hosts` array
- **Save failure**: GIVEN disk full or permission error → THEN warning logged to stderr, scan output still printed to stdout
- **No-CVE scan**: GIVEN `--no-cve` flag → THEN saved scan has hosts with empty CVE arrays (reflects actual run)

---

## REQ-PERS-2: Last Scan Retrieval

| Field | Value |
|-------|-------|
| Statement | The system MUST provide a `load_last_scan()` function that returns the most recently saved scan. When `netascan report --last` is invoked, the handler MUST call `load_last_scan()` and pass the resulting `Vec<DiscoveredHost>` to the existing report engine. If no saved scan exists, the system MUST print "No saved scans found. Run `netascan scan` first." to stderr and exit with code 1. |
| Priority | P0 |
| Depends on | REQ-PERS-1 |

- **Last exists**: GIVEN at least one saved scan → WHEN `--last` → THEN most recent scan loaded and passed to report engine
- **No scans**: GIVEN empty scans directory → WHEN `--last` → THEN error message to stderr, exit code 1
- **Corrupted file**: GIVEN `last.json` with invalid JSON → THEN error with path and parse details, exit code 1
- **With format**: GIVEN `--last --format json` → THEN JSON report from last scan (uses existing format logic)

---

## REQ-PERS-3: Scan Cleanup

| Field | Value |
|-------|-------|
| Statement | The system MUST enforce a maximum of 10 saved scan files. After each successful save, the system MUST delete the oldest files if the count exceeds 10. The `last.json` file MUST NOT count toward this limit. Deletion failures MUST log a warning but MUST NOT abort the save operation. |
| Priority | P1 |
| Depends on | REQ-PERS-1 |

- **Under limit**: GIVEN 5 saved scans → WHEN new scan saved → THEN 6 files exist, none deleted
- **At limit**: GIVEN 10 saved scans → WHEN new scan saved → THEN 10 files exist (oldest deleted)
- **last.json preserved**: GIVEN cleanup runs → THEN `last.json` is never deleted

---

## REQ-PERS-4: Atomic Write

| Field | Value |
|-------|-------|
| Statement | The system MUST write scan files atomically to prevent corruption from interrupted writes. Each save MUST write to a temporary file in the same directory, then rename it to the target filename using `std::fs::rename`. The `last.json` file MUST also be written atomically. |
| Priority | P1 |
| Depends on | REQ-PERS-1 |

- **Atomic save**: GIVEN scan completes → WHEN saving → THEN temp file written, then renamed (no partial file visible)
- **last.json atomic**: GIVEN save succeeds → THEN `last.json` updated via temp+rename, not direct overwrite

---

## REQ-PERS-5: ScanRecord Schema

| Field | Value |
|-------|-------|
| Statement | The `ScanRecord` struct MUST include: `id` (UUID v4 string), `started_at` (ISO 8601 UTC), `completed_at` (ISO 8601 UTC), `network` (CIDR string from CLI args), `cli_args` (object with `port_range`, `full`, `no_cve` booleans/strings), `host_count` (usize), `total_cves` (usize, sum of all CVEs across all hosts), and `hosts` (`Vec<DiscoveredHost>`). All fields MUST be serializable via serde. |
| Priority | P0 |
| Depends on | REQ-PERS-1 |

- **Schema completeness**: GIVEN a saved scan file → WHEN deserialized → THEN all fields present and typed correctly
- **Round-trip**: GIVEN `ScanRecord` → WHEN serialized then deserialized → THEN all data matches original
