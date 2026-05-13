# Report Generation Specification

## Purpose

Generate HTML and JSON audit reports from scan data, using a view model that flattens per-port CVEs into host-level aggregates for template consumption.

## Requirements

### REQ-RG-1: Scan Data Input

| Field | Value |
|-------|-------|
| Statement | The system MUST read scan data from `--input <file>` (JSON path) or stdin (`--input -`), deserializing into `Vec<DiscoveredHost>`. Invalid or unreadable input MUST produce a human-readable error and exit code 1. |
| Priority | P1 |

- **File input**: GIVEN `scan.json` exists with valid data → WHEN `--input scan.json` → THEN hosts deserialized and passed to engine
- **Stdin**: GIVEN data piped → WHEN `--input -` → THEN stdin read to EOF and deserialized
- **Missing file**: GIVEN `--input missing.json` → THEN error to stderr, exit code 1

---

### REQ-RG-2: Report View Model

| Field | Value |
|-------|-------|
| Statement | The system MUST flatten `DiscoveredHost` → `ReportHost` where `cves` is the deduplicated aggregation of `open_ports[*].cves`. `ReportContext` SHALL contain `generated_at` (ISO 8601), `network` (subnet), and `hosts: Vec<ReportHost>`. Hosts with no CVEs MUST appear with an empty `cves` list. |
| Priority | P1 |

- **CVE aggregation**: GIVEN host with port 22 (2 CVEs) and port 80 (3 CVEs) → THEN `ReportHost.cves` has 5 deduplicated entries
- **No CVEs**: GIVEN host with open ports but zero CVE matches → THEN `cves` is empty `Vec`

---

### REQ-RG-3: HTML Report Generation

| Field | Value |
|-------|-------|
| Statement | The system MUST render HTML via Tera with templates loaded through `include_dir!`. The template MUST use `host.cves` from the view model (not raw `DiscoveredHost`). Output MUST be valid HTML5. Render errors MUST return a descriptive message and exit code 1. |
| Priority | P1 |
| Depends on | REQ-RG-2 |

- **To file**: GIVEN `--format html --output report.html` → THEN valid HTML5 written to path
- **To stdout**: GIVEN `--format html` with no `--output` → THEN HTML to stdout
- **Render failure**: GIVEN template referencing undefined variables → THEN descriptive error, exit code 1

---

### REQ-RG-4: JSON Report Generation

| Field | Value |
|-------|-------|
| Statement | The system MUST produce JSON via serde_json as a `ReportContext` wrapper with `generated_at`, `network`, `version` (`"0.1.0"`), and `hosts`. Output MUST be pretty-printed (2-space indent). |
| Priority | P1 |
| Depends on | REQ-RG-2 |

- **To file**: GIVEN `--format json --output report.json` → THEN pretty-printed JSON with all four fields written
- **To stdout**: GIVEN `--format json` with no `--output` → THEN pretty-printed JSON to stdout

---

### REQ-RG-5: CLI Wiring and `--last` Deprecation

| Field | Value |
|-------|-------|
| Statement | `--input <path>` MUST be added to `ReportArgs`. `--format` MUST accept `html` or `json` (default `html`). `--last` MUST print `"not yet implemented"` to stderr and exit 0. The handler MUST invoke the engine scoped to format and input source. |
| Priority | P1 |
| Depends on | REQ-RG-1, REQ-RG-3, REQ-RG-4 |

- **Default format**: GIVEN `netascan report --input scan.json` with no `--format` → THEN HTML report generated
- **Invalid format**: GIVEN `--format pdf` → THEN error listing valid formats, exit code 1
- **`--last` deprecation**: GIVEN `--last` → THEN `"not yet implemented"` to stderr, exit code 0