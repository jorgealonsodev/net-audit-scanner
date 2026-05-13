# Design: Report Generator MVP

## Technical Approach

Build a `ReportEngine` that reads scan JSON, flattens `DiscoveredHost` into a template-friendly `ReportContext` via a `ReportHost` view model (aggregating per-port CVEs to host-level), and renders via Tera (HTML) or serde_json (JSON). Templates are embedded at compile time with `include_dir!`, following the pattern already used for the OUI database. The CLI handler dispatches to `ReportEngine::generate()` based on `--format`.

## Architecture Decisions

### Decision: View model placement

| Option | Tradeoff | Decision |
|--------|----------|----------|
| `ReportHost` in `src/report/view_model.rs` | Single-responsibility, colocated with engine | **Chosen** |
| Ad-hoc `HashMap` in engine | No new file, but untyped and untestable | Rejected |
| Extend `DiscoveredHost` with a `cves_flat` field | Couples domain model to presentation | Rejected |

**Rationale**: The view model is a presentation concern. Isolating it from `scanner::models` keeps domain types clean and makes CVE aggregation independently testable.

### Decision: Template loading strategy

| Option | Tradeoff | Decision |
|--------|----------|----------|
| `include_dir!` for `src/report/templates/` | Compile-time embed, zero runtime I/O, matches OUI pattern | **Chosen** |
| `Tera::new("templates/**/*")` | Runtime file I/O, breaks single-binary goal | Rejected |
| Inline `const` strings | Works but hard to maintain for multi-template future | Rejected |

**Rationale**: The project already uses `include_dir!` for `data/manuf`. Using it for templates preserves the single-binary portability and is a proven pattern in this codebase.

### Decision: JSON report wrapper structure

| Option | Tradeoff | Decision |
|--------|----------|----------|
| `ReportContext` wrapper with `generated_at`, `version`, `network`, `hosts` | Structured, self-describing, avoids top-level arrays | **Chosen** |
| Bare `Vec<DiscoveredHost>` array | No metadata, no version — fragile for consumers | Rejected |
| `serde_json::Value` dynamic | No type safety | Rejected |

**Rationale**: A wrapper object lets consumers validate schema version and metadata without parsing hosts. This is a general best practice for JSON APIs.

### Decision: Output routing

| Option | Tradeoff | Decision |
|--------|----------|----------|
| `--output <path>` or stdout when absent | Matches Unix conventions, same pattern as scan's JSON output | **Chosen** |
| Always write to file | Forces temp files for piping | Rejected |

**Rationale**: The scan subcommand already writes to stdout with `--json`. Mirror that pattern for consistency.

## Data Flow

```
CLI (--input, --format, --output)
  │
  ▼
Read JSON ──── stdin or file path
  │
  ▼
serde_json::from_str → Vec<DiscoveredHost>
  │
  ▼
ReportHost::from_discovered(host) → ReportHost  (CVE aggregation)
  │                                              │
  ├─ ReportContext { generated_at, version,      │
  │                  network, hosts }            │
  ▼                                              │
┌─ format = html ──→ Tera::render_str ──────────┘
│   (template from include_dir!)
│
├─ format = json ──→ serde_json::to_string_pretty ─┘
│
▼
Write ──── file path or stdout
```

## File Changes

| File | Action | Description |
|------|--------|-------------|
| `src/report/view_model.rs` | Create | `ReportHost`, `ReportContext` structs, `From<DiscoveredHost>` impl with CVE aggregation |
| `src/report/engine.rs` | Create | `ReportEngine` struct with `generate()` method; template loading via `include_dir!`; render dispatch |
| `src/report/mod.rs` | Modify | Declare `view_model` and `engine` modules; re-export `ReportEngine` |
| `src/report/templates/report.html.tera` | Modify | Fix template to use `host.cves` from view model (already correct ref), add CVE detail rows |
| `src/cli/report.rs` | Modify | Add `--input` flag with `Option<String>`, update `--format` to validate `html\|json` |
| `src/cli/mod.rs` | Modify | Wire `Commands::Report` to call `ReportEngine::generate()`, handle `--last` deprecation |
| `src/error.rs` | Modify | Add `Report(String)` and `Template(String)` error variants |

## Interfaces / Contracts

```rust
// src/report/view_model.rs

/// Flattened view model for a single host in a report.
#[derive(Debug, Clone, Serialize)]
pub struct ReportHost {
    pub ip: String,
    pub mac: Option<String>,
    pub hostname: Option<String>,
    pub vendor: Option<String>,
    pub open_ports: Vec<ReportPort>,
    pub cves: Vec<ReportCve>,       // aggregated from all ports
    pub total_cves: usize,          // cves.len() for Tera convenience
    pub insecure_ports: usize,      // count of ports where is_insecure=true
}

#[derive(Debug, Clone, Serialize)]
pub struct ReportPort {
    pub port: u16,
    pub service: String,
    pub banner: Option<String>,
    pub is_insecure: bool,
    pub cve_count: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct ReportCve {
    pub cve_id: String,
    pub description: String,
    pub severity: String,
    pub score: Option<f32>,
}

/// Top-level context for report templates and JSON output.
#[derive(Debug, Clone, Serialize)]
pub struct ReportContext {
    pub generated_at: String,   // ISO 8601
    pub version: String,        // "0.1.0"
    pub host_count: usize,
    pub hosts: Vec<ReportHost>,
}

impl ReportHost {
    /// Build from a `DiscoveredHost`, aggregating CVEs across all ports.
    pub fn from_discovered(host: &DiscoveredHost) -> Self { ... }
}
```

```rust
// src/report/engine.rs

pub struct ReportEngine;

impl ReportEngine {
    /// Generate a report from scan data.
    pub fn generate(
        hosts: &[DiscoveredHost],
        format: &str,
        output: Option<&Path>,
    ) -> Result<(), Error> { ... }
}
```

## Testing Strategy

| Layer | What to Test | Approach |
|-------|-------------|----------|
| Unit | `ReportHost::from_discovered` — CVE aggregation, dedup, empty CVEs | `#[cfg(test)]` in `view_model.rs`, construct `DiscoveredHost` fixtures |
| Unit | `ReportContext` construction — metadata, host_count | `#[cfg(test)]` in `view_model.rs` |
| Unit | `ReportEngine::generate` — HTML render produces valid output | `#[cfg(test)]` in `engine.rs`, use `format="html"` to temp file, check contains tags |
| Unit | `ReportEngine::generate` — JSON render round-trips | `#[cfg(test)]` in `engine.rs`, deserialize output back into `ReportContext` |
| Integration | CLI `netascan report --input scan.json --format html` | `assert_cmd` crate, provide fixture JSON, assert exit 0 + output contains HTML |
| Integration | CLI `--input -` stdin pipe | `assert_cmd` with stdin pipe |
| Integration | Error cases: missing file, invalid JSON, bad format | `assert_cmd`, assert exit 1 + stderr message |

## Migration / Rollout

No migration required. The report subcommand is currently a stub (`println!("report subcommand (stub)")`). This change replaces it with working logic. Rollback is reverting to the stub.

## Open Questions

- [ ] Should `network` (subnet CIDR) be stored in the scan JSON for `ReportContext`, or derived/inferred? Current `Vec<DiscoveredHost>` has no subnet field — may need an optional wrapper at scan time. For MVP, `network` will be `"unknown"` if not provided, or extracted from any host's subnet calculation.
- [ ] The template currently uses `{{ network }}` with no data source. Design uses `"unknown"` fallback for MVP; a future change can persist the scanned CIDR in the JSON file.