# Implementation Tasks: report-generator

**Change**: report-generator
**Spec**: REQ-RG-1 through REQ-RG-5 (5 requirements, 11 scenarios)
**Design**: View model → ReportEngine → CLI wiring
**TDD**: `cargo test` (Rust project)

---

## Review Workload Forecast

| Phase | File(s) | Est. Lines | Risk |
|-------|---------|-----------|------|
| 1 | `src/report/view_model.rs` | ~130 | LOW |
| 2 | `src/report/engine.rs` | ~150 | LOW |
| 3 | `src/report/mod.rs` | ~20 | LOW |
| 4 | `src/cli/report.rs`, `src/cli/mod.rs` | ~80 | MEDIUM |
| 5 | `src/error.rs` | ~10 | LOW |
| 6 | `src/report/templates/report.html.tera` | ~50 | LOW |
| **Total** | | **~440** | **HIGH** |

> ⚠️ **~440 lines exceeds the 400-line budget.** Stacked-to-main chain recommended.
> Plan 3 PRs:
> - **PR 1**: Phases 1–2 (view model + engine) ✅ COMPLETE
> - **PR 2**: Phase 3–5 (module wiring + CLI + errors) ✅ COMPLETE
> - **PR 3**: Phase 6 (template + integration tests) Pending

**Strict TDD**: Write failing test → implement → green → refactor.

---

## Phase 1 — View Model

**File**: `src/report/view_model.rs` (NEW)

### 1.1 `ReportCve` struct

```rust
#[derive(Debug, Clone, Serialize)]
pub struct ReportCve {
    pub cve_id: String,
    pub description: String,
    pub severity: String,
    pub score: Option<f32>,
}
```

Tests:
- Default construction with all fields
- Serializes to JSON with `cve_id`, `description`, `severity`, `score`

### 1.2 `ReportPort` struct

```rust
#[derive(Debug, Clone, Serialize)]
pub struct ReportPort {
    pub port: u16,
    pub service: String,
    pub banner: Option<String>,
    pub is_insecure: bool,
    pub cve_count: usize,
}
```

Tests:
- Default construction
- JSON round-trip

### 1.3 `ReportHost` struct

```rust
#[derive(Debug, Clone, Serialize)]
pub struct ReportHost {
    pub ip: String,
    pub mac: Option<String>,
    pub hostname: Option<String>,
    pub vendor: Option<String>,
    pub open_ports: Vec<ReportPort>,
    pub cves: Vec<ReportCve>,
    pub total_cves: usize,
    pub insecure_ports: usize,
}
```

Tests:
- Default construction
- JSON round-trip

### 1.4 `ReportHost::from_discovered()`

`impl From<&DiscoveredHost> for ReportHost`

Requirements:
- Flatten `open_ports[*].cves` into single `cves` vector (dedup by `cve_id`)
- `total_cves` = `cves.len()`
- `insecure_ports` = count of ports where `is_insecure == true`
- `open_ports` converted to `Vec<ReportPort>`
- MAC converted to hex string `aa:bb:cc:dd:ee:ff` or `null`

Tests:
- Host with 2 ports (22 with 2 CVEs, 80 with 3 CVEs) → `cves.len() == 5`
- Duplicate CVEs across ports → deduplicated
- Host with no CVEs → `cves` empty, `total_cves == 0`
- `insecure_ports` correctly counted
- `mac` formatted as hex string or `null`

### 1.5 `ReportContext` struct

```rust
#[derive(Debug, Clone, Serialize)]
pub struct ReportContext {
    pub generated_at: String,  // ISO 8601
    pub version: String,       // "0.1.0"
    pub host_count: usize,
    pub hosts: Vec<ReportHost>,
}
```

Tests:
- Construction with `generated_at = chrono::Utc::now().to_rfc3339()`
- JSON round-trip
- `host_count` matches `hosts.len()`

---

## Phase 2 — Report Engine

**File**: `src/report/engine.rs` (NEW)

### 2.1 `ReportEngine` struct and template loading

Template loaded via `include_dir!` at compile time (following `src/scanner/oui.rs` pattern):

```rust
static TEMPLATE_DIR: Dir<'_> = include_dir!("$CARGO_MANIFEST_DIR/src/report/templates");

fn embedded_template(name: &str) -> Result<String, Error> {
    TEMPLATE_DIR
        .get_file(name)
        .and_then(|f| f.contents_utf8())
        .ok_or_else(|| Error::Template(format!("template '{name}' not found")))
}
```

### 2.2 `ReportEngine::generate_html(hosts, output_path)`

- Build `ReportContext` from `&[DiscoveredHost]`
- Render via Tera `render_str` with `ReportContext` as context
- Output to `output_path` or stdout

Tests:
- Renders HTML with `<!DOCTYPE html>` and `generated_at`
- HTML contains host rows from view model (not raw `DiscoveredHost`)
- Empty hosts → valid HTML with empty `<tbody>`

### 2.3 `ReportEngine::generate_json(hosts, output_path)`

- Build `ReportContext`
- Serialize via `serde_json::to_string_pretty`
- Output to `output_path` or stdout

Tests:
- JSON has `generated_at`, `version` ("0.1.0"), `hosts` fields
- `version` is exactly "0.1.0"
- JSON is pretty-printed (2-space indent)
- Round-trip: deserialize back to `ReportContext`

### 2.4 Error handling

- Invalid JSON input → `Error::Report("...")` with exit code 1
- Template render failure → `Error::Template("...")` with exit code 1
- Invalid format → `Error::Report("invalid format")` with exit code 1

---

## Phase 3 — Module Declaration ✅ COMPLETE

**File**: `src/report/mod.rs`

```rust
pub mod engine;
pub mod view_model;

pub use engine::ReportEngine;
pub use view_model::{ReportContext, ReportHost};
```

Tests:
- [x] `module_path()` returns "report"
- [x] Module exports `ReportEngine`, `ReportContext`, `ReportHost`

---

## Phase 4 — CLI Wiring ✅ COMPLETE

**Files**: `src/cli/report.rs`, `src/cli/mod.rs`

### 4.1 `ReportArgs` additions ✅

```rust
/// Input file path (JSON scan result), or `-` for stdin
#[arg(short, long)]
pub input: Option<PathBuf>,
```

Existing fields preserved: `format`, `output`, `last`.

### 4.2 Input reading ✅

`read_input()` function handles file, stdin, and `-` for stdin.

### 4.3 Handler in `mod.rs` ✅

`Commands::Report(args)` → `report::handle_report(&args).await?`

Tests:
- [x] `--input scan.json` with valid data → HTML output
- [x] `--input -` with piped stdin → HTML output
- [x] `--input missing.json` → exit 1, error to stderr
- [x] `--format json` → JSON output
- [x] `--last` → `"not yet implemented"` to stderr, exit 0
- [x] Default format is HTML
- [x] HTML output to file
- [x] JSON output to file
- [x] JSON from stdin

---

## Phase 5 — Error Variants ✅ COMPLETE

**File**: `src/error.rs`

```rust
#[error("Report error: {0}")]
Report(String),

#[error("Template error: {0}")]
Template(String),
```

Tests:
- [x] `Error::Report("bad input")` displays "Report error: bad input"
- [x] `Error::Template("missing template")` displays "Template error: missing template"
- [x] Debug output contains variant name

---

## Phase 6 — Template Fix

**File**: `src/report/templates/report.html.tera`

The template already exists with correct `host.cves` usage (not raw `host.open_ports[*].cves`). Verify and enhance:

- `{{ generated_at }}` — ISO 8601 timestamp
- `{{ network }}` — fallback to "unknown" (no subnet in scan data MVP)
- `{{ hosts | length }}` — host count
- `{{ host.cves | length }}` in detail rows — CVE count per host

Tests (integration):
- `netascan report --input scan.json --format html` → valid HTML5
- `netascan report --input scan.json --format html | grep "Security Audit Report"`
- `netascan report --input scan.json --format json` → valid JSON with `version: "0.1.0"`

---

## Chained PR Sequence

| PR | Phases | Contents | Target | Status |
|----|--------|----------|--------|--------|
| 1 | 1, 2 | `view_model.rs` + `engine.rs` | stacked to main | ✅ COMPLETE |
| 2 | 3, 4, 5 | `mod.rs` + CLI wiring + errors | stacked to main | ✅ COMPLETE |
| 3 | 6 | Template fix + integration tests | stacked to main | Pending |

Each PR: tests pass → review → merge before next PR opens.