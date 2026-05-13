# Proposal: Report Generator MVP

## Intent

The `report` subcommand exists as a stub — it prints "report subcommand (stub)" and does nothing. A Tera HTML template exists at `src/report/templates/report.html.tera` but is never instantiated. Users who run `netascan scan` get results on stdout with no way to save, review, or share them. This change implements HTML + JSON report generation from scan data so users can produce actionable security reports.

## Scope

### In Scope
- Report view model that flattens per-port CVEs into host-level aggregates
- HTML report generation via Tera (embedded template with `include_dir`)
- JSON report generation (serde serialization of scan data)
- CLI wiring: `--input <file>` flag to load scan data from JSON file or stdin
- Fix template/data mismatch: `host.cves` → aggregated from `host.open_ports[].cves`
- Write output to `--output <path>` or stdout

### Out of Scope
- Scan persistence / database storage (no `--last` support yet)
- Web dashboard server (`serve` subcommand remains stub)
- PDF generation (use browser "Print to PDF" from HTML)
- Report templates beyond the single existing HTML template

## Capabilities

### New Capabilities
- `report-generation`: Generate HTML and JSON reports from scan data loaded via `--input` flag. Accepts JSON matching `Vec<DiscoveredHost>` schema. Produces formatted HTML via Tera template or raw JSON output.

### Modified Capabilities
- None

## Approach

1. **View model** (`src/report/view_model.rs`): Create `ReportHost` and `ReportContext` structs that flatten `DiscoveredHost` → `ReportHost` with aggregated `cves: Vec<CveSummary>` collected from all `open_ports[].cves`. This bridges the template's expectation of `host.cves` with the actual nested data model.

2. **Template fix** (`src/report/templates/report.html.tera`): Update template to iterate CVEs per-host (from the view model), not per-port. Add CVE severity coloring and detail rows.

3. **Report engine** (`src/report/mod.rs`): Replace stub with `generate_html()` (Tera + `include_dir`) and `generate_json()` (serde_json) functions. Embed template at compile time via `include_dir!`.

4. **CLI wiring** (`src/cli/report.rs`): Add `--input <file>` flag (`Option<String>`, defaults to stdin if `-`). Replace stub handler in `cli/mod.rs` to read JSON, build view model, call report engine, write to `--output` or stdout.

5. **Deprecate `--last`**: Keep flag but emit "not yet implemented — use `--input` with saved scan JSON" message.

## Affected Areas

| Area | Impact | Description |
|------|--------|-------------|
| `src/report/mod.rs` | Modified | Replace stub with report engine (HTML + JSON generation) |
| `src/report/view_model.rs` | New | View model structs bridging scan data → template context |
| `src/report/templates/report.html.tera` | Modified | Fix `host.cves` reference, add CVE detail rendering |
| `src/cli/report.rs` | Modified | Add `--input` flag, remove `--last` functionality |
| `src/cli/mod.rs` | Modified | Wire report handler to engine |
| `Cargo.toml` | Modified | Add `include_dir` feature usage (already present as dep) |

## Risks

| Risk | Likelihood | Mitigation |
|------|------------|------------|
| Template/data mismatch causes Tera render errors | Medium | View model guarantees flat `cves` field; unit tests with sample data |
| Tera API unfamiliarity (embedded templates) | Low | `include_dir` + `Tera::one_off()` pattern is well-documented; use existing crate |
| Large scan JSON causes memory issues | Low | MVP targets typical /24 scans (~256 hosts max); streaming not needed |
| `--input` JSON schema drifts from `DiscoveredHost` | Medium | Use same serde types; version field in JSON for future compatibility |

## Rollback Plan

1. Revert the `report` handler in `src/cli/mod.rs` back to the stub `println!`
2. Restore `src/report/mod.rs` to its original 8-line stub
3. Delete `src/report/view_model.rs`
4. Restore the original template (git checkout)
5. No database migrations or config changes to undo

## Dependencies

- None beyond existing crates (`tera`, `include_dir`, `serde`, `serde_json`, `chrono`)

## Success Criteria

- [ ] `netascan report --input scan.json --format html` produces valid HTML file
- [ ] `netascan report --input scan.json --format json` produces valid JSON output
- [ ] `netascan report --input -` reads from stdin
- [ ] HTML report shows all hosts with aggregated CVE counts from all ports
- [ ] Template renders without Tera errors on sample scan data
- [ ] `cargo test` passes with report module tests
- [ ] `cargo clippy` reports no warnings in new code
