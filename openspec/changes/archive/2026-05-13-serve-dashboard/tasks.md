# Tasks: serve-dashboard

## Review Workload Forecast

| Field | Value |
|-------|-------|
| Estimated changed lines | ~200–280 |
| 400-line budget risk | Low |
| Chained PRs recommended | No |
| Suggested split | Single PR |
| Delivery strategy | auto-chain |
| Chain strategy | stacked-to-main |

Decision needed before apply: No
Chained PRs recommended: No
Chain strategy: stacked-to-main
400-line budget risk: Low

### Suggested Work Units

| Unit | Goal | Likely PR | Notes |
|------|------|-----------|-------|
| 1 | Full serve-dashboard implementation | PR 1 | Single PR; tests and docs included |

## Phase 1: Foundation — Types and Interfaces

- [x] 1.1 Add `multipart` feature to `axum` in `Cargo.toml`
- [x] 1.2 Create `src/server/mod.rs` with `run(args: ServeArgs) -> Result<(), Error>` function signature and basic Axum router scaffolding

## Phase 2: Core Implementation — Handlers

- [x] 2.1 RED: write `#[cfg(test)]` for `index()` handler — assert response contains `<form` and `action="/report"`
- [x] 2.2 GREEN: implement `index()` returning `Html<String>` from embedded static asset
- [x] 2.3 RED: write `#[cfg(test)]` for `health()` handler — assert body `"ok"` and status 200
- [x] 2.4 GREEN: implement `health()` returning ` &'static str`
- [x] 2.5 RED: write `#[cfg(test)]` for `report()` — valid JSON → 200 + HTML; malformed JSON → 400; empty file → 400; missing file → 400
- [x] 2.6 GREEN: implement `report(multipart: Multipart)` — extract file bytes, `serde_json::from_slice`, `ReportContext::from`, `spawn_blocking { ReportEngine::render_html() }`
- [x] 2.7 REFACTOR: extract error conversion helper `into_status_code(err: Error) -> StatusCode`

## Phase 3: Static Assets

- [x] 3.1 Create `src/server/static/index.html` with upload form, inline CSS, `<input type="file" accept=".json">`, no JS

## Phase 4: CLI Wiring

- [x] 4.1 RED: write `#[cfg(test)]` for serve dispatch in `cli/mod.rs` — stub returns unimplemented
- [x] 4.2 GREEN: replace `Commands::Serve` stub with `server::run(args).await`
- [x] 4.3 GREEN: propagate server startup errors (port in use) to caller

## Phase 5: Testing and Verification

- [x] 5.1 Unit: test `index()` handler directly
- [x] 5.2 Unit: test `health()` handler directly
- [x] 5.3 Unit: test `report()` with valid multipart JSON — assert 200 and HTML table/report markers
- [x] 5.4 Unit: test `report()` with malformed JSON — assert 400
- [x] 5.5 Unit: test `report()` with empty file — assert 400 + "empty input"
- [x] 5.6 Unit: test `report()` with missing file field — assert 400 + "no file"
- [x] 5.7 Integration: `cargo test server::` passes
- [x] 5.8 Integration: `cargo clippy` — no warnings in new code
- [x] 5.9 Integration: verify `GET /health` returns 200 + "ok" (integration test or manual)
