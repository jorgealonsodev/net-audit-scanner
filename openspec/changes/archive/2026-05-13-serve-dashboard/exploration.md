# Exploration: serve-dashboard

## Current State

The `netascan serve` subcommand is a 2-line stub that prints `"serve subcommand (stub)"`. The CLI infrastructure is already in place:

- `src/cli/serve.rs` — `ServeArgs` struct with `--port` (default 7070) and `--bind` (default 127.0.0.1)
- `src/cli/mod.rs:133-135` — match arm dispatches to the stub
- `src/server/mod.rs` — 3 lines, doc comment only, no implementation
- `axum 0.7` — already in `Cargo.toml` as a dependency

The report engine (`src/report/engine.rs`) is fully functional:
- `ReportEngine::new()` — loads embedded Tera templates via `include_dir!`
- `ReportEngine::render_html(&ReportContext)` — produces complete HTML
- `ReportEngine::render_json(&ReportContext)` — produces pretty-printed JSON
- Templates live at `src/report/templates/` (embedded at compile time)

The view model (`src/report/view_model.rs`) provides:
- `ReportContext` — top-level container with `hosts: Vec<ReportHost>`, summary totals, metadata
- `ReportHost` — per-host summary with ports, CVEs, vendor, MAC
- Full `Serialize`/`Deserialize` on all types — `ReportContext` roundtrips through JSON

The scan CLI (`netascan scan --json`) outputs `Vec<DiscoveredHost>` as JSON, which is the **exact same format** that `report --input` reads and the report engine consumes.

**No persistence layer exists.** Scan results are ephemeral — printed to stdout or written to a file by the user.

## Affected Areas

- `src/server/mod.rs` — needs full implementation (Axum router, handlers, state)
- `src/cli/mod.rs:133-135` — replace stub with `server::run(args).await`
- `src/cli/serve.rs` — may need minor additions (e.g., `--read-timeout`)
- `Cargo.toml` — may need `tower-http` (for static file serving, CORS) or `multipart` crate
- `src/error.rs` — may need a `Server` error variant

## Approaches

### Approach A: Upload + View Dashboard (Recommended MVP)

A single-page web app with a file upload form. User uploads a JSON scan result (from `netascan scan --json > scan.json`), the server parses it, renders the HTML report inline, and displays it. No persistence needed.

**Routes:**
- `GET /` — Upload page (simple HTML form with `<input type="file">`)
- `POST /report` — Accept JSON upload, render HTML, return rendered report as HTML fragment or full page
- `GET /health` — Health check (optional)

**Pros:**
- Zero persistence — stateless, no database, no files to manage
- Reuses existing `ReportEngine` and `ReportContext` directly
- Works with any existing scan JSON file
- Minimal new dependencies (axum already present, may need `axum-extra` or manual multipart parsing)
- ~150-250 lines of new code
- Clear MVP boundary

**Cons:**
- Requires user to run scan separately and upload the file
- No "live" dashboard feel — manual upload each time
- No history of previous scans

**Effort:** Low (1-2 hours)

### Approach B: Live Dashboard with In-Memory Store

Server maintains an in-memory `Vec<ReportContext>` (or last-scan-only). User uploads JSON, server stores it, dashboard shows the latest scan with auto-refresh via SSE or polling.

**Routes:**
- `GET /` — Dashboard (shows latest scan or upload form)
- `POST /api/scans` — Upload + store scan JSON
- `GET /api/scans/latest` — Return latest scan as JSON (for client-side rendering)
- `GET /api/scans/:id` — Return specific scan
- `GET /report/:id` — Render HTML report for a stored scan

**Pros:**
- Better UX — dashboard shows current state without manual navigation
- Can support multiple stored scans (in-memory list)
- Auto-refresh possible with minimal JS

**Cons:**
- In-memory store loses data on restart (user confusion risk)
- More routes, more state management
- Still no true persistence — just deferred loss
- Slightly more complex (~300-400 lines)

**Effort:** Medium (2-4 hours)

### Approach C: Full Persistence + Live Dashboard

Add SQLite-based scan storage. Each upload creates a persisted scan record. Dashboard shows scan history, comparison, trends.

**Pros:**
- Full audit trail — scans survive restarts
- Can build rich features: comparison, trend analysis, export
- SQLite is already a dependency (via sqlx)

**Cons:**
- Significant scope creep — schema design, migrations, CRUD operations
- sqlx is already used for CVE cache, but adding scan storage is a separate concern
- ~500+ lines of new code + schema + tests
- Out of scope for MVP

**Effort:** High (1-2 days)

## Recommendation

**Approach A (Upload + View) as MVP**, with Approach B as a natural follow-up.

Rationale:
1. The report engine already does 90% of the work — it just needs an HTTP wrapper
2. Zero new dependencies beyond axum (multipart can be done with axum's built-in `Form` + `Bytes`)
3. Clear, testable boundary: parse JSON → render HTML → serve
4. No persistence means no schema decisions, no migration concerns
5. The upload form is trivial HTML — can be a single inline template
6. Fits within the 400-line review budget comfortably

### Proposed Axum Routes (MVP)

```
GET  /              → Upload page (inline HTML, not a template)
POST /report        → Accept JSON body, render HTML report, return HTML
GET  /health        → 200 OK
```

### State Design

No shared state needed for MVP. Each request is independent:
- Request body: raw JSON (`Vec<DiscoveredHost>`) or multipart form with `.json` file
- Processing: `serde_json::from_str` → `ReportContext::from` → `ReportEngine::render_html`
- Response: HTML string

### Dependency Additions

- `tower-http` (optional) — for `ServeFile`, compression, request tracing
- No new crates strictly required — axum handles JSON body parsing natively

### File Structure

```
src/server/
├── mod.rs          # Server entry point: run(args) -> Result<()>
├── routes.rs       # Handler functions (index, report, health)
└── state.rs        # (empty for MVP, placeholder for future)
```

## Risks

1. **Multipart parsing complexity** — If using file upload form (not raw JSON POST), need multipart handling. Axum 0.7 has `axum::extract::Multipart` but it requires the `multipart` feature flag. Mitigation: accept raw JSON POST body instead of multipart form, or enable the feature.
2. **Template asset serving** — The Tera templates are embedded via `include_dir!` but not directly servable as static files. Mitigation: render server-side, don't serve templates directly.
3. **Large JSON payloads** — Scan results with many hosts could be large. Mitigation: set reasonable body size limits (axum default is generous enough for typical scans).
4. **Blocking Tera rendering** — Tera template rendering is synchronous. On a busy server this could block the tokio runtime. Mitigation: for MVP with single-user local access, not a concern. For future, use `tokio::task::spawn_blocking`.

## Ready for Proposal

**Yes.** The exploration is complete. The recommended approach (A — Upload + View) has:
- Clear scope boundaries
- Minimal new code (~150-250 lines)
- No new dependencies required
- Reuses existing report engine 1:1
- Fits within review budget

The orchestrator should proceed to **sdd-propose** to create the change proposal, then **sdd-spec** for route contracts, and **sdd-design** for the server architecture.
