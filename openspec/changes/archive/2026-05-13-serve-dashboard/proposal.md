# Proposal: Serve Dashboard MVP

## Intent

The `serve` subcommand is a 2-line stub that prints `"serve subcommand (stub)"`. Users who run `netascan scan --json > scan.json` have no interactive way to view the resulting report in a browser. This change implements a stateless web dashboard where users can upload a scan JSON file and immediately see the rendered HTML report — no persistence, no database, zero state between requests.

## Scope

### In Scope
- `GET /` — Upload page with HTML form (`<input type="file">`)
- `POST /report` — Accept uploaded JSON file, render HTML report, return full HTML page
- `GET /health` — Health check returning 200 OK
- `--port` and `--bind` flags on `ServeArgs` (already exist, defaults: 7070, 127.0.0.1)
- Embedded static HTML/CSS for the upload form via `include_dir!`
- Reuse existing `ReportEngine::render_html()` with `ReportContext` deserialized from uploaded JSON
- Server runs until Ctrl+C (tokio signal handler)

### Out of Scope
- Scan persistence or history (stateless, no DB)
- Live scan triggering from the web UI
- API endpoints returning JSON (server-side rendering only)
- Authentication or access control (binds to localhost by default)
- Multiple stored scans or comparison features
- WebSocket / SSE / real-time updates

## Capabilities

### New Capabilities
- `serve-dashboard`: Stateless web server that accepts scan JSON uploads and renders HTML reports in the browser. Runs via `netascan serve [--port N] [--bind ADDR]`.

### Modified Capabilities
- None

## Approach

1. **Axum router** (`src/server/mod.rs`): Build router with `GET /`, `POST /report`, `GET /health` routes. Bind to `--bind:--port`. Run until `tokio::signal::ctrl_c()`.

2. **Upload form** (`src/server/static/index.html`): Minimal HTML page with file input and submit button. Embedded via `include_dir!`. No JS framework needed.

3. **Multipart handler**: Use `axum::extract::Multipart` (requires `multipart` feature on axum) to parse the uploaded `.json` file. Deserialize into `Vec<DiscoveredHost>`, convert to `ReportContext`, render via `ReportEngine::render_html()`, return HTML.

4. **CLI wiring** (`src/cli/mod.rs`): Replace stub with `server::run(args).await`.

5. **Cargo.toml**: Add `multipart` feature to axum dependency.

## Affected Areas

| Area | Impact | Description |
|------|--------|-------------|
| `src/server/mod.rs` | Modified | Replace 3-line stub with full Axum server implementation |
| `src/server/static/index.html` | New | Upload form HTML + inline CSS |
| `src/cli/mod.rs:133-135` | Modified | Replace stub with `server::run(args).await` |
| `Cargo.toml` | Modified | Add `multipart` feature to axum |

## Risks

| Risk | Likelihood | Mitigation |
|------|------------|------------|
| Multipart parsing complexity | Low | Axum 0.7 has built-in `Multipart` extractor; well-documented |
| Large JSON payloads block tokio | Low (MVP) | Single-user local access; use `spawn_blocking` for Tera render if needed |
| Axum `multipart` feature not enabled | Medium | Explicitly add `features = ["multipart"]` to axum in Cargo.toml |
| Browser CORS issues | Low | Binds to 127.0.0.1; same-origin by default |

## Rollback Plan

1. Revert `src/cli/mod.rs` serve handler back to the stub `println!`
2. Restore `src/server/mod.rs` to its original 3-line stub
3. Delete `src/server/static/index.html`
4. Remove `multipart` feature from axum in Cargo.toml
5. No database migrations or config changes to undo

## Dependencies

- `axum` with `multipart` feature (axum already in Cargo.toml)
- `include_dir` (already in Cargo.toml)
- Reuses `ReportEngine`, `ReportContext`, `DiscoveredHost` from existing modules

## Success Criteria

- [ ] `netascan serve` starts server on `127.0.0.1:7070`
- [ ] `netascan serve --port 8080` binds to custom port
- [ ] `GET /` returns upload form with file input
- [ ] `POST /report` with valid scan JSON returns rendered HTML report
- [ ] `POST /report` with invalid JSON returns 400 error
- [ ] `GET /health` returns 200 OK
- [ ] Server shuts down gracefully on Ctrl+C
- [ ] `cargo test` passes with server module tests
- [ ] `cargo clippy` reports no warnings in new code
