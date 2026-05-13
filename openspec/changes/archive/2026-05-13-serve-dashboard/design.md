# Design: Serve Dashboard MVP

## Technical Approach

Build a stateless Axum 0.7 HTTP server with three routes: `GET /` (upload form), `POST /report` (multipart JSON → HTML report), and `GET /health` (health check). The upload form HTML is embedded at compile time via `include_dir!`. Report rendering reuses the existing `ReportEngine::render_html()` with `ReportContext` deserialized from the uploaded JSON. The server runs until `tokio::signal::ctrl_c()` triggers graceful shutdown.

## Architecture Decisions

### Decision: Multipart vs raw JSON POST

| Option | Tradeoff | Decision |
|--------|----------|----------|
| `multipart/form-data` with file upload form | Better UX (file picker), requires `multipart` feature | **Chosen** |
| Raw `application/json` POST body | Simpler (axum native), but requires API client or curl | Rejected |
| Both endpoints | More code, more surface area | Rejected for MVP |

**Rationale**: The upload form is the primary UX. A file picker is more discoverable than curling a JSON endpoint. The `multipart` feature adds minimal overhead.

### Decision: Static asset embedding

| Option | Tradeoff | Decision |
|--------|----------|----------|
| `include_dir!` for `src/server/static/` | Compile-time embed, single binary, matches existing patterns | **Chosen** |
| Runtime file serving from disk | Requires distributing HTML files alongside binary | Rejected |
| Inline `const &str` in Rust source | Works but mixes content with logic | Rejected |

**Rationale**: The project already uses `include_dir!` for templates and OUI data. Consistency matters.

### Decision: Server state management

| Option | Tradeoff | Decision |
|--------|----------|----------|
| No shared state (stateless handlers) | Simplest, no synchronization, no Arc needed | **Chosen** |
| `Arc<Mutex<Vec<ReportContext>>>` for history | Enables scan history, but out of scope for MVP | Rejected |

**Rationale**: MVP is explicitly stateless. Adding state now would be premature. Each request is fully independent.

### Decision: Blocking Tera rendering

| Option | Tradeoff | Decision |
|--------|----------|----------|
| `tokio::task::spawn_blocking` for `render_html()` | Prevents tokio runtime blocking from sync Tera call | **Chosen** |
| Direct sync call in handler | Simpler, but blocks tokio worker thread | Rejected |

**Rationale**: Tera rendering is synchronous. Even for single-user local access, blocking a tokio worker is a bad habit. `spawn_blocking` is the correct pattern and costs almost nothing.

## Data Flow

```
Browser: GET /
  │
  ▼
Handler: serve embedded index.html (text/html)
  │
  ▼
User selects .json file → submits form

Browser: POST /report (multipart/form-data)
  │
  ▼
Handler: extract multipart → find "file" field → read bytes
  │
  ▼
serde_json::from_slice → Vec<DiscoveredHost>
  │
  ▼
ReportContext::from(&hosts)
  │
  ▼
spawn_blocking { ReportEngine::new()?.render_html(&ctx) }
  │
  ▼
Return HTML response (text/html, 200)
```

## File Changes

| File | Action | Description |
|------|--------|-------------|
| `src/server/mod.rs` | Modified | Replace stub with Axum router, handlers, `run()` function |
| `src/server/static/index.html` | New | Upload form HTML with inline CSS |
| `src/cli/mod.rs:133-135` | Modified | Replace stub with `server::run(args).await` |
| `Cargo.toml` | Modified | Add `multipart` feature to axum dependency |

## Route Contracts

```rust
// src/server/mod.rs

/// Start the web server. Blocks until Ctrl+C.
pub async fn run(args: ServeArgs) -> Result<(), Error>;

// Route handlers (private):

/// GET / — Serve the upload form.
async fn index() -> Html<String>;

/// POST /report — Accept multipart upload, render report.
async fn report(multipart: Multipart) -> Result<Html<String>, StatusCode>;

/// GET /health — Health check.
async fn health() -> &'static str;
```

## Static Assets

```
src/server/static/
└── index.html    # Upload form with inline CSS (no external deps)
```

The `index.html` will be a self-contained page with:
- `<form method="POST" action="/report" enctype="multipart/form-data">`
- `<input type="file" name="file" accept=".json">`
- Inline `<style>` for basic styling (no external CSS files)
- No JavaScript required

## Testing Strategy

| Layer | What to Test | Approach |
|-------|-------------|----------|
| Unit | `index()` returns HTML with form elements | `#[cfg(test)]`, call handler directly, assert contains `<form>` |
| Unit | `health()` returns "ok" | Direct handler call, assert body |
| Unit | `report()` with valid JSON returns HTML | Construct multipart body in test, assert contains `<table>` or report markers |
| Unit | `report()` with invalid JSON returns 400 | Send malformed multipart, assert status code |
| Unit | `report()` with empty file returns 400 | Send empty file in multipart, assert status |
| Integration | `netascan serve` starts and responds | `assert_cmd` + `reqwest` test client, start server, hit endpoints |
| Integration | Graceful shutdown on SIGINT | Spawn server, send signal, assert process exits |

## Migration / Rollout

No migration required. The serve subcommand is currently a stub. This change replaces it with a working server. Rollback is reverting to the stub.

## Open Questions

- [ ] Should the upload form include a "drag and drop" zone? Nice-to-have but adds JS complexity. Defer to post-MVP.
- [ ] Should `POST /report` also accept `application/json` directly (not just multipart)? Useful for API consumers. Defer to post-MVP.
