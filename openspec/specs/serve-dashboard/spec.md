# Serve Dashboard Specification

## Purpose

Provide a stateless web server that accepts scan JSON file uploads and renders HTML security audit reports in the browser, reusing the existing `ReportEngine`.

## Requirements

### REQ-SRV-1: Server Startup and Binding

| Field | Value |
|-------|-------|
| Statement | The system MUST start an Axum HTTP server bound to `--bind:--port` (default `127.0.0.1:7070`) when `netascan serve` is invoked. The server MUST run until receiving a SIGINT (Ctrl+C), then shut down gracefully. |
| Priority | P1 |

- **Default binding**: GIVEN no flags → WHEN `netascan serve` → THEN server listens on `127.0.0.1:7070`
- **Custom port**: GIVEN `--port 8080` → THEN server listens on `127.0.0.1:8080`
- **Custom bind**: GIVEN `--bind 0.0.0.0 --port 3000` → THEN server listens on `0.0.0.0:3000`
- **Graceful shutdown**: GIVEN server running → WHEN Ctrl+C pressed → THEN server stops accepting connections and exits cleanly

---

### REQ-SRV-2: Upload Page (GET /)

| Field | Value |
|-------|-------|
| Statement | The system MUST serve an HTML page at `GET /` containing a file upload form (`<form>` with `<input type="file">`) that POSTs to `/report` with `multipart/form-data` encoding. The HTML and CSS MUST be embedded at compile time via `include_dir!`. |
| Priority | P1 |

- **Upload form**: GIVEN `GET /` → THEN response is `text/html` with a form posting to `/report`
- **File input**: GIVEN the form → THEN it accepts `.json` files via `<input type="file" accept=".json">`
- **Embedded assets**: GIVEN build → THEN HTML/CSS are compiled into the binary, no runtime file I/O

---

### REQ-SRV-3: Report Rendering (POST /report)

| Field | Value |
|-------|-------|
| Statement | The system MUST accept `multipart/form-data` POST requests at `/report` containing a JSON file. It MUST deserialize the file content into `Vec<DiscoveredHost>`, convert to `ReportContext`, render via `ReportEngine::render_html()`, and return the resulting HTML with `Content-Type: text/html`. Invalid input MUST return HTTP 400 with a human-readable error message. |
| Priority | P1 |
| Depends on | REQ-SRV-1, REQ-SRV-2 |

- **Valid upload**: GIVEN valid scan JSON file → WHEN POSTed to `/report` → THEN rendered HTML report returned with 200
- **Invalid JSON**: GIVEN malformed JSON → WHEN POSTed → THEN 400 with error describing the parse failure
- **Empty file**: GIVEN empty file upload → WHEN POSTed → THEN 400 with "empty input" message
- **Missing file field**: GIVEN POST without file field → WHEN POSTed → THEN 400 with "no file uploaded" message
- **Wrong content type**: GIVEN `Content-Type: application/json` (not multipart) → THEN 400 or 415

---

### REQ-SRV-4: Health Check (GET /health)

| Field | Value |
|-------|-------|
| Statement | The system MUST respond to `GET /health` with HTTP 200 and a plain-text body `"ok"`. |
| Priority | P2 |

- **Health endpoint**: GIVEN `GET /health` → THEN 200 with body `"ok"`

---

### REQ-SRV-5: CLI Wiring

| Field | Value |
|-------|-------|
| Statement | The `Commands::Serve` match arm in `cli/mod.rs` MUST invoke `server::run(args).await` instead of the current stub. `ServeArgs` already provides `--port` (default 7070) and `--bind` (default "127.0.0.1"). |
| Priority | P1 |
| Depends on | REQ-SRV-1 |

- **Serve dispatch**: GIVEN `netascan serve` → THEN `server::run()` is called with parsed `ServeArgs`
- **Error propagation**: GIVEN server startup failure (e.g., port in use) → THEN error propagated to caller with descriptive message
