## Verification Report

**Change**: serve-dashboard
**Version**: N/A (delta spec)
**Mode**: Strict TDD

### Completeness
| Metric | Value |
|--------|-------|
| Tasks total | 20 |
| Tasks complete | 20 |
| Tasks incomplete | 0 |

### Build & Tests Execution
**Build**: ✅ Passed
```text
$ cargo build
   Compiling multer v3.1.0
   Compiling axum v0.7.9
   Compiling netascan v0.1.0
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 5.43s
```

**Tests**: ✅ 235 passed / ❌ 0 failed / ⚠️ 0 skipped
```text
$ cargo test --lib
test result: ok. 235 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 14.02s
```

Server-specific test count: ✅ 10 passed (out of 10 server tests)

**Coverage**: ➖ Not available (no coverage tool configured for Rust/cargo-tarpaulin)

### Spec Compliance Matrix
| Requirement | Scenario | Test | Result |
|-------------|----------|------|--------|
| REQ-SRV-1 | Default binding (127.0.0.1:7070) | `parse_serve_subcommand` (CLI test) + handler tests via router | ⚠️ PARTIAL |
| REQ-SRV-1 | Custom port (--port 8080) | `parse_serve_subcommand` + ServeArgs defaults verified | ⚠️ PARTIAL |
| REQ-SRV-1 | Custom bind (--bind 0.0.0.0 --port 3000) | ServeArgs supports `bind` field | ⚠️ PARTIAL |
| REQ-SRV-1 | Graceful shutdown (Ctrl+C) | Design: `shutdown_signal()` with `ctrl_c()` | ⚠️ PARTIAL |
| REQ-SRV-2 | Upload form (GET / → form to /report) | `index_returns_html_with_form` | ✅ COMPLIANT |
| REQ-SRV-2 | File input accepts .json | `index_accepts_json_files` | ✅ COMPLIANT |
| REQ-SRV-2 | Embedded assets (compile-time) | `STATIC_DIR` uses `include_dir!` | ✅ COMPLIANT |
| REQ-SRV-3 | Valid upload → 200 + HTML | `report_valid_json_returns_html` | ✅ COMPLIANT |
| REQ-SRV-3 | Invalid JSON → 400 + error message | `report_malformed_json_returns_400` | ⚠️ PARTIAL |
| REQ-SRV-3 | Empty file → 400 + "empty input" | `report_empty_file_returns_400` | ⚠️ PARTIAL |
| REQ-SRV-3 | Missing file field → 400 + "no file uploaded" | `report_missing_file_field_returns_400` | ⚠️ PARTIAL |
| REQ-SRV-3 | Wrong content type → 400 or 415 | (none found) | ❌ UNTESTED |
| REQ-SRV-4 | Health endpoint → 200 + "ok" | `health_returns_ok` | ✅ COMPLIANT |
| REQ-SRV-5 | Serve dispatch (cli → server::run) | `parse_serve_subcommand` + static wiring | ✅ COMPLIANT |
| REQ-SRV-5 | Error propagation (port in use → caller) | `run()` maps bind errors to `Error::Network` | ⚠️ PARTIAL |

**Compliance summary**: 6/15 scenarios fully COMPLIANT, 8 PARTIAL, 1 UNTESTED

### Correctness (Static Evidence)
| Requirement | Status | Notes |
|------------|--------|-------|
| REQ-SRV-1: Server startup/binding | ✅ Implemented | `run()` parses addr, binds TCP listener, graceful shutdown via `with_graceful_shutdown(ctrl_c)`. Not integration-tested. |
| REQ-SRV-2: Upload page | ✅ Implemented | `index()` returns HTML from embedded `include_dir!`. Form posts to /report, input accept=".json". |
| REQ-SRV-3: Report rendering | ✅ Implemented | Multipart parsing, `serde_json::from_slice`, `ReportContext::from`, `spawn_blocking { render_html() }`. Error messages missing. |
| REQ-SRV-4: Health check | ✅ Implemented | Returns 200 with body "ok". |
| REQ-SRV-5: CLI wiring | ✅ Implemented | `Commands::Serve(args)` dispatches to `server::run(args).await?`. Error propagation via `?`. |

### Coherence (Design)
| Decision | Followed? | Notes |
|----------|-----------|-------|
| Multipart vs raw JSON POST | ✅ Yes | `axum::extract::Multipart` used with `multipart` feature |
| Static asset embedding via `include_dir!` | ✅ Yes | `include_dir!("$CARGO_MANIFEST_DIR/src/server/static")` |
| Stateless server (no shared state) | ✅ Yes | Router created without `.with_state()`, handlers are free functions |
| Blocking Tera rendering via `spawn_blocking` | ✅ Yes | `tokio::task::spawn_blocking(move || engine.render_html(&ctx))` at line 103 |
| Route contracts match design signatures | ✅ Yes | `run()`, `index()`, `report()`, `health()` signatures all match |
| Static assets: no JS, self-contained CSS | ✅ Yes | `index.html` has inline `<style>`, no `<script>` tags |
| Axum `multipart` feature in Cargo.toml | ✅ Yes | `axum = { version = "0.7", features = ["multipart"] }` |

### TDD Compliance
| Check | Result | Details |
|-------|--------|---------|
| TDD Evidence reported | ✅ Yes | Found in apply-progress artifact #3096 |
| All tasks have tests | ✅ Yes | 17/20 tasks are code/test tasks (3 are config/asset tasks: 1.1, 1.2 skel, 3.1) |
| RED confirmed (tests exist) | ✅ 10/10 | All 10 test functions verified in `src/server/mod.rs` lines 140-346 |
| GREEN confirmed (tests pass) | ✅ 10/10 | `cargo test server::` → 10 passed, 0 failed |
| Triangulation adequate | ✅ | 2 cases (index), 1 case (health, spec has 1 scenario), 4 cases (report), 3 cases (into_status_code) |
| Safety Net for modified files | ⚠️ | `src/cli/mod.rs` was modified (added `pub mod serve`, wired Commands::Serve). Safety net reported "Existing" but no dedicated serve CLI integration test was added for error propagation |

**TDD Compliance**: 5/6 checks passed

---

### Test Layer Distribution
| Layer | Tests | Files | Tools |
|-------|-------|-------|-------|
| Unit | 10 | `src/server/mod.rs` | `cargo test`, `tower::ServiceExt` |
| Integration | 0 | — | — |
| E2E | 0 | — | — |
| **Total** | **10** | **1** | |

---

### Changed File Coverage
Coverage analysis skipped — no Rust coverage tool detected (`cargo-tarpaulin` not in Cargo.toml or path).

---

### Assertion Quality
| File | Line | Assertion | Issue | Severity |
|------|------|-----------|-------|----------|
| `src/server/mod.rs` | 179 | `html.contains("accept=\".json\"")` | Implementation-detail assertion (HTML attribute) — borderline; spec explicitly requires `.json` accept attribute | SUGGESTION |
| `src/server/mod.rs` | 276, 295, 325 | `assert_eq!(response.status(), StatusCode::BAD_REQUEST)` | Status-only assertions. Spec requires human-readable error message body on 400 responses. Tests don't validate the error message. | WARNING |
| `src/server/mod.rs` | 113 | `#[expect(dead_code)]` on `into_status_code` | Unfulfilled lint expectation — function IS used in tests, making `dead_code` lint not fire. Clippy emits `unfulfilled_lint_expectations` warning. | WARNING |

**Assertion quality**: 0 CRITICAL, 2 WARNING, 1 SUGGESTION

---

### Quality Metrics
**Linter**: ⚠️ 1 warning in changed code
```text
warning: this lint expectation is unfulfilled
   --> src/server/mod.rs:113:10
    |
113 | #[expect(dead_code)]
    |          ^^^^^^^^^
```
Plus 2 pre-existing warnings in `src/scanner/oui.rs` (not from this change).

**Type Checker**: ✅ No errors (`cargo check` passes via `cargo build` success).

---

### Issues Found
**CRITICAL**: None

**WARNING**:
1. **Clippy unfulfilled lint expectation**: `#[expect(dead_code)]` on `into_status_code` at `src/server/mod.rs:113`. Function is used in tests within same module; the `dead_code` lint no longer fires, making the expectation invalid. Remove the attribute.
2. **REQ-SRV-3 error messages missing**: Spec requires "human-readable error message" body on 400 responses (e.g., "empty input", "no file uploaded"). Implementation returns bare `StatusCode::BAD_REQUEST` with no body. Design chose `Result<Html<String>, StatusCode>` as return type, which precludes body text on error. Design-spec gap.
3. **REQ-SRV-3 "Wrong content type" UNTESTED**: Spec scenario "GIVEN Content-Type: application/json (not multipart) → THEN 400 or 415" has no covering test.
4. **REQ-SRV-1 integration untested**: Server startup, port binding, and graceful shutdown are not covered by automated integration tests. `run()` function is only exercised indirectly through Tower's `oneshot()` on the router, not through a real TCP socket.
5. **REQ-SRV-5 error propagation untested**: No test verifies that port-in-use errors propagate from `run()` through `Commands::Serve` to the caller.

**SUGGESTION**:
1. Add integration tests using `assert_cmd` + `reqwest` to test server startup, health endpoint via real HTTP, and graceful shutdown.
2. Add body-text assertions to report error tests to match spec requirement for human-readable error messages.
3. Add a test case for wrong Content-Type (application/json) to the report handler.
4. Remove or replace `#[expect(dead_code)]` on `into_status_code` — `#[allow(dead_code)]` or extract to a module where it's genuinely needed.

### Verdict
**PASS WITH WARNINGS**

All 235 tests pass (10 server tests), build succeeds, design decisions are correctly implemented, and all 20 tasks are completed. Five warnings exist: clippy lint in new code, REQ-SRV-3 error message body missing (design-spec gap), one untested spec scenario, and no integration tests for server startup/shutdown. No critical blockers.
