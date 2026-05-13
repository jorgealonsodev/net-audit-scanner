## Verification Report

**Change**: security-checks
**Version**: N/A
**Mode**: Strict TDD

### Completeness
| Metric | Value |
|--------|-------|
| Tasks total | 23 |
| Tasks complete | 0 |
| Tasks incomplete | 23 |

### Build & Tests Execution
**Build**: ✅ Passed
```text
$ cargo check
Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.71s
```

**Tests**: ✅ 301 passed / ❌ 0 failed / ⚠️ 7 ignored
```text
$ cargo test
test result: ok. 301 passed; 0 failed; 7 ignored; 0 measured; 0 filtered out
```

**Coverage**: ➖ Not available

### TDD Compliance
| Check | Result | Details |
|-------|--------|---------|
| TDD Evidence reported | ✅ | Found in Engram `sdd/security-checks/apply-progress` (#3120) |
| All tasks have tests | ⚠️ | Runtime evidence exists for protocol checks, but no runtime coverage for post-scan integration |
| RED confirmed (tests exist) | ✅ | Security tests exist in `src/security/mod.rs` |
| GREEN confirmed (tests pass) | ⚠️ | Protocol/security tests pass, but integration scenarios for REQ-SEC-5 are still unverified |
| Triangulation adequate | ⚠️ | HTTP/FTP/Telnet happy+reject paths covered; credential-order behavior not covered |
| Safety Net for modified files | ⚠️ | `tasks.md` was not updated, so completion evidence is incomplete |

**TDD Compliance**: 3/6 checks passed

---

### Test Layer Distribution
| Layer | Tests | Files | Tools |
|-------|-------|-------|-------|
| Unit | 10 | 1 | cargo test |
| Integration | 6 | 1 | cargo test + Tokio TCP mocks |
| E2E | 0 | 0 | not installed |
| **Total** | **16** | **1** | |

---

### Changed File Coverage
Coverage analysis skipped — no coverage tool detected

---

### Assertion Quality
**Assertion quality**: ✅ All assertions verify real behavior

---

### Quality Metrics
**Linter**: ✅ No warnings (`cargo clippy --all-targets`)
**Type Checker**: ✅ No errors (`cargo check`)

### Spec Compliance Matrix
| Requirement | Scenario | Test | Result |
|-------------|----------|------|--------|
| REQ-SEC-1 | HTTP accepts `admin:admin` | `src/security/mod.rs > check_default_credentials_http_mock_accepts_admin` | ✅ COMPLIANT |
| REQ-SEC-1 | HTTP rejects all defaults | `src/security/mod.rs > check_default_credentials_http_mock_rejects_all` | ✅ COMPLIANT |
| REQ-SEC-1 | `enabled = false` skips checks | `src/security/mod.rs > check_default_credentials_disabled_returns_early` | ✅ COMPLIANT |
| REQ-SEC-2 | FTP accepts `admin:admin` | `src/security/mod.rs > check_default_credentials_ftp_mock_accepts` | ✅ COMPLIANT |
| REQ-SEC-2 | FTP rejects all defaults | `src/security/mod.rs > check_default_credentials_ftp_mock_rejects` | ✅ COMPLIANT |
| REQ-SEC-3 | Telnet accepts `admin:admin` | `src/security/mod.rs > check_default_credentials_telnet_mock_accepts` | ✅ COMPLIANT |
| REQ-SEC-3 | Telnet rejects all defaults | `src/security/mod.rs > check_default_credentials_telnet_mock_rejects` | ✅ COMPLIANT |
| REQ-SEC-4 | `SecurityFinding` serializes/deserializes with required fields | `src/security/mod.rs > security_finding_roundtrip` | ✅ COMPLIANT |
| REQ-SEC-5 | Post-scan step records findings on scanned hosts when enabled | (none found) | ❌ UNTESTED |
| REQ-SEC-5 | Post-scan step leaves empty findings when disabled | (none found) | ❌ UNTESTED |
| REQ-SEC-6 | Default credential order reaches `root:root` after earlier failures | (none found) | ❌ UNTESTED |

**Compliance summary**: 8/11 scenarios compliant

### Correctness (Static Evidence)
| Requirement | Status | Notes |
|------------|--------|-------|
| HTTP/FTP/Telnet credential checks | ✅ Implemented | `src/security/mod.rs` implements all three protocol checks |
| `SecurityFinding` model | ✅ Implemented | Struct matches spec/design fields and derives |
| `DiscoveredHost.security_findings` field | ✅ Implemented | Added in `src/scanner/models.rs` with `#[serde(default)]` |
| Post-scan integration | ❌ Missing | `src/cli/mod.rs` never calls `security::check_default_credentials()` |
| Config gating in runtime pipeline | ❌ Missing | `CredentialsCheckConfig` exists in `src/config/mod.rs`, but is not threaded into `Scanner`/CLI scan flow |
| Default credential order runtime proof | ⚠️ Partial | Constant order is defined, but no behavioral test proves fallback reaches later pairs |

### Coherence (Design)
| Decision | Followed? | Notes |
|----------|-----------|-------|
| Reuse CVE `Severity` in `SecurityFinding` | ✅ Yes | `pub use crate::cve::models::Severity;` |
| Implement protocol checks in `src/security/mod.rs` | ✅ Yes | HTTP/FTP/Telnet implemented there |
| Wire checks after scan/CVE enrichment | ❌ No | No runtime integration found in `src/cli/mod.rs` or `src/scanner/discovery.rs` |
| Gate execution on `CredentialsCheckConfig.enabled` in active pipeline | ❌ No | Gate exists only inside helper function, not in actual scan workflow |
| Add dedicated integration tests under `tests/` | ⚠️ Partial | No `tests/security_default_creds.rs` or `tests/security_cli_tests.rs` exists; coverage is in-module only |

### Issues Found
**CRITICAL**:
- Security checks are never executed in the real scan pipeline. `src/cli/mod.rs` runs discovery, port scan, OUI enrichment, CVE enrichment, persistence, and output, but never calls `security::check_default_credentials()`. Grep found runtime references only inside `src/security/mod.rs` tests.
- `CredentialsCheckConfig.enabled` is not wired into the active scan workflow. `src/config/mod.rs` defines it, but the CLI constructs `ScanConfig` directly and `Scanner` has no security-check configuration path.
- REQ-SEC-5 has no passing runtime covering test and is not implemented end-to-end, so the post-scan integration promised by the spec/design is currently unverified and absent.
- REQ-SEC-6 has no passing runtime covering test proving credential-attempt order reaches `root:root` after earlier failures.

**WARNING**:
- `openspec/changes/security-checks/tasks.md` still shows all 23 tasks unchecked, so the SDD completion artifact is out of sync with the code.
- The task artifact requested a dedicated integration test file under `tests/`, but verification found only in-module tests in `src/security/mod.rs`.
- The user-provided summary mentions `tests/security_cli_tests.rs`, but no such file exists in the repository.

**SUGGESTION**:
- Thread `CredentialsCheckConfig` through the real scan flow and call `security::check_default_credentials()` before persistence/output so findings actually land in `DiscoveredHost.security_findings`.
- Add an integration test that exercises the real scan pipeline (or an extracted post-scan orchestration step) to prove REQ-SEC-5 at runtime.
- Add a behavioral test where only `root:root` succeeds, proving the credential list is attempted in order.

### Verdict
FAIL
Verification failed because the protocol checks exist in isolation, but the change is not wired into the actual scan pipeline and several spec scenarios remain untested.
