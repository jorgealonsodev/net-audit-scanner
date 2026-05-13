# Tasks: security-checks

## Review Workload Forecast

| Field | Value |
|-------|-------|
| Estimated changed lines | 380–450 |
| 400-line budget risk | Medium |
| Chained PRs recommended | No |
| Suggested split | Single PR |
| Delivery strategy | auto-chain |
| Chain strategy | stacked-to-main |

Decision needed before apply: No
Chained PRs recommended: No
Chain strategy: stacked-to-main
400-line budget risk: Medium

### Suggested Work Units

| Unit | Goal | Likely PR | Notes |
|------|------|-----------|-------|
| 1 | Full implementation + tests | PR 1 (to main) | All phases in one PR; TDD keeps diff reviewable |

## Phase 1: Foundation — Models and Error Types

- [x] 1.1 Add `Severity` re-export to `src/security/mod.rs` from `crate::cve::models::Severity`
- [x] 1.2 Add `SecurityFinding` struct with `check_type`, `severity`, `port`, `service`, `description`, `target_ip` fields; derive Debug, Clone, Serialize, Deserialize
- [x] 1.3 Write unit tests: `SecurityFinding` serialization roundtrip, JSON contains all fields
- [x] 1.4 Add `Security(String)` variant to `src/error.rs` with `#[error("Security check error: {0}")]`
- [x] 1.5 Add `security_findings: Vec<SecurityFinding>` field to `DiscoveredHost` in `src/scanner/models.rs` with `#[serde(default)]`
- [x] 1.6 Update `DiscoveredHost` constructor in `src/scanner/discovery.rs` to initialize `security_findings: vec![]`
- [x] 1.7 Write unit test: `DiscoveredHost` with `security_findings` roundtrips JSON

## Phase 2: Core Implementation — Credential Check Functions

- [x] 2.1 Define `DEFAULT_CREDS` constant `&[(&str, &str)]` with 6 pairs in `src/security/mod.rs`
- [x] 2.2 Implement `check_http_credentials(ip, port) -> Option<SecurityFinding>` using reqwest with Basic Auth; return finding on 2xx, timeout 3s
- [x] 2.3 Write unit test (mock server): HTTP accepting `admin:admin` → finding; HTTP returning 401 → None
- [x] 2.4 Implement `check_ftp_credentials(ip, port) -> Option<SecurityFinding>` using raw TCP; USER/PASS commands, 230 success / 530 failure
- [x] 2.5 Write unit test (TcpListener): FTP `220` banner → 331 → 230 → finding; FTP `530` → None
- [x] 2.6 Implement `check_telnet_credentials(ip, port) -> Option<SecurityFinding>` using raw TCP with prompt detection; timeout 5s
- [x] 2.7 Write unit test (TcpListener): Telnet accepting creds → finding; Telnet rejecting → None

## Phase 3: Integration — Wiring into Scanner

- [x] 3.1 Implement `pub async fn check_default_credentials(hosts: &mut [DiscoveredHost], config: &CredentialsCheckConfig) -> Result<(), Error>` — gate on `config.enabled`, iterate hosts, dispatch by service type
- [x] 3.2 Wire post-scan call in `src/cli/mod.rs`: after CVE enrichment, call `security::check_default_credentials(&mut hosts, &creds_config).await` (non-fatal, warns on error)
- [x] 3.3 Write unit test: `check_default_credentials` with `enabled = false` returns early, no findings
- [x] 3.4 Write unit test: `check_default_credentials` iterates host with HTTP port and records finding

## Phase 4: Integration Tests

- [x] 4.1 HTTP mock server tests in `src/security/mod.rs`: verify finding recorded
- [x] 4.2 FTP mock: server sends `220`, `331`, `230` → verify finding with `check_type = "default_credential"`, `severity = High`
- [x] 4.3 Telnet mock: server sends login prompt, accepts `admin:admin` → verify finding
- [x] 4.4 Run `cargo test` — 301 passed, 0 failed
- [x] 4.5 Run `cargo clippy` — zero warnings
