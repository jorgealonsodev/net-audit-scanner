# Proposal: security-checks

## Intent

Implement the `src/security/mod.rs` stub to perform default credential testing against discovered services (HTTP, FTP, Telnet). This is a high-value security audit capability that uses **zero new dependencies** — pure TCP + existing `reqwest`. The `CredentialsCheckConfig` already exists in config but is never consumed.

## Scope

### In Scope
- `check_default_credentials()` for HTTP, FTP, Telnet using raw TCP
- `SecurityFinding` model with `check_type`, `severity`, `port`, `service`, `description`
- Wire `CredentialsCheckConfig.enabled` to gate execution
- Integrate as post-scan step after CVE enrichment
- Unit tests with wiremock (HTTP) and TcpListener (FTP/Telnet)

### Out of Scope
- SSH credential testing (requires `russh`/`ssh2` crate)
- TLS certificate verification (requires `rustls` + `x509-parser`)
- Custom credential list parsing from `custom_list` config field
- Report template updates for security findings

## Capabilities

### New Capabilities
- `security-checks`: Default credential testing, security finding model, post-scan integration

### Modified Capabilities
- None

## Approach

1. Add `SecurityFinding` struct to `src/security/mod.rs`
2. Implement `check_default_credentials(hosts, config)` — iterates open ports, attempts protocol-specific login with hardcoded defaults (admin/admin, root/root, etc.)
3. Wire into `Scanner` as a post-scan step: after `scan_ports()` and CVE enrichment, call `security::check_default_credentials()`
4. Gate execution on `CredentialsCheckConfig.enabled`
5. Return `Vec<SecurityFinding>` attached to scan results

## Affected Areas

| Area | Impact | Description |
|------|--------|-------------|
| `src/security/mod.rs` | New | Core implementation: SecurityFinding model, check_default_credentials() |
| `src/scanner/models.rs` | Modified | Add `security_findings: Vec<SecurityFinding>` to DiscoveredHost |
| `src/scanner/discovery.rs` | Modified | Wire security check as post-scan step |
| `src/error.rs` | Modified | Add `Security(String)` variant |
| `tests/` | New | Integration tests with mock servers |

## Risks

| Risk | Likelihood | Mitigation |
|------|------------|------------|
| False positives (service lies about auth) | Medium | Log findings as "suspected" not "confirmed" |
| Performance impact (login handshakes add latency) | Medium | Only check services already classified as HTTP/FTP/Telnet |
| Legal concerns (scanning creds on non-owned hosts) | Low | Tool already requires explicit scan target; config flag gates execution |

## Rollback Plan

Revert the commit — `CredentialsCheckConfig.enabled` defaults to `true` but the field is already present in config, so rollback only removes the new `security_findings` field from `DiscoveredHost` and the security module implementation. No data migration needed.

## Dependencies

- None (no new crates)

## Success Criteria

- [ ] `check_default_credentials()` detects admin/admin on mock HTTP server (wiremock)
- [ ] `check_default_credentials()` detects admin/admin on mock FTP server (TcpListener)
- [ ] `check_default_credentials()` detects admin/admin on mock Telnet server (TcpListener)
- [ ] `CredentialsCheckConfig.enabled = false` skips credential checks entirely
- [ ] `SecurityFinding` serializes/deserializes to JSON correctly
- [ ] `cargo test` passes with zero failures
- [ ] `cargo clippy` passes with zero warnings
