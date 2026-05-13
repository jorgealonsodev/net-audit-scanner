## Exploration: security-checks

### Current State

`src/security/mod.rs` is a 3-line stub with no functionality. The config module already defines `CredentialsCheckConfig { enabled: bool, custom_list: String }` but it is never consumed. The scanner already implements:

- **Port scanning** via TCP connect probes (`scanner/discovery.rs::scan_ports`)
- **Service classification** by port + banner (`scanner/services.rs::classify_service`)
- **Insecure protocol detection** (`scanner/services.rs::is_insecure`) — Telnet/FTP always flagged, HTTP flagged only if no HTTPS on same host, IoT DVR ports flagged
- **Banner grabbing** (`scanner/services.rs::grab_banner`) — reads first 256 bytes from TCP stream

The `OpenPort` model already has `is_insecure: bool` and `cves: Vec<CveMatch>` fields. The report view model surfaces `insecure_ports` counts.

### Affected Areas

- `src/security/mod.rs` — empty stub, primary implementation target
- `src/config/mod.rs` — `CredentialsCheckConfig` exists but unused; `custom_list` is `String` (likely CSV)
- `src/scanner/discovery.rs` — `scan_ports()` is where security checks would integrate after port enumeration
- `src/scanner/models.rs` — `OpenPort` may need new fields (e.g., `default_credential_found: bool`, `tls_issues: Vec<String>`)
- `src/error.rs` — may need `Security(String)` variant
- `Cargo.toml` — may need TLS inspection deps

### Approaches

#### 1. Insecure Protocol Detection (ALREADY DONE)

The `is_insecure()` function in `services.rs` already handles this. No new code needed. The security module could re-export or wrap it for a unified API.

- **Pros**: Zero effort, already tested
- **Cons**: None
- **Effort**: None (already implemented)

#### 2. Default Credential Testing

Connect to open ports (HTTP, Telnet, FTP, SSH) and attempt common default credentials (admin/admin, root/root, etc.). Parse responses to detect successful login.

**Implementation**: Raw TCP connections, protocol-specific login sequences:
- **HTTP**: Send `GET /` with `Authorization: Basic <base64(admin:admin)>`, check for 200 vs 401
- **Telnet**: Connect, wait for login prompt, send username, wait for password prompt, send password, check for shell prompt
- **FTP**: Connect, send `USER admin`, send `PASS admin`, check for `230 Login successful` vs `530`
- **SSH**: More complex — requires SSH protocol handshake. Would need `ssh2` or `russh` crate.

**No new deps for HTTP/Telnet/FTP** (raw TCP + `reqwest` already available). SSH would need a new dependency.

- **Pros**: High security value, uses existing TCP infrastructure, no deps for 3/4 protocols
- **Cons**: SSH requires new dep; credential testing is slow (adds latency per port); false positives possible
- **Effort**: Medium (HTTP+FTP+Telnet ~100 lines; SSH adds complexity)

#### 3. TLS Certificate Verification

Connect to port 443 (or any HTTPS port), retrieve the TLS certificate, and check for:
- Expired certificates
- Self-signed certificates
- Weak cipher suites
- Missing SAN entries

**Current deps**: `reqwest` with `rustls-tls` is already in `Cargo.toml`, but rustls is an internal dep of reqwest — not directly usable for certificate inspection.

**Options**:
- **A. Add `rustls` + `x509-parser` as direct deps**: Full control, can parse cert details (issuer, expiry, SAN, key size). Adds ~10-15 transitive deps.
- **B. Add `native-tls`**: Simpler API, uses OS trust store. Less detailed cert info.
- **C. Use `reqwest` to make an HTTPS request and inspect the response**: Limited — reqwest doesn't expose raw cert details.

**Recommendation**: Option A (`rustls` + `x509-parser`). The project already uses rustls-tls via reqwest, so adding it directly is consistent. `x509-parser` gives access to validity dates, subject, issuer, extensions.

- **Pros**: High security value, detects misconfigured TLS
- **Cons**: New deps required; TLS handshake is slower than TCP connect; adds complexity
- **Effort**: Medium-High (200-300 lines + 2 new deps)

### Recommendation

**MVP scope: Credential testing for HTTP + FTP + Telnet only.** Defer SSH and TLS to a follow-up PR.

**Rationale**:
1. Credential testing for HTTP/FTP/Telnet uses **zero new dependencies** — pure TCP + existing `reqwest`
2. `CredentialsCheckConfig` already exists in config — the intent is clear
3. TLS verification adds 2 new crates and significant complexity for an MVP
4. SSH credential testing requires an SSH protocol library (non-trivial)
5. Insecure protocol detection is **already done**

**One-PR scope**:
- Implement `check_default_credentials()` for HTTP, FTP, Telnet
- Add `SecurityFinding` model (type, severity, description, port)
- Integrate into `Scanner::scan_ports()` or as a post-scan step
- Wire up `CredentialsCheckConfig.enabled` flag
- Add tests with mock servers (wiremock for HTTP, TcpListener for FTP/Telnet)

**Deferred to next PR**:
- SSH credential testing (needs `russh` or `ssh2`)
- TLS certificate verification (needs `rustls` + `x509-parser`)
- Custom credential list parsing from config

### Risks

- **False positives**: A service responding positively to `admin/admin` doesn't mean it's actually vulnerable — the banner might lie or the service might be a honeypot
- **Performance**: Credential checks add 1-3 seconds per target service (login handshake + timeout). With 512 concurrency this could still be significant
- **Legal/ethical**: Scanning credentials against hosts you don't own could be problematic. The tool should have a clear warning or require explicit opt-in
- **Protocol fragility**: Telnet/FTP login sequences vary by implementation. Banner-based prompt detection is heuristic, not deterministic

### Ready for Proposal

**Yes.** The exploration identifies a clear MVP scope (credential testing for HTTP/FTP/Telnet) that fits in one PR with zero new dependencies. The orchestrator should tell the user:

> Security module MVP can deliver default credential testing for HTTP, FTP, and Telnet in a single PR with no new dependencies. TLS verification and SSH testing are deferred — they require additional crates. Insecure protocol detection is already implemented. Ready to propose the change.
