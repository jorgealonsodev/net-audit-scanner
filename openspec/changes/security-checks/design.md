# Design: security-checks

## Architecture Overview

The security checks module sits between port scanning and report generation. It operates as a post-scan enrichment step that adds `SecurityFinding` records to `DiscoveredHost` instances.

```
Network Discovery → Port Scanning → CVE Enrichment → Security Checks → Report Generation
                                                              ↑
                                                    check_default_credentials()
                                                    ↓
                                              SecurityFinding[]
```

## Data Models

### SecurityFinding

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityFinding {
    pub check_type: String,       // "default_credential", "tls_issue", etc.
    pub severity: Severity,       // Reuses cve::models::Severity
    pub port: u16,
    pub service: String,          // "http", "ftp", "telnet"
    pub description: String,      // "Default credentials detected: admin/admin"
    pub target_ip: String,        // IP of the affected host
}
```

The `Severity` enum is reused from `cve::models` to maintain consistency across vulnerability reporting.

### DiscoveredHost Extension

Add `security_findings: Vec<SecurityFinding>` to `DiscoveredHost` in `src/scanner/models.rs`:

```rust
pub struct DiscoveredHost {
    // ... existing fields ...
    #[serde(default)]
    pub security_findings: Vec<SecurityFinding>,
}
```

The `#[serde(default)]` ensures backward compatibility with existing serialized data.

## Core Implementation

### check_default_credentials()

```rust
pub async fn check_default_credentials(
    hosts: &mut [DiscoveredHost],
    config: &CredentialsCheckConfig,
) -> Result<(), Error>
```

**Algorithm:**
1. If `config.enabled` is false, return early (no-op)
2. For each host, iterate `open_ports`
3. Match on service type:
   - `Http` → call `check_http_credentials(ip, port)`
   - `Ftp` → call `check_ftp_credentials(ip, port)`
   - `Telnet` → call `check_telnet_credentials(ip, port)`
4. Collect findings into `host.security_findings`

**Default credential list (hardcoded):**
```rust
const DEFAULT_CREDS: &[(&str, &str)] = &[
    ("admin", "admin"),
    ("admin", "password"),
    ("root", "root"),
    ("root", "admin"),
    ("root", "password"),
    ("guest", "guest"),
];
```

### HTTP Credential Check

Uses `reqwest` with Basic Auth:

```rust
async fn check_http_credentials(ip: IpAddr, port: u16) -> Option<SecurityFinding>
```

1. Build URL: `http://{ip}:{port}/`
2. For each credential pair, send `GET /` with `Authorization: Basic <base64(user:pass)>`
3. If response status is 2xx → return `SecurityFinding` (severity: High)
4. If all credentials return 401/403 → return `None`
5. Timeout: 3 seconds per credential pair

### FTP Credential Check

Uses raw TCP with protocol-specific commands:

```rust
async fn check_ftp_credentials(ip: IpAddr, port: u16) -> Option<SecurityFinding>
```

1. Connect via `TcpStream::connect((ip, port))`
2. Read initial banner (expect `220` welcome)
3. For each credential pair:
   - Send `USER {username}\r\n`
   - Read response (expect `331` password required)
   - Send `PASS {password}\r\n`
   - Read response: `230` = success, `530` = failure
4. On success → return `SecurityFinding` (severity: High)
5. On failure after all pairs → `QUIT\r\n` and return `None`
6. Timeout: 3 seconds per command

### Telnet Credential Check

Uses raw TCP with prompt detection:

```rust
async fn check_telnet_credentials(ip: IpAddr, port: u16) -> Option<SecurityFinding>
```

1. Connect via `TcpStream::connect((ip, port))`
2. Read initial data, detect login prompt (heuristic: contains "login", "user", "name")
3. For each credential pair:
   - Send `{username}\r\n`
   - Read response, detect password prompt (heuristic: contains "password", "pass", "secret")
   - Send `{password}\r\n`
   - Read response: if contains shell prompt indicators (`$`, `#`, `>`, `login:`) → success
   - If connection closed or error → failure
4. On success → return `SecurityFinding` (severity: High)
5. Timeout: 5 seconds per credential pair (Telnet is slower)

## Integration Point

Wire into `Scanner` in `src/scanner/discovery.rs`:

```rust
// After scan_ports() completes:
if config.credentials_check.enabled {
    let mut hosts_with_findings = hosts;
    security::check_default_credentials(&mut hosts_with_findings, &config.credentials_check).await?;
}
```

This requires passing `CredentialsCheckConfig` to the Scanner or making it available via the scan context.

## Error Handling

Add `Security(String)` variant to `Error` enum:

```rust
#[error("Security check error: {0}")]
Security(String),
```

Individual credential checks return `Option<SecurityFinding>` — errors within a check (timeout, connection refused) are logged via `tracing::warn!` and treated as "no finding" rather than failing the entire scan.

## Testing Strategy

### Unit Tests (in-module)
- `SecurityFinding` serialization/deserialization roundtrip
- Default credential list iteration order
- Config enabled/disabled gating

### Integration Tests (tests/ directory)
- **HTTP**: wiremock server with Basic Auth enabled → verify finding detected
- **HTTP**: wiremock server returning 401 → verify no finding
- **FTP**: TcpListener sending `220`, `331`, `230` → verify finding detected
- **FTP**: TcpListener sending `220`, `331`, `530` → verify no finding
- **Telnet**: TcpListener with login/password prompts → verify finding detected
- **Telnet**: TcpListener rejecting credentials → verify no finding

### Mock Server Patterns
```rust
// FTP mock: sends expected protocol responses
let listener = TcpListener::bind("127.0.0.1:0").unwrap();
let port = listener.local_addr().unwrap().port();
thread::spawn(move || {
    let (mut stream, _) = listener.accept().unwrap();
    stream.write_all(b"220 Welcome\r\n").unwrap();
    // Read USER, send 331
    // Read PASS, send 230 or 530
});
```

## Performance Considerations

- **Concurrency**: Use `tokio::spawn` per host to check credentials in parallel
- **Timeouts**: Aggressive timeouts prevent slow services from blocking the scan
- **Service filtering**: Only check ports classified as Http/Ftp/Telnet — skip unknown services
- **Credential limit**: 6 pairs × 3 services = max 18 connection attempts per host

## Security Considerations

- Findings are marked as "suspected" not "confirmed" — false positives are possible
- No credentials are stored or logged — only the fact that a default pair worked
- The `enabled` flag provides explicit opt-in for credential testing
