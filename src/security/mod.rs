//! Security checks module — default credential testing, TLS verification, protocol analysis.

use serde::{Deserialize, Serialize};
use std::net::IpAddr;

/// Re-export Severity from CVE models for consistent vulnerability reporting.
pub use crate::cve::models::Severity;

/// A security finding detected during credential or protocol checks.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityFinding {
    /// Type of check performed (e.g. "default_credential", "tls_issue").
    pub check_type: String,
    /// Severity level of the finding.
    pub severity: Severity,
    /// Target port number.
    pub port: u16,
    /// Service name (e.g. "http", "ftp", "telnet").
    pub service: String,
    /// Human-readable description of the finding.
    pub description: String,
    /// IP address of the affected host.
    pub target_ip: String,
}

/// Default credential pairs used for brute-force testing.
pub const DEFAULT_CREDS: &[(&str, &str)] = &[
    ("admin", "admin"),
    ("admin", "password"),
    ("root", "root"),
    ("root", "admin"),
    ("root", "password"),
    ("guest", "guest"),
];

/// Check default credentials against an HTTP service.
///
/// Sends GET requests with Basic Auth for each credential pair.
/// Returns a finding if any pair succeeds (2xx response).
pub async fn check_http_credentials(ip: IpAddr, port: u16) -> Option<SecurityFinding> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(3))
        .build()
        .ok()?;

    for (username, password) in DEFAULT_CREDS {
        let url = format!("http://{}:{}/", ip, port);
        let resp = client
            .get(&url)
            .basic_auth(username, Some(password))
            .send()
            .await
            .ok()?;

        if resp.status().is_success() {
            return Some(SecurityFinding {
                check_type: "default_credential".into(),
                severity: Severity::High,
                port,
                service: "http".into(),
                description: format!("Default credentials detected: {}/{}", username, password),
                target_ip: ip.to_string(),
            });
        }
    }

    None
}

/// Check default credentials against an FTP service.
///
/// Uses raw TCP with FTP protocol commands (USER/PASS).
/// Returns a finding if any pair succeeds (230 response).
pub async fn check_ftp_credentials(ip: IpAddr, port: u16) -> Option<SecurityFinding> {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::TcpStream;
    use tokio::time::timeout;

    let stream = match timeout(std::time::Duration::from_secs(3), TcpStream::connect((ip, port))).await {
        Ok(Ok(s)) => s,
        _ => {
            tracing::warn!("FTP connection timeout for {}:{}", ip, port);
            return None;
        }
    };

    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);
    let mut buf = String::new();

    // Read initial banner (expect 220)
    buf.clear();
    let n = match timeout(std::time::Duration::from_secs(3), reader.read_line(&mut buf)).await {
        Ok(Ok(n)) => n,
        _ => return None,
    };
    if n == 0 || !buf.starts_with("220") {
        return None;
    }

    for (username, password) in DEFAULT_CREDS {
        // Send USER command
        if writer
            .write_all(format!("USER {}\r\n", username).as_bytes())
            .await
            .is_err()
        {
            continue;
        }

        buf.clear();
        let n = match timeout(std::time::Duration::from_secs(3), reader.read_line(&mut buf)).await {
            Ok(Ok(n)) => n,
            _ => continue,
        };
        if n == 0 {
            continue;
        }
        // Expect 331 (password required) or 230 (no password needed)
        if !buf.starts_with("331") && !buf.starts_with("230") {
            continue;
        }
        if buf.starts_with("230") {
            return Some(SecurityFinding {
                check_type: "default_credential".into(),
                severity: Severity::High,
                port,
                service: "ftp".into(),
                description: format!("Default credentials detected: {}/{}", username, password),
                target_ip: ip.to_string(),
            });
        }

        // Send PASS command
        if writer
            .write_all(format!("PASS {}\r\n", password).as_bytes())
            .await
            .is_err()
        {
            continue;
        }

        buf.clear();
        let n = match timeout(std::time::Duration::from_secs(3), reader.read_line(&mut buf)).await {
            Ok(Ok(n)) => n,
            _ => continue,
        };
        if n == 0 {
            continue;
        }

        if buf.starts_with("230") {
            return Some(SecurityFinding {
                check_type: "default_credential".into(),
                severity: Severity::High,
                port,
                service: "ftp".into(),
                description: format!("Default credentials detected: {}/{}", username, password),
                target_ip: ip.to_string(),
            });
        }
    }

    // Send QUIT
    let _ = writer.write_all(b"QUIT\r\n").await;
    None
}

/// Check default credentials against a Telnet service.
///
/// Uses raw TCP with prompt detection heuristics.
/// Returns a finding if any pair succeeds (shell prompt detected).
pub async fn check_telnet_credentials(ip: IpAddr, port: u16) -> Option<SecurityFinding> {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::TcpStream;
    use tokio::time::timeout;

    let stream = match timeout(std::time::Duration::from_secs(5), TcpStream::connect((ip, port))).await {
        Ok(Ok(s)) => s,
        _ => {
            tracing::warn!("Telnet connection timeout for {}:{}", ip, port);
            return None;
        }
    };

    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);
    let mut buf = String::new();

    // Read initial data, detect login prompt
    buf.clear();
    let n = match timeout(std::time::Duration::from_secs(5), reader.read_line(&mut buf)).await {
        Ok(Ok(n)) => n,
        _ => return None,
    };
    if n == 0 {
        return None;
    }

    let login_keywords = ["login", "user", "name", "account"];
    let buf_lower = buf.to_lowercase();
    if !login_keywords.iter().any(|kw| buf_lower.contains(kw)) {
        // If no login prompt detected, try anyway (some servers don't send a prompt)
    }

    for (username, password) in DEFAULT_CREDS {
        // Send username
        if writer.write_all(format!("{}\r\n", username).as_bytes()).await.is_err() {
            continue;
        }

        // Wait for password prompt
        buf.clear();
        let n = match timeout(std::time::Duration::from_secs(5), reader.read_line(&mut buf)).await {
            Ok(Ok(n)) => n,
            _ => continue,
        };
        if n == 0 {
            continue;
        }

        let pass_keywords = ["password", "pass", "secret"];
        let buf_lower = buf.to_lowercase();
        if !pass_keywords.iter().any(|kw| buf_lower.contains(kw)) {
            // Might have accepted username without password prompt — continue anyway
        }

        // Send password
        if writer.write_all(format!("{}\r\n", password).as_bytes()).await.is_err() {
            continue;
        }

        // Read response — check for shell prompt indicators
        buf.clear();
        let n = match timeout(std::time::Duration::from_secs(5), reader.read_line(&mut buf)).await {
            Ok(Ok(n)) => n,
            _ => continue,
        };
        if n == 0 {
            continue;
        }

        // Check for success indicators: shell prompt markers
        let shell_indicators = ["$ ", "# ", "> "];
        if shell_indicators.iter().any(|ind| buf.contains(ind)) {
            return Some(SecurityFinding {
                check_type: "default_credential".into(),
                severity: Severity::High,
                port,
                service: "telnet".into(),
                description: format!("Default credentials detected: {}/{}", username, password),
                target_ip: ip.to_string(),
            });
        }
    }

    None
}

/// Execute credential checks as a post-scan enrichment step.
///
/// Gates on `config.enabled`, iterates hosts, and dispatches by service type.
pub async fn check_default_credentials(
    hosts: &mut [crate::scanner::models::DiscoveredHost],
    config: &crate::config::CredentialsCheckConfig,
) -> Result<(), crate::error::Error> {
    if !config.enabled {
        return Ok(());
    }

    for host in hosts.iter_mut() {
        let ip = host.ip;
        let mut findings = Vec::new();

        for open_port in &host.open_ports {
            let finding = match open_port.service {
                crate::scanner::models::ServiceType::Http => check_http_credentials(ip, open_port.port).await,
                crate::scanner::models::ServiceType::Ftp => check_ftp_credentials(ip, open_port.port).await,
                crate::scanner::models::ServiceType::Telnet => check_telnet_credentials(ip, open_port.port).await,
                _ => None,
            };

            if let Some(f) = finding {
                findings.push(f);
            }
        }

        host.security_findings.extend(findings);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn security_finding_serializes_to_json() {
        let finding = SecurityFinding {
            check_type: "default_credential".into(),
            severity: Severity::High,
            port: 80,
            service: "http".into(),
            description: "Default credentials detected: admin/admin".into(),
            target_ip: "192.168.1.1".into(),
        };
        let json = serde_json::to_string(&finding).unwrap();
        assert!(json.contains("default_credential"));
        assert!(json.contains("high"));
        assert!(json.contains("80"));
        assert!(json.contains("http"));
        assert!(json.contains("admin/admin"));
        assert!(json.contains("192.168.1.1"));
    }

    #[test]
    fn security_finding_deserializes_from_json() {
        let json = r#"{
            "check_type": "default_credential",
            "severity": "high",
            "port": 21,
            "service": "ftp",
            "description": "Default credentials detected: root/root",
            "target_ip": "10.0.0.1"
        }"#;
        let finding: SecurityFinding = serde_json::from_str(json).unwrap();
        assert_eq!(finding.check_type, "default_credential");
        assert_eq!(finding.severity, Severity::High);
        assert_eq!(finding.port, 21);
        assert_eq!(finding.service, "ftp");
        assert_eq!(finding.target_ip, "10.0.0.1");
    }

    #[test]
    fn security_finding_roundtrip() {
        let original = SecurityFinding {
            check_type: "tls_issue".into(),
            severity: Severity::Medium,
            port: 443,
            service: "https".into(),
            description: "Self-signed certificate detected".into(),
            target_ip: "172.16.0.1".into(),
        };
        let json = serde_json::to_string(&original).unwrap();
        let restored: SecurityFinding = serde_json::from_str(&json).unwrap();
        assert_eq!(original.check_type, restored.check_type);
        assert_eq!(original.severity, restored.severity);
        assert_eq!(original.port, restored.port);
        assert_eq!(original.service, restored.service);
        assert_eq!(original.description, restored.description);
        assert_eq!(original.target_ip, restored.target_ip);
    }

    #[test]
    fn security_finding_clone() {
        let finding = SecurityFinding {
            check_type: "default_credential".into(),
            severity: Severity::High,
            port: 23,
            service: "telnet".into(),
            description: "test".into(),
            target_ip: "1.2.3.4".into(),
        };
        let cloned = finding.clone();
        assert_eq!(finding.check_type, cloned.check_type);
    }

    #[test]
    fn security_finding_debug_output() {
        let finding = SecurityFinding {
            check_type: "default_credential".into(),
            severity: Severity::Critical,
            port: 80,
            service: "http".into(),
            description: "test".into(),
            target_ip: "127.0.0.1".into(),
        };
        let debug = format!("{:?}", finding);
        assert!(debug.contains("default_credential"));
        assert!(debug.contains("127.0.0.1"));
    }

    #[test]
    fn default_creds_has_six_pairs() {
        assert_eq!(DEFAULT_CREDS.len(), 6);
    }

    #[test]
    fn default_creds_first_pair_is_admin_admin() {
        assert_eq!(DEFAULT_CREDS[0], ("admin", "admin"));
    }

    #[test]
    fn default_creds_contains_root_root() {
        assert!(DEFAULT_CREDS.contains(&("root", "root")));
    }

    #[test]
    fn default_creds_contains_guest_guest() {
        assert!(DEFAULT_CREDS.contains(&("guest", "guest")));
    }

    #[tokio::test]
    async fn check_default_credentials_disabled_returns_early() {
        use crate::scanner::models::{DiscoveredHost, DiscoveryMethod, OpenPort, Protocol, ServiceType};

        let config = crate::config::CredentialsCheckConfig {
            enabled: false,
            custom_list: String::new(),
        };
        let mut hosts = vec![DiscoveredHost {
            ip: "127.0.0.1".parse().unwrap(),
            mac: None,
            hostname: None,
            method: DiscoveryMethod::Tcp,
            open_ports: vec![OpenPort {
                port: 80,
                service: ServiceType::Http,
                banner: None,
                protocol: Protocol::Tcp,
                is_insecure: true,
                cves: vec![],
            }],
            rtt_ms: None,
            vendor: None,
            device_model: None,
            os_hint: None,
            security_findings: vec![],
        }];

        check_default_credentials(&mut hosts, &config).await.unwrap();
        assert!(hosts[0].security_findings.is_empty());
    }

    #[tokio::test]
    async fn check_default_credentials_http_mock_accepts_admin() {
        use crate::scanner::models::{DiscoveredHost, DiscoveryMethod, OpenPort, Protocol, ServiceType};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        // Mock HTTP server that accepts admin:admin via Basic Auth
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        // Spawn mock server
        let server_handle = tokio::spawn(async move {
            let (mut stream, _addr) = listener.accept().await.unwrap();

            // Read request
            let mut buf = [0u8; 4096];
            let n = stream.read(&mut buf).await.unwrap();
            let request = String::from_utf8_lossy(&buf[..n]);

            // Check for Basic Auth header with admin:admin
            // admin:admin base64 = YWRtaW46YWRtaW4=
            if request.contains("YWRtaW46YWRtaW4=") {
                let response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK";
                stream.write_all(response.as_bytes()).await.unwrap();
            } else {
                let response = "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic realm=\"test\"\r\nContent-Length: 12\r\n\r\nUnauthorized";
                stream.write_all(response.as_bytes()).await.unwrap();
            }
        });

        let config = crate::config::CredentialsCheckConfig {
            enabled: true,
            custom_list: String::new(),
        };
        let mut hosts = vec![DiscoveredHost {
            ip: "127.0.0.1".parse().unwrap(),
            mac: None,
            hostname: None,
            method: DiscoveryMethod::Tcp,
            open_ports: vec![OpenPort {
                port,
                service: ServiceType::Http,
                banner: None,
                protocol: Protocol::Tcp,
                is_insecure: true,
                cves: vec![],
            }],
            rtt_ms: None,
            vendor: None,
            device_model: None,
            os_hint: None,
            security_findings: vec![],
        }];

        check_default_credentials(&mut hosts, &config).await.unwrap();
        server_handle.await.unwrap();

        assert!(!hosts[0].security_findings.is_empty());
        let finding = &hosts[0].security_findings[0];
        assert_eq!(finding.check_type, "default_credential");
        assert_eq!(finding.severity, Severity::High);
        assert_eq!(finding.service, "http");
        assert_eq!(finding.port, port);
    }

    #[tokio::test]
    async fn check_default_credentials_http_mock_rejects_all() {
        use crate::scanner::models::{DiscoveredHost, DiscoveryMethod, OpenPort, Protocol, ServiceType};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        // Mock HTTP server that rejects ALL credentials
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let server_handle = tokio::spawn(async move {
            // Accept up to 6 connections (one per credential pair)
            for _ in 0..6 {
                if let Ok((mut stream, _addr)) = listener.accept().await {
                    let mut buf = [0u8; 4096];
                    let _ = stream.read(&mut buf).await;
                    let response = "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic realm=\"test\"\r\nContent-Length: 12\r\n\r\nUnauthorized";
                    let _ = stream.write_all(response.as_bytes()).await;
                }
            }
        });

        let config = crate::config::CredentialsCheckConfig {
            enabled: true,
            custom_list: String::new(),
        };
        let mut hosts = vec![DiscoveredHost {
            ip: "127.0.0.1".parse().unwrap(),
            mac: None,
            hostname: None,
            method: DiscoveryMethod::Tcp,
            open_ports: vec![OpenPort {
                port,
                service: ServiceType::Http,
                banner: None,
                protocol: Protocol::Tcp,
                is_insecure: true,
                cves: vec![],
            }],
            rtt_ms: None,
            vendor: None,
            device_model: None,
            os_hint: None,
            security_findings: vec![],
        }];

        check_default_credentials(&mut hosts, &config).await.unwrap();
        let _ = server_handle.await;

        assert!(hosts[0].security_findings.is_empty());
    }

    #[tokio::test]
    async fn check_default_credentials_ftp_mock_accepts() {
        use crate::scanner::models::{DiscoveredHost, DiscoveryMethod, OpenPort, Protocol, ServiceType};
        use std::net::SocketAddr;
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let server_handle = tokio::spawn(async move {
            let (stream, _addr): (tokio::net::TcpStream, SocketAddr) = listener.accept().await.unwrap();
            let (reader, mut writer) = stream.into_split();
            let mut reader = BufReader::new(reader);
            let mut buf = String::new();

            // Send banner
            writer.write_all(b"220 Welcome\r\n").await.unwrap();

            // Read USER, send 331
            buf.clear();
            reader.read_line(&mut buf).await.unwrap();
            writer.write_all(b"331 Password required\r\n").await.unwrap();

            // Read PASS, send 230
            buf.clear();
            reader.read_line(&mut buf).await.unwrap();
            writer.write_all(b"230 Login successful\r\n").await.unwrap();
        });

        let config = crate::config::CredentialsCheckConfig {
            enabled: true,
            custom_list: String::new(),
        };
        let mut hosts = vec![DiscoveredHost {
            ip: "127.0.0.1".parse().unwrap(),
            mac: None,
            hostname: None,
            method: DiscoveryMethod::Tcp,
            open_ports: vec![OpenPort {
                port,
                service: ServiceType::Ftp,
                banner: None,
                protocol: Protocol::Tcp,
                is_insecure: true,
                cves: vec![],
            }],
            rtt_ms: None,
            vendor: None,
            device_model: None,
            os_hint: None,
            security_findings: vec![],
        }];

        check_default_credentials(&mut hosts, &config).await.unwrap();
        server_handle.await.unwrap();

        assert!(!hosts[0].security_findings.is_empty());
        let finding = &hosts[0].security_findings[0];
        assert_eq!(finding.check_type, "default_credential");
        assert_eq!(finding.severity, Severity::High);
        assert_eq!(finding.service, "ftp");
    }

    #[tokio::test]
    async fn check_default_credentials_ftp_mock_rejects() {
        use crate::scanner::models::{DiscoveredHost, DiscoveryMethod, OpenPort, Protocol, ServiceType};
        use std::net::SocketAddr;
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let server_handle = tokio::spawn(async move {
            let (stream, _addr): (tokio::net::TcpStream, SocketAddr) = listener.accept().await.unwrap();
            let (reader, mut writer) = stream.into_split();
            let mut reader = BufReader::new(reader);
            let mut buf = String::new();

            // Send banner
            writer.write_all(b"220 Welcome\r\n").await.unwrap();

            // Reject all credential pairs
            for _ in 0..6 {
                buf.clear();
                let _ = reader.read_line(&mut buf).await;
                writer.write_all(b"331 Password required\r\n").await.unwrap();

                buf.clear();
                let _ = reader.read_line(&mut buf).await;
                writer.write_all(b"530 Login incorrect\r\n").await.unwrap();
            }

            // Read QUIT
            buf.clear();
            let _ = reader.read_line(&mut buf).await;
        });

        let config = crate::config::CredentialsCheckConfig {
            enabled: true,
            custom_list: String::new(),
        };
        let mut hosts = vec![DiscoveredHost {
            ip: "127.0.0.1".parse().unwrap(),
            mac: None,
            hostname: None,
            method: DiscoveryMethod::Tcp,
            open_ports: vec![OpenPort {
                port,
                service: ServiceType::Ftp,
                banner: None,
                protocol: Protocol::Tcp,
                is_insecure: true,
                cves: vec![],
            }],
            rtt_ms: None,
            vendor: None,
            device_model: None,
            os_hint: None,
            security_findings: vec![],
        }];

        check_default_credentials(&mut hosts, &config).await.unwrap();
        server_handle.await.unwrap();

        assert!(hosts[0].security_findings.is_empty());
    }

    #[tokio::test]
    async fn check_default_credentials_telnet_mock_accepts() {
        use crate::scanner::models::{DiscoveredHost, DiscoveryMethod, OpenPort, Protocol, ServiceType};
        use std::net::SocketAddr;
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let server_handle = tokio::spawn(async move {
            let (stream, _addr): (tokio::net::TcpStream, SocketAddr) = listener.accept().await.unwrap();
            let (reader, mut writer) = stream.into_split();
            let mut reader = BufReader::new(reader);
            let mut buf = String::new();

            // Send login prompt
            writer.write_all(b"login: \r\n").await.unwrap();

            // Read username
            buf.clear();
            reader.read_line(&mut buf).await.unwrap();

            // Send password prompt
            writer.write_all(b"Password: \r\n").await.unwrap();

            // Read password
            buf.clear();
            reader.read_line(&mut buf).await.unwrap();

            // Send shell prompt (success indicator)
            writer.write_all(b"$ \r\n").await.unwrap();
        });

        let config = crate::config::CredentialsCheckConfig {
            enabled: true,
            custom_list: String::new(),
        };
        let mut hosts = vec![DiscoveredHost {
            ip: "127.0.0.1".parse().unwrap(),
            mac: None,
            hostname: None,
            method: DiscoveryMethod::Tcp,
            open_ports: vec![OpenPort {
                port,
                service: ServiceType::Telnet,
                banner: None,
                protocol: Protocol::Tcp,
                is_insecure: true,
                cves: vec![],
            }],
            rtt_ms: None,
            vendor: None,
            device_model: None,
            os_hint: None,
            security_findings: vec![],
        }];

        check_default_credentials(&mut hosts, &config).await.unwrap();
        server_handle.await.unwrap();

        assert!(!hosts[0].security_findings.is_empty());
        let finding = &hosts[0].security_findings[0];
        assert_eq!(finding.check_type, "default_credential");
        assert_eq!(finding.severity, Severity::High);
        assert_eq!(finding.service, "telnet");
    }

    #[tokio::test]
    async fn check_default_credentials_telnet_mock_rejects() {
        use crate::scanner::models::{DiscoveredHost, DiscoveryMethod, OpenPort, Protocol, ServiceType};
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let server_handle = tokio::spawn(async move {
            let (stream, _addr) = listener.accept().await.unwrap();
            let (reader, mut writer) = stream.into_split();
            let mut reader = BufReader::new(reader);
            let mut buf = String::new();

            // Handle all 6 credential pairs on the same connection
            for _ in 0..6 {
                // Send login prompt
                if writer.write_all(b"login: \r\n").await.is_err() {
                    break;
                }
                buf.clear();
                if reader.read_line(&mut buf).await.is_err() {
                    break;
                }

                // Send password prompt
                if writer.write_all(b"Password: \r\n").await.is_err() {
                    break;
                }
                buf.clear();
                if reader.read_line(&mut buf).await.is_err() {
                    break;
                }

                // Send rejection
                if writer.write_all(b"Login incorrect\r\n").await.is_err() {
                    break;
                }
            }
        });

        let config = crate::config::CredentialsCheckConfig {
            enabled: true,
            custom_list: String::new(),
        };
        let mut hosts = vec![DiscoveredHost {
            ip: "127.0.0.1".parse().unwrap(),
            mac: None,
            hostname: None,
            method: DiscoveryMethod::Tcp,
            open_ports: vec![OpenPort {
                port,
                service: ServiceType::Telnet,
                banner: None,
                protocol: Protocol::Tcp,
                is_insecure: true,
                cves: vec![],
            }],
            rtt_ms: None,
            vendor: None,
            device_model: None,
            os_hint: None,
            security_findings: vec![],
        }];

        check_default_credentials(&mut hosts, &config).await.unwrap();
        let _ = server_handle.await;

        assert!(hosts[0].security_findings.is_empty());
    }
}
