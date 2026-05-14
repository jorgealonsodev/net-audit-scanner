//! Banner grabbing and service classification.
//!
//! Implements TCP banner grabbing, service detection by port + banner,
//! and insecure protocol flagging.

use std::io::Read;
use std::net::TcpStream;
use std::time::Duration;

use crate::scanner::models::{Protocol, ServiceType};

/// Grab a banner from a TCP stream.
///
/// Reads up to 256 bytes with the given timeout. Returns the first line
/// (up to newline) or the full buffer if no newline is found.
pub fn grab_banner(stream: &mut TcpStream, timeout: Duration) -> Option<String> {
    stream.set_read_timeout(Some(timeout)).ok()?;

    let mut buffer = [0u8; 256];
    let bytes_read = match stream.read(&mut buffer) {
        Ok(n) if n > 0 => n,
        _ => return None,
    };

    let data = &buffer[..bytes_read];
    // Try to parse as UTF-8, return None if binary garbage
    let text = String::from_utf8(data.to_vec()).ok()?;

    // Return first line (strip trailing whitespace/newlines)
    let line = text.lines().next()?;
    let trimmed = line.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

/// Classify the service running on a port, optionally refined by banner.
///
/// Uses port-first classification, then banner-based refinement.
pub fn classify_service(port: u16, banner: Option<&str>) -> ServiceType {
    // Port-first classification
    let base = match port {
        80 | 8080 | 8008 | 8888 | 8000 => ServiceType::Http,
        443 | 8443 | 4443 => ServiceType::Https,
        22 => ServiceType::Ssh,
        23 | 2323 => ServiceType::Telnet,
        21 | 20 => ServiceType::Ftp,
        554 => ServiceType::Rtsp,
        1883 | 8883 => ServiceType::Mqtt,
        1900 => ServiceType::Upnp,
        25 | 587 | 465 => ServiceType::Smtp,
        53 => ServiceType::Dns,
        _ => ServiceType::Unknown,
    };

    // Banner-based refinement
    if let Some(b) = banner {
        let lower = b.to_lowercase();
        if lower.contains("ssh") {
            return ServiceType::Ssh;
        }
        if lower.contains("http") && !lower.contains("https") {
            // Could be HTTP server banner
            if base == ServiceType::Unknown {
                return ServiceType::Http;
            }
        }
        if lower.contains("ftp") {
            return ServiceType::Ftp;
        }
        if lower.contains("smtp") || lower.contains("mail") || lower.contains("postfix") || lower.contains("exim") {
            return ServiceType::Smtp;
        }
        if lower.contains("telnet") {
            return ServiceType::Telnet;
        }
        if lower.contains("mqtt") {
            return ServiceType::Mqtt;
        }
        if lower.contains("rtsp") {
            return ServiceType::Rtsp;
        }
        if lower.contains("upnp") || lower.contains("ssdp") {
            return ServiceType::Upnp;
        }
        // Banner says HTTPS but port isn't 443
        if lower.contains("https") && base != ServiceType::Https {
            return ServiceType::Https;
        }
    }

    base
}

/// Determine if a service is insecure.
///
/// Rules:
/// - Telnet and FTP are ALWAYS insecure
/// - HTTP is insecure ONLY if the host does NOT also have HTTPS (port 443) open
/// - IoT DVR ports (37777 Dahua, 34567 HiSilicon) are ALWAYS insecure
/// - All other services are considered secure by default
pub fn is_insecure(service: &ServiceType, port: u16, host_has_https: bool) -> bool {
    // Port-based insecure detection (catches Unknown service on insecure ports)
    match port {
        37777 | 34567 | 23 | 21 => return true, // Dahua DVR, HiSilicon DVR, Telnet, FTP
        _ => {}
    }

    match service {
        ServiceType::Telnet | ServiceType::Ftp => true,
        ServiceType::Http => !host_has_https,
        _ => false,
    }
}

/// Build an OpenPort from a port number, optional banner, and host HTTPS status.
pub fn build_open_port(port: u16, banner: Option<&str>, host_has_https: bool) -> crate::scanner::models::OpenPort {
    let service = classify_service(port, banner);
    let insecure = is_insecure(&service, port, host_has_https);
    crate::scanner::models::OpenPort {
        port,
        service,
        banner: banner.map(String::from),
        protocol: Protocol::Tcp,
        is_insecure: insecure,
        cves: vec![],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::net::TcpListener;
    use std::thread;

    // ─── Banner grabbing tests ───

    #[test]
    fn grab_banner_reads_first_line() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();

        // Server sends a banner
        let server_thread = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream.write_all(b"SSH-2.0-OpenSSH_8.9\r\n").unwrap();
        });

        let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
        let banner = grab_banner(&mut stream, Duration::from_secs(2));
        server_thread.join().unwrap();

        assert_eq!(banner.unwrap(), "SSH-2.0-OpenSSH_8.9");
    }

    #[test]
    fn grab_banner_handles_no_newline() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();

        let server_thread = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream.write_all(b"Hello World").unwrap();
        });

        let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
        let banner = grab_banner(&mut stream, Duration::from_secs(2));
        server_thread.join().unwrap();

        assert_eq!(banner.unwrap(), "Hello World");
    }

    #[test]
    fn grab_banner_returns_none_on_empty() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();

        let server_thread = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream.write_all(b"\r\n").unwrap();
        });

        let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
        let banner = grab_banner(&mut stream, Duration::from_secs(2));
        server_thread.join().unwrap();

        assert!(banner.is_none());
    }

    #[test]
    fn grab_banner_truncates_to_256_bytes() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();

        let long_banner = format!("{}-end", "A".repeat(300));
        let server_thread = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream.write_all(long_banner.as_bytes()).unwrap();
        });

        let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
        let banner = grab_banner(&mut stream, Duration::from_secs(2));
        server_thread.join().unwrap();

        let b = banner.unwrap();
        assert!(b.len() <= 256);
    }

    #[test]
    fn grab_banner_returns_none_on_binary_data() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();

        let server_thread = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream.write_all(&[0xFF, 0xFE, 0x00, 0x01]).unwrap();
        });

        let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
        let banner = grab_banner(&mut stream, Duration::from_secs(2));
        server_thread.join().unwrap();

        assert!(banner.is_none());
    }

    // ─── Service classification tests ───

    #[test]
    fn classify_by_port_ssh() {
        assert_eq!(classify_service(22, None), ServiceType::Ssh);
    }

    #[test]
    fn classify_by_port_http() {
        assert_eq!(classify_service(80, None), ServiceType::Http);
    }

    #[test]
    fn classify_by_port_https() {
        assert_eq!(classify_service(443, None), ServiceType::Https);
    }

    #[test]
    fn classify_by_port_telnet() {
        assert_eq!(classify_service(23, None), ServiceType::Telnet);
    }

    #[test]
    fn classify_by_port_ftp() {
        assert_eq!(classify_service(21, None), ServiceType::Ftp);
        assert_eq!(classify_service(20, None), ServiceType::Ftp);
    }

    #[test]
    fn classify_by_port_mqtt() {
        assert_eq!(classify_service(1883, None), ServiceType::Mqtt);
        assert_eq!(classify_service(8883, None), ServiceType::Mqtt);
    }

    #[test]
    fn classify_by_port_upnp() {
        assert_eq!(classify_service(1900, None), ServiceType::Upnp);
    }

    #[test]
    fn classify_by_port_smtp() {
        assert_eq!(classify_service(25, None), ServiceType::Smtp);
        assert_eq!(classify_service(587, None), ServiceType::Smtp);
        assert_eq!(classify_service(465, None), ServiceType::Smtp);
    }

    #[test]
    fn classify_by_port_dns() {
        assert_eq!(classify_service(53, None), ServiceType::Dns);
    }

    #[test]
    fn classify_by_port_rtsp() {
        assert_eq!(classify_service(554, None), ServiceType::Rtsp);
    }

    #[test]
    fn classify_by_port_unknown() {
        assert_eq!(classify_service(9999, None), ServiceType::Unknown);
    }

    #[test]
    fn classify_refined_by_banner_ssh() {
        assert_eq!(classify_service(2222, Some("SSH-2.0-OpenSSH")), ServiceType::Ssh);
    }

    #[test]
    fn classify_refined_by_banner_ftp() {
        assert_eq!(classify_service(2121, Some("220 FTP server ready")), ServiceType::Ftp);
    }

    #[test]
    fn classify_refined_by_banner_smtp() {
        assert_eq!(classify_service(2525, Some("220 smtp.example.com")), ServiceType::Smtp);
    }

    #[test]
    fn classify_refined_by_banner_telnet() {
        assert_eq!(classify_service(2323, Some("Telnet login:")), ServiceType::Telnet);
    }

    #[test]
    fn classify_refined_by_banner_mqtt() {
        assert_eq!(classify_service(1884, Some("MQTT broker")), ServiceType::Mqtt);
    }

    // ─── Insecure flagging tests ───

    #[test]
    fn telnet_always_insecure() {
        assert!(is_insecure(&ServiceType::Telnet, 23, false));
        assert!(is_insecure(&ServiceType::Telnet, 23, true));
    }

    #[test]
    fn ftp_always_insecure() {
        assert!(is_insecure(&ServiceType::Ftp, 21, false));
        assert!(is_insecure(&ServiceType::Ftp, 21, true));
    }

    #[test]
    fn http_insecure_without_https() {
        assert!(is_insecure(&ServiceType::Http, 80, false));
    }

    #[test]
    fn http_secure_with_https() {
        assert!(!is_insecure(&ServiceType::Http, 80, true));
    }

    #[test]
    fn https_never_insecure() {
        assert!(!is_insecure(&ServiceType::Https, 443, false));
    }

    #[test]
    fn ssh_never_insecure() {
        assert!(!is_insecure(&ServiceType::Ssh, 22, false));
    }

    #[test]
    fn unknown_never_insecure() {
        assert!(!is_insecure(&ServiceType::Unknown, 9999, false));
    }

    #[test]
    fn dahua_dvr_port_insecure() {
        // Port 37777 is insecure even with Unknown service
        assert!(is_insecure(&ServiceType::Unknown, 37777, false));
        assert!(is_insecure(&ServiceType::Unknown, 37777, true));
    }

    #[test]
    fn hisilicon_dvr_port_insecure() {
        // Port 34567 is insecure even with Unknown service
        assert!(is_insecure(&ServiceType::Unknown, 34567, false));
        assert!(is_insecure(&ServiceType::Unknown, 34567, true));
    }

    #[test]
    fn telnet_port_insecure_even_with_unknown_service() {
        // Port 23 is insecure even if service classification fails
        assert!(is_insecure(&ServiceType::Unknown, 23, false));
        assert!(is_insecure(&ServiceType::Unknown, 23, true));
    }

    #[test]
    fn ftp_port_insecure_even_with_unknown_service() {
        // Port 21 is insecure even if service classification fails
        assert!(is_insecure(&ServiceType::Unknown, 21, false));
        assert!(is_insecure(&ServiceType::Unknown, 21, true));
    }

    // ─── build_open_port tests ───

    #[test]
    fn build_open_port_http_insecure() {
        let port = build_open_port(80, None, false);
        assert_eq!(port.port, 80);
        assert_eq!(port.service, ServiceType::Http);
        assert!(port.is_insecure);
        assert_eq!(port.protocol, Protocol::Tcp);
    }

    #[test]
    fn build_open_port_http_secure_when_https_present() {
        let port = build_open_port(80, None, true);
        assert!(!port.is_insecure);
    }

    #[test]
    fn build_open_port_telnet_always_insecure() {
        let port = build_open_port(23, None, true);
        assert!(port.is_insecure);
    }

    #[test]
    fn build_open_port_stores_banner() {
        let port = build_open_port(22, Some("SSH-2.0-OpenSSH_8.9"), false);
        assert_eq!(port.banner.as_deref(), Some("SSH-2.0-OpenSSH_8.9"));
        assert_eq!(port.service, ServiceType::Ssh);
    }

    #[test]
    fn build_open_port_dahua_dvr_insecure() {
        let port = build_open_port(37777, None, true);
        assert!(port.is_insecure);
    }

    #[test]
    fn build_open_port_hisilicon_dvr_insecure() {
        let port = build_open_port(34567, None, true);
        assert!(port.is_insecure);
    }
}
