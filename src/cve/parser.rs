use crate::scanner::models::ServiceType;
use regex::Regex;

/// Extract (product, version) from a service banner.
///
/// Returns `None` if the banner is empty or no recognized pattern matches.
pub fn extract_version(banner: &str, service: ServiceType) -> Option<(String, String)> {
    if banner.is_empty() {
        return None;
    }

    match service {
        ServiceType::Ssh => extract_ssh(banner),
        ServiceType::Http | ServiceType::Https => extract_http(banner),
        ServiceType::Ftp => extract_ftp(banner),
        ServiceType::Smtp => extract_smtp(banner),
        _ => extract_generic(banner),
    }
}

fn extract_ssh(banner: &str) -> Option<(String, String)> {
    let re = Regex::new(r"SSH-\d+\.\d+-([A-Za-z0-9]+)[/_]([\d\.]+)").ok()?;
    let caps = re.captures(banner)?;
    let product = caps.get(1)?.as_str().to_lowercase();
    let version = caps.get(2)?.as_str().to_string();
    Some((product, version))
}

fn extract_http(banner: &str) -> Option<(String, String)> {
    // Try common web server patterns first
    let re = Regex::new(r"(?i)(apache|nginx|lighttpd|caddy|openresty|hiawatha)/([\d\.]+)").ok()?;
    if let Some(caps) = re.captures(banner) {
        let product = caps.get(1)?.as_str().to_lowercase();
        let version = caps.get(2)?.as_str().to_string();
        return Some((product, version));
    }
    // Generic fallback for HTTP: Product/Version
    let re = Regex::new(r"([A-Za-z0-9\-]+)/([\d\.]+)").ok()?;
    let caps = re.captures(banner)?;
    let product = caps.get(1)?.as_str().to_lowercase();
    let version = caps.get(2)?.as_str().to_string();
    Some((product, version))
}

fn extract_ftp(banner: &str) -> Option<(String, String)> {
    let re = Regex::new(r"(?i)proftpd\s+([\d\.]+)").ok()?;
    if let Some(caps) = re.captures(banner) {
        let version = caps.get(1)?.as_str().to_string();
        return Some(("proftpd".into(), version));
    }
    let re = Regex::new(r"(?i)vsftpd\s+([\d\.]+)").ok()?;
    if let Some(caps) = re.captures(banner) {
        let version = caps.get(1)?.as_str().to_string();
        return Some(("vsftpd".into(), version));
    }
    let re = Regex::new(r"(?i)filezilla\s+server\s+([\d\.]+)").ok()?;
    if let Some(caps) = re.captures(banner) {
        let version = caps.get(1)?.as_str().to_string();
        return Some(("filezilla".into(), version));
    }
    None
}

fn extract_smtp(banner: &str) -> Option<(String, String)> {
    let re = Regex::new(r"(?i)postfix\s+([\d\.]+)").ok()?;
    if let Some(caps) = re.captures(banner) {
        let version = caps.get(1)?.as_str().to_string();
        return Some(("postfix".into(), version));
    }
    let re = Regex::new(r"(?i)exim\s+([\d\.]+)").ok()?;
    if let Some(caps) = re.captures(banner) {
        let version = caps.get(1)?.as_str().to_string();
        return Some(("exim".into(), version));
    }
    let re = Regex::new(r"(?i)sendmail\s+([\d\.]+)").ok()?;
    if let Some(caps) = re.captures(banner) {
        let version = caps.get(1)?.as_str().to_string();
        return Some(("sendmail".into(), version));
    }
    None
}

fn extract_generic(banner: &str) -> Option<(String, String)> {
    let re = Regex::new(r"([A-Za-z0-9\-]+)[/_]([\d\.]+)").ok()?;
    let caps = re.captures(banner)?;
    let product = caps.get(1)?.as_str().to_lowercase();
    let version = caps.get(2)?.as_str().to_string();
    Some((product, version))
}

/// Look up the CPE vendor name for a given product.
///
/// Returns the product itself if no mapping is known.
pub fn vendor_lookup(product: &str) -> &str {
    match product.to_lowercase().as_str() {
        "openssh" => "openbsd",
        "apache" => "apache",
        "nginx" => "nginx",
        "proftpd" => "proftpd",
        "vsftpd" => "vsftpd",
        "mysql" => "oracle",
        "postgresql" => "postgresql",
        "postfix" => "postfix",
        "exim" => "exim",
        "sendmail" => "sendmail",
        "lighttpd" => "lighttpd",
        "caddy" => "caddy",
        _ => product,
    }
}

/// Build a CPE 2.3 string from product and version.
///
/// Format: `cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*:*`
pub fn build_cpe(product: &str, version: &str) -> String {
    let vendor = vendor_lookup(product);
    format!("cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*")
}

#[cfg(test)]
mod tests {
    use crate::scanner::models::ServiceType;

    #[test]
    fn extract_version_openssh() {
        let result = super::extract_version("SSH-2.0-OpenSSH_8.9", ServiceType::Ssh);
        assert_eq!(result, Some(("openssh".into(), "8.9".into())));
    }

    #[test]
    fn extract_version_apache() {
        let result = super::extract_version("Apache/2.4.51", ServiceType::Http);
        assert_eq!(result, Some(("apache".into(), "2.4.51".into())));
    }

    #[test]
    fn extract_version_nginx() {
        let result = super::extract_version("nginx/1.21.6", ServiceType::Http);
        assert_eq!(result, Some(("nginx".into(), "1.21.6".into())));
    }

    #[test]
    fn extract_version_proftpd() {
        let result = super::extract_version("ProFTPD 1.3.7", ServiceType::Ftp);
        assert_eq!(result, Some(("proftpd".into(), "1.3.7".into())));
    }

    #[test]
    fn extract_version_none_banner_returns_none() {
        let result = super::extract_version("", ServiceType::Ssh);
        assert_eq!(result, None);
    }

    #[test]
    fn extract_version_unrecognized_returns_none() {
        let result = super::extract_version("some random text", ServiceType::Http);
        assert_eq!(result, None);
    }

    #[test]
    fn extract_version_vsftpd() {
        let result = super::extract_version("220 vsftpd 3.0.3", ServiceType::Ftp);
        assert_eq!(result, Some(("vsftpd".into(), "3.0.3".into())));
    }

    #[test]
    fn extract_version_lighttpd() {
        let result = super::extract_version("lighttpd/1.4.59", ServiceType::Http);
        assert_eq!(result, Some(("lighttpd".into(), "1.4.59".into())));
    }

    #[test]
    fn extract_version_postfix() {
        let result = super::extract_version("220 mail.example.com ESMTP Postfix 3.6.4", ServiceType::Smtp);
        assert_eq!(result, Some(("postfix".into(), "3.6.4".into())));
    }

    #[test]
    fn extract_version_exim() {
        let result = super::extract_version("220 mail.example.com Exim 4.94", ServiceType::Smtp);
        assert_eq!(result, Some(("exim".into(), "4.94".into())));
    }

    #[test]
    fn extract_version_generic_fallback() {
        let result = super::extract_version("MyApp/2.0.1", ServiceType::Unknown);
        assert_eq!(result, Some(("myapp".into(), "2.0.1".into())));
    }

    #[test]
    fn extract_version_ssh_with_p1_suffix() {
        let result = super::extract_version("SSH-2.0-OpenSSH_9.1p1", ServiceType::Ssh);
        assert_eq!(result, Some(("openssh".into(), "9.1".into())));
    }

    #[test]
    fn extract_version_unknown_service_returns_none_for_gibberish() {
        let result = super::extract_version("!!!@@@###", ServiceType::Dns);
        assert_eq!(result, None);
    }

    #[test]
    fn extract_version_apache_with_detail() {
        let result = super::extract_version("Apache/2.4.41 (Ubuntu)", ServiceType::Http);
        assert_eq!(result, Some(("apache".into(), "2.4.41".into())));
    }

    #[test]
    fn build_cpe_openssh() {
        let result = super::build_cpe("openssh", "8.9");
        assert_eq!(result, "cpe:2.3:a:openbsd:openssh:8.9:*:*:*:*:*:*:*");
    }

    #[test]
    fn build_cpe_nginx() {
        let result = super::build_cpe("nginx", "1.21.6");
        assert_eq!(result, "cpe:2.3:a:nginx:nginx:1.21.6:*:*:*:*:*:*:*");
    }

    #[test]
    fn build_cpe_apache() {
        let result = super::build_cpe("apache", "2.4.51");
        assert_eq!(result, "cpe:2.3:a:apache:apache:2.4.51:*:*:*:*:*:*:*");
    }

    #[test]
    fn build_cpe_proftpd() {
        let result = super::build_cpe("proftpd", "1.3.7");
        assert_eq!(result, "cpe:2.3:a:proftpd:proftpd:1.3.7:*:*:*:*:*:*:*");
    }

    #[test]
    fn vendor_lookup_mysql() {
        assert_eq!(super::vendor_lookup("mysql"), "oracle");
    }

    #[test]
    fn vendor_lookup_postgresql() {
        assert_eq!(super::vendor_lookup("postgresql"), "postgresql");
    }

    #[test]
    fn vendor_lookup_unknown_product_returns_itself() {
        assert_eq!(super::vendor_lookup("unknownproduct"), "unknownproduct");
    }
}
