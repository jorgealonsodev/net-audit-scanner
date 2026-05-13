//! Report generation engine using embedded Tera templates.

use anyhow::Result;
use include_dir::{include_dir, Dir};
use tera::Tera;

use crate::scanner::models::DiscoveredHost;

use super::view_model::ReportContext;

static TEMPLATE_DIR: Dir<'_> = include_dir!("$CARGO_MANIFEST_DIR/src/report/templates");

/// Report generation engine with embedded templates.
pub struct ReportEngine {
    tera: Tera,
}

impl ReportEngine {
    /// Creates a new engine with embedded templates.
    pub fn new() -> Result<Self> {
        let mut tera = Tera::default();

        // Load all .tera files from the embedded directory
        for entry in TEMPLATE_DIR.files() {
            let path = entry.path();
            if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                if name.ends_with(".tera") {
                    if let Some(content) = entry.contents_utf8() {
                        tera.add_raw_template(name, content)
                            .map_err(|e| anyhow::anyhow!("Failed to parse template '{}': {}", name, e))?;
                    }
                }
            }
        }

        Ok(ReportEngine { tera })
    }

    /// Renders an HTML report from the given context.
    pub fn render_html(&self, ctx: &ReportContext) -> Result<String> {
        let mut context = tera::Context::from_serialize(ctx)
            .map_err(|e| anyhow::anyhow!("Failed to serialize report context: {}", e))?;
        // Add network field separately since it's not in ReportContext but template expects it
        context.insert("network", &ctx.network);

        self.tera
            .render("report.html.tera", &context)
            .map_err(|e| anyhow::anyhow!("Template render error: {}", e))
    }

    /// Serializes the report context to pretty-printed JSON.
    pub fn render_json(&self, ctx: &ReportContext) -> Result<String> {
        serde_json::to_string_pretty(ctx)
            .map_err(|e| anyhow::anyhow!("JSON serialization error: {}", e))
    }

    /// Convenience: generate HTML from raw scan data.
    pub fn generate_html(hosts: &[DiscoveredHost], output: Option<&std::path::Path>) -> Result<()> {
        let engine = Self::new()?;
        let ctx = ReportContext::from(&hosts.to_vec());
        let html = engine.render_html(&ctx)?;
        write_output(&html, output)
    }

    /// Convenience: generate JSON from raw scan data.
    pub fn generate_json(hosts: &[DiscoveredHost], output: Option<&std::path::Path>) -> Result<()> {
        let engine = Self::new()?;
        let ctx = ReportContext::from(&hosts.to_vec());
        let json = engine.render_json(&ctx)?;
        write_output(&json, output)
    }
}

fn write_output(content: &str, output: Option<&std::path::Path>) -> Result<()> {
    if let Some(path) = output {
        std::fs::write(path, content)?;
    } else {
        print!("{}", content);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cve::models::{CveMatch, Severity};
    use crate::scanner::models::{DiscoveryMethod, OpenPort, ServiceType};

    fn make_host(ip: &str, ports: Vec<OpenPort>) -> DiscoveredHost {
        DiscoveredHost {
            ip: ip.parse().unwrap(),
            mac: None,
            hostname: Some("test-host".into()),
            method: DiscoveryMethod::Tcp,
            open_ports: ports,
            rtt_ms: None,
            vendor: Some("Test Vendor".into()),
        }
    }

    fn make_port(port: u16, service: ServiceType, is_insecure: bool, cves: Vec<CveMatch>) -> OpenPort {
        OpenPort {
            port,
            service,
            banner: None,
            protocol: crate::scanner::models::Protocol::Tcp,
            is_insecure,
            cves,
        }
    }

    fn make_cve(id: &str) -> CveMatch {
        CveMatch {
            cve_id: id.into(),
            description: format!("Desc for {}", id),
            severity: Severity::High,
            score: Some(7.5),
            published: "2021-01-01".into(),
        }
    }

    #[test]
    fn engine_creates_successfully() {
        let engine = ReportEngine::new();
        assert!(engine.is_ok(), "Engine should create successfully");
    }

    #[test]
    fn render_html_produces_valid_html() {
        let engine = ReportEngine::new().unwrap();
        let hosts = vec![make_host("192.168.1.10", vec![])];
        let ctx = ReportContext::from(&hosts);
        let html = engine.render_html(&ctx).unwrap();

        assert!(html.contains("<!DOCTYPE html>"));
        assert!(html.contains("Security Audit Report"));
        assert!(html.contains("192.168.1.10"));
        // generated_at renders as an actual timestamp, not the variable name
        assert!(html.contains("Generated:"));
    }

    #[test]
    fn render_html_contains_host_data() {
        let engine = ReportEngine::new().unwrap();
        let cve = make_cve("CVE-2021-TEST");
        let port = make_port(22, ServiceType::Ssh, false, vec![cve]);
        let hosts = vec![make_host("10.0.0.1", vec![port])];
        let ctx = ReportContext::from(&hosts);
        let html = engine.render_html(&ctx).unwrap();

        assert!(html.contains("10.0.0.1"));
        assert!(html.contains("Test Vendor"));
        // Template renders host.cves length (from view model aggregation)
        assert!(html.contains("<td>1</td>"));
    }

    #[test]
    fn render_html_empty_hosts_produces_valid_html() {
        let engine = ReportEngine::new().unwrap();
        let hosts: Vec<DiscoveredHost> = vec![];
        let ctx = ReportContext::from(&hosts);
        let html = engine.render_html(&ctx).unwrap();

        assert!(html.contains("<!DOCTYPE html>"));
        assert!(html.contains("</html>"));
        // Empty tbody should still be present
        assert!(html.contains("<tbody>"));
    }

    #[test]
    fn render_json_has_required_fields() {
        let engine = ReportEngine::new().unwrap();
        let hosts = vec![make_host("10.0.0.1", vec![])];
        let ctx = ReportContext::from(&hosts);
        let json = engine.render_json(&ctx).unwrap();

        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(value.get("generated_at").is_some());
        assert!(value.get("version").is_some());
        assert!(value.get("network").is_some());
        assert!(value.get("host_count").is_some());
        assert!(value.get("hosts").is_some());
    }

    #[test]
    fn render_json_version_is_cargo_version() {
        let engine = ReportEngine::new().unwrap();
        let hosts: Vec<DiscoveredHost> = vec![];
        let ctx = ReportContext::from(&hosts);
        let json = engine.render_json(&ctx).unwrap();

        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(value["version"], "0.1.0");
    }

    #[test]
    fn render_json_is_pretty_printed() {
        let engine = ReportEngine::new().unwrap();
        let hosts = vec![make_host("10.0.0.1", vec![])];
        let ctx = ReportContext::from(&hosts);
        let json = engine.render_json(&ctx).unwrap();

        // Pretty-printed JSON has newlines and indentation
        assert!(json.contains('\n'));
        // 2-space indent
        assert!(json.contains("  \""));
    }

    #[test]
    fn render_json_roundtrip() {
        let engine = ReportEngine::new().unwrap();
        let cve = make_cve("CVE-2021-ROUNDTRIP");
        let port = make_port(80, ServiceType::Http, true, vec![cve]);
        let hosts = vec![make_host("192.168.1.1", vec![port])];
        let ctx = ReportContext::from(&hosts);
        let json = engine.render_json(&ctx).unwrap();

        let decoded: ReportContext = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.host_count, 1);
        assert_eq!(decoded.version, "0.1.0");
        assert_eq!(decoded.network, "unknown");
        assert_eq!(decoded.hosts[0].ip, "192.168.1.1");
        assert_eq!(decoded.hosts[0].cves.len(), 1);
        assert_eq!(decoded.hosts[0].cves[0].cve_id, "CVE-2021-ROUNDTRIP");
    }

    #[test]
    fn render_html_template_shows_cve_details() {
        let engine = ReportEngine::new().unwrap();
        let cve1 = make_cve("CVE-2021-41617");
        let cve2 = CveMatch {
            cve_id: "CVE-2020-9999".into(),
            description: "Another vulnerability".into(),
            severity: Severity::Critical,
            score: Some(9.8),
            published: "2020-01-01".into(),
        };
        let ssh_port = make_port(22, ServiceType::Ssh, false, vec![cve1]);
        let http_port = make_port(80, ServiceType::Http, true, vec![cve2]);
        let hosts = vec![make_host("10.0.0.50", vec![ssh_port, http_port])];
        let ctx = ReportContext::from(&hosts);
        let html = engine.render_html(&ctx).unwrap();

        // Summary section
        assert!(html.contains("Hosts Scanned"));
        assert!(html.contains("CVEs Found"));
        assert!(html.contains("Insecure Ports"));
        assert!(html.contains(">2<")); // total_cves = 2

        // Host table
        assert!(html.contains("10.0.0.50"));
        assert!(html.contains("Test Vendor"));
        assert!(html.contains("test-host")); // hostname

        // CVE details section
        assert!(html.contains("CVE-2021-41617"));
        assert!(html.contains("CVE-2020-9999"));
        assert!(html.contains("HIGH"));
        assert!(html.contains("CRITICAL"));
        assert!(html.contains("7.5"));
        assert!(html.contains("9.8"));

        // Port details
        assert!(html.contains("22"));
        assert!(html.contains("ssh"));
        assert!(html.contains("80"));
        assert!(html.contains("http"));
    }

    #[test]
    fn render_html_shows_no_cves_message() {
        let engine = ReportEngine::new().unwrap();
        let hosts = vec![make_host("10.0.0.99", vec![])];
        let ctx = ReportContext::from(&hosts);
        let html = engine.render_html(&ctx).unwrap();

        assert!(html.contains("No CVEs found for this host"));
    }

    #[test]
    fn render_html_shows_insecure_port_warning() {
        let engine = ReportEngine::new().unwrap();
        let port = make_port(23, ServiceType::Telnet, true, vec![]);
        let hosts = vec![make_host("10.0.0.77", vec![port])];
        let ctx = ReportContext::from(&hosts);
        let html = engine.render_html(&ctx).unwrap();

        assert!(html.contains("Yes")); // insecure port indicator
        assert!(html.contains("insecure")); // CSS class
    }

    #[test]
    fn render_html_fails_with_broken_template() {
        // Create an engine with a deliberately broken template
        let mut tera = Tera::default();
        tera.add_raw_template("broken.tera", "{{ undefined_var }}")
            .expect("Broken template should parse (Tera allows undefined vars at parse time)");
        let engine = ReportEngine { tera };

        let hosts: Vec<DiscoveredHost> = vec![];
        let ctx = ReportContext::from(&hosts);
        let result = engine.render_html(&ctx);
        assert!(result.is_err(), "Render with undefined variable should fail");
        let err = result.unwrap_err().to_string();
        assert!(err.contains("Template render error"), "Error should mention template render issue: {err}");
    }

    #[test]
    fn render_html_context_has_summary_totals() {
        let engine = ReportEngine::new().unwrap();
        let cve = make_cve("CVE-2021-TEST");
        let port1 = make_port(22, ServiceType::Ssh, false, vec![cve]);
        let port2 = make_port(23, ServiceType::Telnet, true, vec![]);
        let hosts = vec![make_host("10.0.0.1", vec![port1, port2])];
        let ctx = ReportContext::from(&hosts);
        let html = engine.render_html(&ctx).unwrap();

        // Verify summary cards render the correct totals
        assert!(html.contains(">1<")); // host_count
        assert!(html.contains(">1<")); // total_cves (1 CVE)
        assert!(html.contains(">1<")); // total_insecure_ports (1 insecure port)
    }
}
