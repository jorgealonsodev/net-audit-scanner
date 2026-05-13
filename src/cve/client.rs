//! NVD API v2 client with rate-limit handling and graceful degradation.
//!
//! Provides [`NvdClient`] for querying CVEs by CPE string. On network or
//! rate-limit errors the client logs a warning and returns an empty vector so
//! the scan pipeline can continue uninterrupted.

use crate::cve::models::{CveMatch, Severity};
use anyhow::Result;
use reqwest::StatusCode;
use serde::Deserialize;
use std::time::Duration;

/// NVD API v2 client.
#[derive(Debug, Clone)]
pub struct NvdClient {
    http: reqwest::Client,
    api_key: Option<String>,
    base_url: String,
}

impl NvdClient {
    /// Create a new client with an optional API key.
    pub fn new(api_key: Option<String>) -> Self {
        Self::with_base_url(api_key, "https://services.nvd.nist.gov".into())
    }

    /// Create a client pointing at a custom base URL (useful for testing).
    pub fn with_base_url(api_key: Option<String>, base_url: String) -> Self {
        Self {
            http: reqwest::Client::new(),
            api_key,
            base_url,
        }
    }

    /// Query NVD for CVEs matching the given CPE string.
    ///
    /// Retries up to 3 times on 429 or 403 responses with exponential backoff.
    /// Returns an empty vector on unrecoverable failure (logged as warning).
    pub async fn query_cves(&self, cpe: &str) -> Result<Vec<CveMatch>> {
        let mut retries = 0;
        let max_retries = 3;

        loop {
            let mut request = self
                .http
                .get(format!("{}/rest/json/cves/2.0", self.base_url))
                .query(&[("cpeName", cpe)]);

            if let Some(ref key) = self.api_key {
                request = request.header("apiKey", key);
            }

            match request.send().await {
                Ok(response) => {
                    let status = response.status();

                    if status == StatusCode::TOO_MANY_REQUESTS || status == StatusCode::FORBIDDEN {
                        if retries < max_retries {
                            retries += 1;
                            let delay = Duration::from_secs(2u64.pow(retries));
                            tracing::warn!(
                                "NVD rate limit ({}), retrying in {:?} (attempt {}/{})",
                                status,
                                delay,
                                retries,
                                max_retries
                            );
                            tokio::time::sleep(delay).await;
                            continue;
                        } else {
                            tracing::warn!("NVD rate limit ({}) exceeded max retries, skipping CVE lookup", status);
                            return Ok(Vec::new());
                        }
                    }

                    if !status.is_success() {
                        tracing::warn!("NVD API returned {} for CPE {}, skipping CVE lookup", status, cpe);
                        return Ok(Vec::new());
                    }

                    let body = response.text().await?;
                    return Ok(parse_nvd_response(&body));
                }
                Err(e) => {
                    tracing::warn!("NVD request failed for CPE {}: {}, skipping", cpe, e);
                    return Ok(Vec::new());
                }
            }
        }
    }
}

/// Raw NVD API response shape (only the fields we care about).
#[derive(Debug, Deserialize)]
struct NvdResponse {
    #[serde(default)]
    vulnerabilities: Vec<NvdVulnerability>,
}

#[derive(Debug, Deserialize)]
struct NvdVulnerability {
    cve: NvdCve,
    #[serde(default)]
    impact: Option<NvdImpact>,
}

#[derive(Debug, Deserialize)]
struct NvdCve {
    id: String,
    #[serde(default)]
    descriptions: Vec<NvdDescription>,
    #[serde(default)]
    published: Option<String>,
}

#[derive(Debug, Deserialize)]
struct NvdDescription {
    lang: String,
    value: String,
}

#[derive(Debug, Deserialize)]
#[allow(non_snake_case)]
struct NvdImpact {
    #[serde(default)]
    baseMetricV3: Option<NvdBaseMetricV3>,
}

#[derive(Debug, Deserialize)]
#[allow(non_snake_case)]
struct NvdBaseMetricV3 {
    #[serde(default)]
    cvssV3: Option<NvdCvssV3>,
}

#[derive(Debug, Deserialize)]
#[allow(non_snake_case)]
struct NvdCvssV3 {
    #[serde(default)]
    baseScore: Option<f32>,
    #[serde(default)]
    baseSeverity: Option<String>,
}

/// Parse an NVD JSON response into a list of [`CveMatch`]es.
fn parse_nvd_response(body: &str) -> Vec<CveMatch> {
    let parsed: NvdResponse = match serde_json::from_str(body) {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!("Failed to parse NVD response: {}", e);
            return Vec::new();
        }
    };

    parsed
        .vulnerabilities
        .into_iter()
        .map(|v| {
            let description = v
                .cve
                .descriptions
                .iter()
                .find(|d| d.lang == "en")
                .map(|d| d.value.clone())
                .unwrap_or_default();

            let (score, severity) = v
                .impact
                .and_then(|i| i.baseMetricV3)
                .and_then(|bm| bm.cvssV3)
                .map(|cvss| {
                    let sev = match cvss.baseSeverity.as_deref() {
                        Some("CRITICAL") => Severity::Critical,
                        Some("HIGH") => Severity::High,
                        Some("MEDIUM") => Severity::Medium,
                        Some("LOW") => Severity::Low,
                        _ => Severity::Unknown,
                    };
                    (cvss.baseScore, sev)
                })
                .unwrap_or((None, Severity::Unknown));

            CveMatch {
                cve_id: v.cve.id,
                description,
                severity,
                score,
                published: v.cve.published.unwrap_or_default(),
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    // ─── parse_nvd_response tests ───

    #[test]
    fn parse_nvd_response_extracts_cve_fields() {
        let json = r#"{
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2021-41617",
                        "descriptions": [
                            {"lang": "en", "value": "sshd privilege escalation"}
                        ],
                        "published": "2021-09-20T00:00:00.000"
                    },
                    "impact": {
                        "baseMetricV3": {
                            "cvssV3": {
                                "baseScore": 7.8,
                                "baseSeverity": "HIGH"
                            }
                        }
                    }
                }
            ]
        }"#;

        let matches = parse_nvd_response(json);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].cve_id, "CVE-2021-41617");
        assert_eq!(matches[0].description, "sshd privilege escalation");
        assert_eq!(matches[0].severity, Severity::High);
        assert_eq!(matches[0].score, Some(7.8));
        assert_eq!(matches[0].published, "2021-09-20T00:00:00.000");
    }

    #[test]
    fn parse_nvd_response_multiple_cves() {
        let json = r#"{
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2021-41617",
                        "descriptions": [{"lang": "en", "value": "First"}],
                        "published": "2021-09-20T00:00:00.000"
                    },
                    "impact": {
                        "baseMetricV3": {
                            "cvssV3": {"baseScore": 7.8, "baseSeverity": "HIGH"}
                        }
                    }
                },
                {
                    "cve": {
                        "id": "CVE-2023-1234",
                        "descriptions": [{"lang": "en", "value": "Second"}],
                        "published": "2023-01-15T00:00:00.000"
                    },
                    "impact": {
                        "baseMetricV3": {
                            "cvssV3": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}
                        }
                    }
                }
            ]
        }"#;

        let matches = parse_nvd_response(json);
        assert_eq!(matches.len(), 2);
        assert_eq!(matches[0].cve_id, "CVE-2021-41617");
        assert_eq!(matches[1].cve_id, "CVE-2023-1234");
        assert_eq!(matches[1].severity, Severity::Critical);
    }

    #[test]
    fn parse_nvd_response_empty_vulnerabilities() {
        let json = r#"{"vulnerabilities": []}"#;
        let matches = parse_nvd_response(json);
        assert!(matches.is_empty());
    }

    #[test]
    fn parse_nvd_response_missing_impact_defaults_unknown() {
        let json = r#"{
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2020-9999",
                        "descriptions": [{"lang": "en", "value": "No CVSS"}],
                        "published": "2020-01-01T00:00:00.000"
                    }
                }
            ]
        }"#;

        let matches = parse_nvd_response(json);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].severity, Severity::Unknown);
        assert_eq!(matches[0].score, None);
    }

    #[test]
    fn parse_nvd_response_invalid_json_returns_empty() {
        let matches = parse_nvd_response("not json");
        assert!(matches.is_empty());
    }

    // ─── NvdClient integration tests with wiremock ───

    #[tokio::test]
    async fn query_cves_returns_parsed_matches() {
        let server = MockServer::start().await;
        let client = NvdClient::with_base_url(None, server.uri());

        Mock::given(method("GET"))
            .and(path("/rest/json/cves/2.0"))
            .and(query_param("cpeName", "cpe:2.3:a:openbsd:openssh:8.9:*:*:*:*:*:*:*"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "vulnerabilities": [
                    {
                        "cve": {
                            "id": "CVE-2021-41617",
                            "descriptions": [{"lang": "en", "value": "sshd privilege escalation"}],
                            "published": "2021-09-20T00:00:00.000"
                        },
                        "impact": {
                            "baseMetricV3": {
                                "cvssV3": {"baseScore": 7.8, "baseSeverity": "HIGH"}
                            }
                        }
                    }
                ]
            })))
            .mount(&server)
            .await;

        let matches = client
            .query_cves("cpe:2.3:a:openbsd:openssh:8.9:*:*:*:*:*:*:*")
            .await
            .unwrap();

        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].cve_id, "CVE-2021-41617");
    }

    #[tokio::test]
    async fn query_cves_returns_empty_on_403() {
        let server = MockServer::start().await;
        let client = NvdClient::with_base_url(None, server.uri());

        Mock::given(method("GET"))
            .and(path("/rest/json/cves/2.0"))
            .respond_with(ResponseTemplate::new(403))
            .mount(&server)
            .await;

        let matches = client
            .query_cves("cpe:2.3:a:test:test:1.0:*:*:*:*:*:*:*")
            .await
            .unwrap();
        assert!(matches.is_empty());
    }

    #[tokio::test]
    async fn query_cves_retries_on_429_then_succeeds() {
        let server = MockServer::start().await;
        let client = NvdClient::with_base_url(None, server.uri());

        Mock::given(method("GET"))
            .and(path("/rest/json/cves/2.0"))
            .respond_with(ResponseTemplate::new(429))
            .up_to_n_times(2)
            .mount(&server)
            .await;

        Mock::given(method("GET"))
            .and(path("/rest/json/cves/2.0"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "vulnerabilities": [
                    {
                        "cve": {
                            "id": "CVE-2023-9999",
                            "descriptions": [{"lang": "en", "value": "Retry success"}],
                            "published": "2023-01-01T00:00:00.000"
                        },
                        "impact": {
                            "baseMetricV3": {
                                "cvssV3": {"baseScore": 5.0, "baseSeverity": "MEDIUM"}
                            }
                        }
                    }
                ]
            })))
            .mount(&server)
            .await;

        let matches = client
            .query_cves("cpe:2.3:a:test:test:1.0:*:*:*:*:*:*:*")
            .await
            .unwrap();
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].cve_id, "CVE-2023-9999");
    }

    #[tokio::test]
    async fn query_cves_returns_empty_after_max_retries() {
        let server = MockServer::start().await;
        let client = NvdClient::with_base_url(None, server.uri());

        Mock::given(method("GET"))
            .and(path("/rest/json/cves/2.0"))
            .respond_with(ResponseTemplate::new(429))
            .expect(4) // initial + 3 retries
            .mount(&server)
            .await;

        let matches = client
            .query_cves("cpe:2.3:a:test:test:1.0:*:*:*:*:*:*:*")
            .await
            .unwrap();
        assert!(matches.is_empty());
    }

    #[tokio::test]
    async fn query_cves_includes_api_key_header_when_set() {
        let server = MockServer::start().await;
        let client = NvdClient::with_base_url(Some("my-secret-key".into()), server.uri());

        Mock::given(method("GET"))
            .and(path("/rest/json/cves/2.0"))
            .and(wiremock::matchers::header("apiKey", "my-secret-key"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "vulnerabilities": []
            })))
            .mount(&server)
            .await;

        let matches = client
            .query_cves("cpe:2.3:a:test:test:1.0:*:*:*:*:*:*:*")
            .await
            .unwrap();
        assert!(matches.is_empty());
    }
}
