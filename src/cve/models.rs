use serde::{Deserialize, Serialize};

/// Severity level of a CVE vulnerability.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Unknown,
}

/// A matched CVE vulnerability for a given service/version.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CveMatch {
    pub cve_id: String,
    pub description: String,
    pub severity: Severity,
    pub score: Option<f32>,
    pub published: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cve_match_can_be_constructed() {
        let cve = CveMatch {
            cve_id: "CVE-2021-1234".into(),
            description: "Test vulnerability".into(),
            severity: Severity::High,
            score: Some(7.5),
            published: "2021-01-01".into(),
        };
        assert_eq!(cve.cve_id, "CVE-2021-1234");
        assert_eq!(cve.description, "Test vulnerability");
        assert_eq!(cve.severity, Severity::High);
        assert_eq!(cve.score, Some(7.5));
        assert_eq!(cve.published, "2021-01-01");
    }

    #[test]
    fn severity_variants_exist() {
        let _ = Severity::Critical;
        let _ = Severity::High;
        let _ = Severity::Medium;
        let _ = Severity::Low;
        let _ = Severity::Unknown;
    }

    #[test]
    fn severity_serializes_to_lowercase() {
        assert_eq!(
            serde_json::to_string(&Severity::Critical).unwrap(),
            r#""critical""#
        );
        assert_eq!(
            serde_json::to_string(&Severity::High).unwrap(),
            r#""high""#
        );
        assert_eq!(
            serde_json::to_string(&Severity::Medium).unwrap(),
            r#""medium""#
        );
        assert_eq!(
            serde_json::to_string(&Severity::Low).unwrap(),
            r#""low""#
        );
        assert_eq!(
            serde_json::to_string(&Severity::Unknown).unwrap(),
            r#""unknown""#
        );
    }

    #[test]
    fn cve_match_serializes_and_deserializes() {
        let cve = CveMatch {
            cve_id: "CVE-2021-1234".into(),
            description: "Test vulnerability".into(),
            severity: Severity::High,
            score: Some(7.5),
            published: "2021-01-01".into(),
        };
        let json = serde_json::to_string(&cve).unwrap();
        assert!(json.contains("CVE-2021-1234"));
        assert!(json.contains("Test vulnerability"));
        assert!(json.contains("high"));
        assert!(json.contains("7.5"));
        assert!(json.contains("2021-01-01"));

        let decoded: CveMatch = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.cve_id, cve.cve_id);
        assert_eq!(decoded.severity, cve.severity);
        assert_eq!(decoded.score, cve.score);
    }

    #[test]
    fn cve_match_with_none_score_roundtrips() {
        let cve = CveMatch {
            cve_id: "CVE-2020-9999".into(),
            description: "No score available".into(),
            severity: Severity::Unknown,
            score: None,
            published: "2020-12-31".into(),
        };
        let json = serde_json::to_string(&cve).unwrap();
        let decoded: CveMatch = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.score, None);
        assert_eq!(decoded.severity, Severity::Unknown);
    }
}
