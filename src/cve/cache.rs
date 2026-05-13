//! SQLite-backed CVE result cache with 24-hour TTL.
//!
//! Stores NVD API responses keyed by CPE string to avoid redundant queries
//! across hosts and scans. Stale entries (> 24h) are transparently re-fetched.

use crate::cve::models::CveMatch;
use anyhow::Result;
use sqlx::SqlitePool;
use sqlx::sqlite::SqlitePoolOptions;
use std::time::{SystemTime, UNIX_EPOCH};

/// Default cache TTL in seconds (24 hours).
pub const DEFAULT_CACHE_TTL_SECS: i64 = 86_400;

/// SQLite-backed cache for NVD CVE query results.
#[derive(Debug, Clone)]
pub struct CveCache {
    pool: SqlitePool,
    ttl_secs: i64,
}

impl CveCache {
    /// Open or create the cache database at the given path.
    ///
    /// The schema is created automatically if it does not exist.
    pub async fn open(path: &str) -> Result<Self> {
        let pool = SqlitePoolOptions::new().max_connections(2).connect(path).await?;

        let cache = Self {
            pool,
            ttl_secs: DEFAULT_CACHE_TTL_SECS,
        };
        cache.init_schema().await?;
        Ok(cache)
    }

    /// Create a cache with an existing pool (useful for testing).
    pub async fn with_pool(pool: SqlitePool) -> Result<Self> {
        let cache = Self {
            pool,
            ttl_secs: DEFAULT_CACHE_TTL_SECS,
        };
        cache.init_schema().await?;
        Ok(cache)
    }

    /// Set a custom TTL (used for testing or config overrides).
    pub fn with_ttl(mut self, ttl_secs: i64) -> Self {
        self.ttl_secs = ttl_secs;
        self
    }

    async fn init_schema(&self) -> Result<()> {
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS cve_cache (
                cpe_query TEXT PRIMARY KEY,
                response_json TEXT NOT NULL,
                fetched_at INTEGER NOT NULL
            )
            "#,
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Look up cached CVE results for a CPE string.
    ///
    /// Returns `None` if the entry is missing or older than the TTL.
    pub async fn lookup(&self, cpe: &str) -> Option<Vec<CveMatch>> {
        let now = Self::unix_now();
        let cutoff = now - self.ttl_secs;

        let row: Option<(String,)> =
            sqlx::query_as("SELECT response_json FROM cve_cache WHERE cpe_query = ? AND fetched_at > ?")
                .bind(cpe)
                .bind(cutoff)
                .fetch_optional(&self.pool)
                .await
                .ok()?;

        let (json,) = row?;
        serde_json::from_str(&json).ok()
    }

    /// Store CVE results for a CPE string, replacing any existing entry.
    pub async fn store(&self, cpe: &str, matches: &[CveMatch]) -> Result<()> {
        let json = serde_json::to_string(matches)?;
        let now = Self::unix_now();

        sqlx::query(
            r#"
            INSERT INTO cve_cache (cpe_query, response_json, fetched_at)
            VALUES (?, ?, ?)
            ON CONFLICT(cpe_query) DO UPDATE SET
                response_json = excluded.response_json,
                fetched_at = excluded.fetched_at
            "#,
        )
        .bind(cpe)
        .bind(json)
        .bind(now)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    fn unix_now() -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64
    }
}

/// Query NVD for CVEs, using the cache as a first-line lookup.
///
/// On cache miss the NVD client is called and the result is stored.
pub async fn query_nvd_cached(
    client: &crate::cve::client::NvdClient,
    cache: &CveCache,
    cpe: &str,
) -> Result<Vec<CveMatch>> {
    if let Some(matches) = cache.lookup(cpe).await {
        return Ok(matches);
    }

    let matches = client.query_cves(cpe).await?;
    if let Err(e) = cache.store(cpe, &matches).await {
        tracing::warn!("Failed to cache CVE results for {}: {}", cpe, e);
    }
    Ok(matches)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cve::models::Severity;

    async fn create_test_cache() -> CveCache {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        CveCache::with_pool(pool).await.unwrap()
    }

    fn sample_match() -> CveMatch {
        CveMatch {
            cve_id: "CVE-2021-41617".into(),
            description: "sshd privilege escalation".into(),
            severity: Severity::High,
            score: Some(7.8),
            published: "2021-09-20".into(),
        }
    }

    // ─── schema / round-trip tests ───

    #[tokio::test]
    async fn cache_store_and_lookup_roundtrip() {
        let cache = create_test_cache().await;
        let cpe = "cpe:2.3:a:openbsd:openssh:8.9:*:*:*:*:*:*:*";
        let matches = vec![sample_match()];

        cache.store(cpe, &matches).await.unwrap();
        let looked_up = cache.lookup(cpe).await;

        assert!(looked_up.is_some(), "Expected cache hit after store");
        let looked_up = looked_up.unwrap();
        assert_eq!(looked_up.len(), 1);
        assert_eq!(looked_up[0].cve_id, "CVE-2021-41617");
    }

    #[tokio::test]
    async fn cache_lookup_returns_none_when_missing() {
        let cache = create_test_cache().await;
        let result = cache.lookup("cpe:2.3:a:unknown:product:1.0:*:*:*:*:*:*:*").await;
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn cache_store_overwrites_existing() {
        let cache = create_test_cache().await;
        let cpe = "cpe:2.3:a:test:test:1.0:*:*:*:*:*:*:*";

        let first = vec![CveMatch {
            cve_id: "CVE-2021-1111".into(),
            description: "First".into(),
            severity: Severity::Low,
            score: Some(2.0),
            published: "2021-01-01".into(),
        }];
        let second = vec![CveMatch {
            cve_id: "CVE-2022-2222".into(),
            description: "Second".into(),
            severity: Severity::Critical,
            score: Some(9.8),
            published: "2022-02-02".into(),
        }];

        cache.store(cpe, &first).await.unwrap();
        cache.store(cpe, &second).await.unwrap();

        let looked_up = cache.lookup(cpe).await.unwrap();
        assert_eq!(looked_up.len(), 1);
        assert_eq!(looked_up[0].cve_id, "CVE-2022-2222");
    }

    // ─── TTL tests ───

    #[tokio::test]
    async fn cache_lookup_returns_none_when_stale() {
        let cache = create_test_cache().await;
        let cpe = "cpe:2.3:a:openbsd:openssh:8.9:*:*:*:*:*:*:*";
        let matches = vec![sample_match()];

        cache.store(cpe, &matches).await.unwrap();

        // Manually backdate the entry to make it stale
        let stale_time = CveCache::unix_now() - DEFAULT_CACHE_TTL_SECS - 1;
        sqlx::query("UPDATE cve_cache SET fetched_at = ? WHERE cpe_query = ?")
            .bind(stale_time)
            .bind(cpe)
            .execute(&cache.pool)
            .await
            .unwrap();

        let looked_up = cache.lookup(cpe).await;
        assert!(looked_up.is_none(), "Expected stale entry to be ignored");
    }

    #[tokio::test]
    async fn cache_lookup_returns_data_when_fresh() {
        let cache = create_test_cache().await;
        let cpe = "cpe:2.3:a:openbsd:openssh:8.9:*:*:*:*:*:*:*";
        let matches = vec![sample_match()];

        cache.store(cpe, &matches).await.unwrap();
        let looked_up = cache.lookup(cpe).await;
        assert!(looked_up.is_some(), "Fresh entry should be returned");
    }

    #[tokio::test]
    async fn cache_custom_ttl_respected() {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        let cache = CveCache::with_pool(pool).await.unwrap().with_ttl(60); // 1 minute TTL

        let cpe = "cpe:2.3:a:test:test:1.0:*:*:*:*:*:*:*";
        let matches = vec![sample_match()];
        cache.store(cpe, &matches).await.unwrap();

        // Backdate by 2 minutes (past the 1-minute TTL)
        let stale_time = CveCache::unix_now() - 120;
        sqlx::query("UPDATE cve_cache SET fetched_at = ? WHERE cpe_query = ?")
            .bind(stale_time)
            .bind(cpe)
            .execute(&cache.pool)
            .await
            .unwrap();

        let looked_up = cache.lookup(cpe).await;
        assert!(looked_up.is_none(), "Custom TTL should cause staleness");
    }

    // ─── query_nvd_cached tests ───

    #[tokio::test]
    async fn query_nvd_cached_uses_cache_on_second_call() {
        use crate::cve::client::NvdClient;
        use wiremock::matchers::{method, path, query_param};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let client = NvdClient::with_base_url(None, server.uri());
        let cache = create_test_cache().await;
        let cpe = "cpe:2.3:a:test:test:1.0:*:*:*:*:*:*:*";

        Mock::given(method("GET"))
            .and(path("/rest/json/cves/2.0"))
            .and(query_param("cpeName", cpe))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "vulnerabilities": [
                    {
                        "cve": {
                            "id": "CVE-2023-1234",
                            "descriptions": [{"lang": "en", "value": "Cached"}],
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
            .expect(1) // should only be called once
            .mount(&server)
            .await;

        // First call hits the API
        let first = query_nvd_cached(&client, &cache, cpe).await.unwrap();
        assert_eq!(first.len(), 1);
        assert_eq!(first[0].cve_id, "CVE-2023-1234");

        // Second call should use cache
        let second = query_nvd_cached(&client, &cache, cpe).await.unwrap();
        assert_eq!(second.len(), 1);
        assert_eq!(second[0].cve_id, "CVE-2023-1234");
    }
}
