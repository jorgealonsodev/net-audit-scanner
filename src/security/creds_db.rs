//! Default credentials database — download, cache, and load.
//!
//! Source: SecLists default-passwords.csv (Daniel Miessler)
//! Format: Vendor,Username,Password,Comments
//! Special values: `<BLANK>` = empty string, `<N/A>` = skip entry.
//!
//! Cache location: `~/.cache/netascan/default-creds.csv`
//! On first use: downloaded automatically if cache is absent.
//! Manual refresh: `netascan update` re-downloads both OUI and creds.

use std::path::PathBuf;

/// SecLists default credentials URL.
pub const SECLISTS_CREDS_URL: &str =
    "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Default-Credentials/default-passwords.csv";

/// Returns the path to the cached credentials CSV.
pub fn creds_cache_path() -> PathBuf {
    // Respect SUDO_USER so we don't write to /root/.cache under sudo.
    if let Ok(sudo_user) = std::env::var("SUDO_USER") {
        let home = PathBuf::from("/home").join(&sudo_user);
        if home.exists() {
            return home.join(".cache/netascan/default-creds.csv");
        }
    }
    dirs::cache_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("netascan/default-creds.csv")
}

/// Download the SecLists credentials CSV and save it to the cache path atomically.
/// Returns the number of credential pairs saved.
pub async fn download_creds_db() -> Result<usize, String> {
    let url = SECLISTS_CREDS_URL;
    let response = reqwest::get(url)
        .await
        .map_err(|e| format!("Failed to download credentials db: {}", e))?;

    if !response.status().is_success() {
        return Err(format!("Download failed with status: {}", response.status()));
    }

    let body = response
        .bytes()
        .await
        .map_err(|e| format!("Failed to read response body: {}", e))?;

    let path = creds_cache_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("Failed to create cache directory: {}", e))?;
    }

    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, &body)
        .map_err(|e| format!("Failed to write temp file: {}", e))?;
    std::fs::rename(&tmp, &path)
        .map_err(|e| format!("Failed to rename temp file: {}", e))?;

    let count = parse_csv(&String::from_utf8_lossy(&body)).len();
    Ok(count)
}

/// Parse the SecLists CSV into `(vendor, username, password)` triples.
/// Skips entries where username or password is `<N/A>`.
/// Replaces `<BLANK>` with empty string `""`.
pub fn parse_csv(content: &str) -> Vec<(String, String, String)> {
    let mut triples: Vec<(String, String, String)> = Vec::new();

    for line in content.lines().skip(1) {
        // CSV fields: Vendor,Username,Password,Comments
        let fields: Vec<&str> = line.splitn(4, ',').collect();
        if fields.len() < 3 {
            continue;
        }

        let raw_vendor = fields[0].trim().trim_matches('"');
        let raw_user = fields[1].trim().trim_matches('"');
        let raw_pass = fields[2].trim().trim_matches('"');

        if raw_user == "<N/A>" || raw_pass == "<N/A>" {
            continue;
        }

        let vendor = if raw_vendor == "<BLANK>" { "" } else { raw_vendor }.to_string();
        let username = if raw_user == "<BLANK>" { "" } else { raw_user }.to_string();
        let password = if raw_pass == "<BLANK>" { "" } else { raw_pass }.to_string();

        let triple = (vendor, username, password);
        if !triples.contains(&triple) {
            triples.push(triple);
        }
    }

    triples
}

/// Normalize a vendor string for fuzzy matching:
/// lowercase, strip punctuation, collapse whitespace.
pub fn normalize_vendor(v: &str) -> String {
    v.to_lowercase()
        .replace([',', '.', '-', '_', '(', ')', '/', '\\'], " ")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

/// Load credentials filtered by vendor.
///
/// Strategy:
/// 1. Always include "generic" pairs (vendor field is empty or vendor is unknown).
/// 2. If `vendor` is Some, also include pairs whose vendor name is a substring
///    match (normalized) of the host vendor, or vice versa.
/// 3. Falls back to the full list if the filtered result has fewer than 10 pairs
///    (covers cases where no vendor-specific creds exist).
pub async fn load_credentials_for_vendor(vendor: Option<&str>) -> Vec<(String, String)> {
    let path = creds_cache_path();

    let triples = if path.exists() {
        if let Ok(content) = std::fs::read_to_string(&path) {
            let t = parse_csv(&content);
            if !t.is_empty() { t } else { download_and_parse().await }
        } else {
            download_and_parse().await
        }
    } else {
        download_and_parse().await
    };

    if triples.is_empty() {
        return super::DEFAULT_CREDS
            .iter()
            .map(|(u, p)| (u.to_string(), p.to_string()))
            .collect();
    }

    let norm_host_vendor = vendor.map(normalize_vendor);

    let mut pairs: Vec<(String, String)> = Vec::new();
    let mut seen = std::collections::HashSet::new();

    for (csv_vendor, username, password) in &triples {
        let include = if csv_vendor.is_empty() {
            // Generic entry — always include
            true
        } else if let Some(ref nhv) = norm_host_vendor {
            let norm_csv = normalize_vendor(csv_vendor);
            // Match if either contains the other (handles abbreviations)
            nhv.contains(norm_csv.as_str()) || norm_csv.contains(nhv.as_str())
        } else {
            // No vendor info — include generic only (already handled above)
            false
        };

        if include {
            let pair = (username.clone(), password.clone());
            if seen.insert(pair.clone()) {
                pairs.push(pair);
            }
        }
    }

    // If too few vendor-specific pairs, fall back to full list
    if pairs.len() < 10 {
        tracing::debug!(
            "Vendor '{}' matched only {} pairs — using full list",
            vendor.unwrap_or("unknown"),
            pairs.len()
        );
        let mut all_pairs: Vec<(String, String)> = Vec::new();
        let mut all_seen = std::collections::HashSet::new();
        for (_, username, password) in &triples {
            let pair = (username.clone(), password.clone());
            if all_seen.insert(pair.clone()) {
                all_pairs.push(pair);
            }
        }
        return all_pairs;
    }

    tracing::debug!(
        "Vendor '{}' matched {} credential pairs",
        vendor.unwrap_or("unknown"),
        pairs.len()
    );
    pairs
}

/// Load all credentials without vendor filtering (kept for backwards compat).
pub async fn load_credentials() -> Vec<(String, String)> {
    load_credentials_for_vendor(None).await
}

async fn download_and_parse() -> Vec<(String, String, String)> {
    tracing::info!("Default credentials cache not found — downloading from SecLists...");
    match download_creds_db().await {
        Ok(count) => tracing::info!("Downloaded {} credential pairs", count),
        Err(e) => tracing::warn!("Could not download credentials db: {} — using built-in list", e),
    }
    let path = creds_cache_path();
    if let Ok(content) = std::fs::read_to_string(&path) {
        parse_csv(&content)
    } else {
        vec![]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_csv_skips_header() {
        let csv = "Vendor,Username,Password,Comments\n3COM,admin,admin,\n";
        let triples = parse_csv(csv);
        assert_eq!(triples.len(), 1);
        assert_eq!(triples[0], ("3COM".to_string(), "admin".to_string(), "admin".to_string()));
    }

    #[test]
    fn parse_csv_blank_becomes_empty_string() {
        let csv = "Vendor,Username,Password,Comments\n3COM,<BLANK>,<BLANK>,\n";
        let triples = parse_csv(csv);
        assert_eq!(triples.len(), 1);
        assert_eq!(triples[0], ("3COM".to_string(), "".to_string(), "".to_string()));
    }

    #[test]
    fn parse_csv_skips_na_entries() {
        let csv = "Vendor,Username,Password,Comments\n3COM,<N/A>,admin,\n3COM,admin,<N/A>,\n";
        let triples = parse_csv(csv);
        assert!(triples.is_empty());
    }

    #[test]
    fn parse_csv_deduplicates_same_vendor_user_pass() {
        let csv = "Vendor,Username,Password,Comments\nA,admin,admin,\nA,admin,admin,\n";
        let triples = parse_csv(csv);
        assert_eq!(triples.len(), 1);
    }

    #[test]
    fn parse_csv_different_vendors_same_creds_kept() {
        let csv = "Vendor,Username,Password,Comments\nA,admin,admin,\nB,admin,admin,\n";
        let triples = parse_csv(csv);
        assert_eq!(triples.len(), 2);
    }

    #[test]
    fn parse_csv_empty_content_returns_empty() {
        let triples = parse_csv("");
        assert!(triples.is_empty());
    }

    #[test]
    fn parse_csv_header_only_returns_empty() {
        let csv = "Vendor,Username,Password,Comments\n";
        let triples = parse_csv(csv);
        assert!(triples.is_empty());
    }

    #[test]
    fn parse_csv_multiple_pairs() {
        let csv = "Vendor,Username,Password,Comments\n\
            Cisco,cisco,cisco,\n\
            TP-Link,admin,admin,\n\
            TP-Link,admin,password,\n\
            Ubiquiti,ubnt,ubnt,\n";
        let triples = parse_csv(csv);
        assert_eq!(triples.len(), 4);
    }

    #[test]
    fn normalize_vendor_lowercases_and_strips_punct() {
        assert_eq!(normalize_vendor("TP-Link Systems Inc."), "tp link systems inc");
        assert_eq!(normalize_vendor("D-Link"), "d link");
        assert_eq!(normalize_vendor("3COM"), "3com");
    }

    #[test]
    fn vendor_match_tp_link() {
        // "tp link" contains "tp link" — should match
        let csv_vendor = normalize_vendor("TP-Link");
        let host_vendor = normalize_vendor("TP-Link Systems Inc.");
        assert!(host_vendor.contains(csv_vendor.as_str()) || csv_vendor.contains(host_vendor.as_str()));
    }

    #[test]
    fn vendor_match_zyxel() {
        let csv_vendor = normalize_vendor("Zyxel");
        let host_vendor = normalize_vendor("Zyxel Communications Corporation");
        assert!(host_vendor.contains(csv_vendor.as_str()) || csv_vendor.contains(host_vendor.as_str()));
    }

    #[test]
    fn vendor_no_match_different_brands() {
        let csv_vendor = normalize_vendor("Cisco");
        let host_vendor = normalize_vendor("TP-Link Systems Inc.");
        assert!(!host_vendor.contains(csv_vendor.as_str()) && !csv_vendor.contains(host_vendor.as_str()));
    }

    #[test]
    fn creds_cache_path_contains_netascan() {
        let path = creds_cache_path();
        assert!(path.to_string_lossy().contains("netascan"));
        assert!(path.to_string_lossy().ends_with("default-creds.csv"));
    }
}
