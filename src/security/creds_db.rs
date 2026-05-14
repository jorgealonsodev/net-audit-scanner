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

/// Parse the SecLists CSV into `(username, password)` pairs.
/// Skips entries where username or password is `<N/A>`.
/// Replaces `<BLANK>` with empty string `""`.
pub fn parse_csv(content: &str) -> Vec<(String, String)> {
    let mut pairs: Vec<(String, String)> = Vec::new();

    for line in content.lines().skip(1) {
        // CSV fields: Vendor,Username,Password,Comments
        // Simple split — values are not quoted except Vendor
        let fields: Vec<&str> = line.splitn(4, ',').collect();
        if fields.len() < 3 {
            continue;
        }

        let raw_user = fields[1].trim().trim_matches('"');
        let raw_pass = fields[2].trim().trim_matches('"');

        // Skip unusable entries
        if raw_user == "<N/A>" || raw_pass == "<N/A>" {
            continue;
        }

        let username = if raw_user == "<BLANK>" { "" } else { raw_user }.to_string();
        let password = if raw_pass == "<BLANK>" { "" } else { raw_pass }.to_string();

        let pair = (username, password);
        if !pairs.contains(&pair) {
            pairs.push(pair);
        }
    }

    pairs
}

/// Load credentials from cache. If cache is absent, download it first.
/// Falls back to the built-in minimal list on any error.
pub async fn load_credentials() -> Vec<(String, String)> {
    let path = creds_cache_path();

    // Try cache first
    if path.exists() {
        if let Ok(content) = std::fs::read_to_string(&path) {
            let pairs = parse_csv(&content);
            if !pairs.is_empty() {
                return pairs;
            }
        }
    }

    // Cache absent — try to download
    tracing::info!("Default credentials cache not found — downloading from SecLists...");
    match download_creds_db().await {
        Ok(count) => {
            tracing::info!("Downloaded {} credential pairs", count);
            if let Ok(content) = std::fs::read_to_string(&path) {
                let pairs = parse_csv(&content);
                if !pairs.is_empty() {
                    return pairs;
                }
            }
        }
        Err(e) => {
            tracing::warn!("Could not download credentials db: {} — using built-in list", e);
        }
    }

    // Fallback: built-in minimal list
    super::DEFAULT_CREDS
        .iter()
        .map(|(u, p)| (u.to_string(), p.to_string()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_csv_skips_header() {
        let csv = "Vendor,Username,Password,Comments\n3COM,admin,admin,\n";
        let pairs = parse_csv(csv);
        assert_eq!(pairs.len(), 1);
        assert_eq!(pairs[0], ("admin".to_string(), "admin".to_string()));
    }

    #[test]
    fn parse_csv_blank_becomes_empty_string() {
        let csv = "Vendor,Username,Password,Comments\n3COM,<BLANK>,<BLANK>,\n";
        let pairs = parse_csv(csv);
        assert_eq!(pairs.len(), 1);
        assert_eq!(pairs[0], ("".to_string(), "".to_string()));
    }

    #[test]
    fn parse_csv_skips_na_entries() {
        let csv = "Vendor,Username,Password,Comments\n3COM,<N/A>,admin,\n3COM,admin,<N/A>,\n";
        let pairs = parse_csv(csv);
        assert!(pairs.is_empty());
    }

    #[test]
    fn parse_csv_deduplicates() {
        let csv = "Vendor,Username,Password,Comments\nA,admin,admin,\nB,admin,admin,\n";
        let pairs = parse_csv(csv);
        assert_eq!(pairs.len(), 1);
    }

    #[test]
    fn parse_csv_empty_content_returns_empty() {
        let pairs = parse_csv("");
        assert!(pairs.is_empty());
    }

    #[test]
    fn parse_csv_header_only_returns_empty() {
        let csv = "Vendor,Username,Password,Comments\n";
        let pairs = parse_csv(csv);
        assert!(pairs.is_empty());
    }

    #[test]
    fn parse_csv_multiple_pairs() {
        let csv = "Vendor,Username,Password,Comments\n\
            Cisco,cisco,cisco,\n\
            TP-Link,admin,admin,\n\
            TP-Link,admin,password,\n\
            Ubiquiti,ubnt,ubnt,\n";
        let pairs = parse_csv(csv);
        assert_eq!(pairs.len(), 4);
    }

    #[test]
    fn creds_cache_path_contains_netascan() {
        let path = creds_cache_path();
        assert!(path.to_string_lossy().contains("netascan"));
        assert!(path.to_string_lossy().ends_with("default-creds.csv"));
    }
}
