use clap::Args;

use crate::error::Error;

/// Arguments for the `update` subcommand.
#[derive(Args)]
pub struct UpdateArgs {
    /// Custom source URL for the manuf database
    #[arg(long)]
    pub source: Option<String>,
}

/// Canonical Wireshark manuf database URL.
const WIRESHARK_MANUF_URL: &str =
    "https://gitlab.com/wireshark/wireshark/-/raw/master/manuf";

/// Download the Wireshark manuf database and cache it atomically.
///
/// Downloads to a `.tmp` file first, then renames to the final cache path.
/// On success, prints the entry count and source URL to stdout.
/// On failure, prints an error to stderr and exits non-zero.
pub async fn handle_update(args: &UpdateArgs) -> Result<(), Error> {
    let url = args
        .source
        .as_deref()
        .unwrap_or(WIRESHARK_MANUF_URL);

    let response = reqwest::get(url)
        .await
        .map_err(|e| Error::Update(format!("Failed to download from {}: {}", url, e)))?;

    if !response.status().is_success() {
        return Err(Error::Update(format!(
            "Download failed with status: {}",
            response.status()
        )));
    }

    let body = response
        .bytes()
        .await
        .map_err(|e| Error::Update(format!("Failed to read response body: {}", e)))?;

    // Count entries before writing
    let content = String::from_utf8_lossy(&body);
    let entry_count = content
        .lines()
        .filter(|line| {
            let line = line.trim();
            !line.is_empty() && !line.starts_with('#')
        })
        .count();

    // Atomic write: write to .tmp, then rename
    let cache_path = crate::scanner::oui::cache_path();
    let tmp_path = cache_path.with_extension("tmp");

    if let Some(parent) = cache_path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| {
            Error::Update(format!("Failed to create cache directory: {}", e))
        })?;
    }

    std::fs::write(&tmp_path, &body).map_err(|e| {
        Error::Update(format!("Failed to write temporary file: {}", e))
    })?;

    std::fs::rename(&tmp_path, &cache_path).map_err(|e| {
        // Clean up tmp file on rename failure
        let _ = std::fs::remove_file(&tmp_path);
        Error::Update(format!("Failed to rename temporary file: {}", e))
    })?;

    println!("Downloaded {} OUI entries from {}", entry_count, url);
    println!("Cached to {}", cache_path.display());

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn handle_update_success_with_mock_server() {
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let manuf_fixture = "00:00:0C\tCisco\tCisco Systems, Inc.\n00:50:56\tVMware\tVMware, Inc.\n";

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_string(manuf_fixture))
            .mount(&server)
            .await;

        let args = UpdateArgs {
            source: Some(server.uri()),
        };
        let result = handle_update(&args).await;
        assert!(result.is_ok());

        // Verify cache file exists
        let cache_path = crate::scanner::oui::cache_path();
        assert!(cache_path.exists());

        // Clean up
        let _ = std::fs::remove_file(&cache_path);
    }

    #[tokio::test]
    async fn handle_update_failure_500_no_tmp_residue() {
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;

        let args = UpdateArgs {
            source: Some(server.uri()),
        };
        let result = handle_update(&args).await;
        assert!(result.is_err());

        // Verify no .tmp residue
        let tmp_path = crate::scanner::oui::cache_path().with_extension("tmp");
        assert!(!tmp_path.exists());
    }
}
