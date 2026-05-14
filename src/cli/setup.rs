//! First-run API key setup prompt.
//!
//! On the first invocation of `netascan scan`, if any optional API keys are
//! missing from the config file, the user is prompted interactively with a
//! brief explanation of what each key enables and where to obtain it.
//!
//! Rules:
//! - Never blocks the scan — all keys are optional.
//! - Each key is prompted at most once (state tracked in the config file).
//! - Pressing Enter skips a key silently.
//! - Saved to `~/.netascan/config.toml`.

use std::io::{self, Write};
use std::path::PathBuf;

use crate::config::Config;

/// API key descriptor — what it is, why it matters, and where to get it.
struct KeyPrompt {
    env_var: &'static str,
    label: &'static str,
    benefit: &'static str,
    url: &'static str,
}

const KEY_PROMPTS: &[KeyPrompt] = &[
    KeyPrompt {
        env_var: "NVD_API_KEY",
        label: "NVD API key",
        benefit: "raises CVE rate limit from 5 to 50 req/30s (faster CVE lookups)",
        url: "https://nvd.nist.gov/developers/request-an-api-key",
    },
];

/// Check whether any API keys are missing and, if so, prompt the user once.
///
/// This function is intentionally non-fatal: if stdin is not a terminal (e.g.
/// in CI or when piped), it skips the prompt silently.
pub fn prompt_missing_keys_if_first_run(config: &Config) {
    // Only prompt when running interactively (stdin is a TTY).
    if !is_tty() {
        return;
    }

    let missing: Vec<&KeyPrompt> = KEY_PROMPTS
        .iter()
        .filter(|kp| {
            // Key is "missing" when not set in env AND not set in the config file.
            std::env::var(kp.env_var).is_err() && config_key_is_empty(config, kp.env_var)
        })
        .collect();

    if missing.is_empty() {
        return;
    }

    eprintln!();
    eprintln!("┌─────────────────────────────────────────────────────────────┐");
    eprintln!("│  netascan — first-run API key setup (optional, press Enter  │");
    eprintln!("│  to skip any key)                                           │");
    eprintln!("└─────────────────────────────────────────────────────────────┘");

    let mut collected: Vec<(&'static str, String)> = Vec::new();

    for kp in &missing {
        eprintln!();
        eprintln!("  {}:", kp.label);
        eprintln!("  → {} ", kp.benefit);
        eprintln!("  → Get yours free at: {}", kp.url);
        eprint!("  Paste key (or Enter to skip): ");
        let _ = io::stderr().flush();

        let mut input = String::new();
        match io::stdin().read_line(&mut input) {
            Ok(_) => {
                let trimmed = input.trim().to_string();
                if !trimmed.is_empty() {
                    collected.push((kp.env_var, trimmed));
                }
            }
            Err(_) => continue,
        }
    }

    eprintln!();

    if collected.is_empty() {
        return;
    }

    // Persist collected keys to ~/.netascan/config.toml
    if let Err(e) = save_keys_to_config(&collected) {
        eprintln!("[!] Could not save API keys to config: {e}");
        eprintln!("    You can set them manually via environment variables instead.");
    } else {
        eprintln!("[+] API keys saved to ~/.netascan/config.toml");
    }
}

/// Returns true when stdin is a terminal (not a pipe or redirect).
fn is_tty() -> bool {
    use std::os::unix::io::AsRawFd;
    // SAFETY: isatty is a safe POSIX call.
    unsafe { libc::isatty(io::stdin().as_raw_fd()) != 0 }
}

/// Returns true when the key is absent/empty in the loaded config.
fn config_key_is_empty(config: &Config, env_var: &str) -> bool {
    match env_var {
        "NVD_API_KEY" => config.cve.nvd_api_key.is_empty(),
        _ => true,
    }
}

/// Append or update the given keys in `~/.netascan/config.toml`.
///
/// Uses a simple line-based approach: reads existing content, replaces matching
/// `key = "..."` lines, or appends them to the correct section.
fn save_keys_to_config(keys: &[(&'static str, String)]) -> Result<(), std::io::Error> {
    let path = config_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    // Read existing content or start fresh.
    let existing = if path.exists() {
        std::fs::read_to_string(&path)?
    } else {
        default_config_template()
    };

    let updated = apply_keys_to_toml(existing, keys);
    std::fs::write(&path, updated)
}

/// Replace matching `key = "..."` assignments in the TOML string.
/// If a key is not found, it is appended to the relevant section.
fn apply_keys_to_toml(mut content: String, keys: &[(&'static str, String)]) -> String {
    for (env_var, value) in keys {
        let toml_key = env_var_to_toml_key(env_var);
        let replacement = format!("{} = \"{}\"", toml_key, value);

        // Try to replace an existing assignment (key = "...").
        let pattern = format!("{} = \"", toml_key);
        if let Some(start) = content.find(&pattern) {
            if let Some(end_quote) = content[start + pattern.len()..].find('"') {
                let line_end = start + pattern.len() + end_quote + 1;
                content.replace_range(start..line_end, &replacement);
                continue;
            }
        }

        // Key not found — append to the appropriate section.
        let section = env_var_to_section(env_var);
        let section_header = format!("[{}]", section);
        if let Some(pos) = content.find(&section_header) {
            // Insert after the section header line.
            let insert_at = content[pos..].find('\n').map(|n| pos + n + 1).unwrap_or(content.len());
            content.insert_str(insert_at, &format!("{}\n", replacement));
        } else {
            // Section missing entirely — append.
            content.push_str(&format!("\n[{}]\n{}\n", section, replacement));
        }
    }
    content
}

fn env_var_to_toml_key(env_var: &str) -> &'static str {
    match env_var {
        "NVD_API_KEY" => "nvd_api_key",
        "MAC_VENDORS_API_KEY" => "mac_vendors_api_key",
        _ => "unknown_key",
    }
}

fn env_var_to_section(env_var: &str) -> &'static str {
    match env_var {
        "NVD_API_KEY" => "cve",
        "MAC_VENDORS_API_KEY" => "enrichment",
        _ => "misc",
    }
}

fn config_path() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_default();
    PathBuf::from(home).join(".netascan").join("config.toml")
}

fn default_config_template() -> String {
    r#"[scan]
default_network = "auto"
port_range = "top-1000"
timeout_ms = 1500
banner_timeout_ms = 500
concurrency = 512

[cve]
nvd_api_key = ""
sources = ["nvd", "circl"]
cache_ttl_hours = 24

[report]
default_format = "html"
open_browser = true

[credentials_check]
enabled = true
custom_list = ""

[enrichment]
snmp_enabled = true
mdns_enabled = true
# MacVendors API is enabled by default — no key needed for up to 1000 req/day.
# Set mac_vendors_api_key for higher rate limits (paid plans at https://macvendors.com/api).
mac_api_enabled = true
snmp_timeout_ms = 1000
mdns_timeout_ms = 2000
snmp_community = "public"
mac_vendors_api_key = ""
"#
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn apply_keys_replaces_existing_nvd_key() {
        let toml = r#"[cve]
nvd_api_key = ""
"#
        .to_string();
        let result = apply_keys_to_toml(toml, &[("NVD_API_KEY", "abc123".to_string())]);
        assert!(result.contains(r#"nvd_api_key = "abc123""#));
    }

    #[test]
    fn apply_keys_appends_when_key_missing() {
        let toml = "[cve]\ncache_ttl_hours = 24\n".to_string();
        let result = apply_keys_to_toml(toml, &[("NVD_API_KEY", "mykey".to_string())]);
        assert!(result.contains(r#"nvd_api_key = "mykey""#));
    }

    #[test]
    fn apply_keys_creates_section_when_missing() {
        let toml = "[scan]\ndefault_network = \"auto\"\n".to_string();
        let result = apply_keys_to_toml(toml, &[("NVD_API_KEY", "newkey".to_string())]);
        assert!(result.contains("[cve]"));
        assert!(result.contains(r#"nvd_api_key = "newkey""#));
    }

    #[test]
    fn apply_keys_handles_mac_vendors_key() {
        let toml = "[enrichment]\nsnmp_enabled = true\nmac_vendors_api_key = \"\"\n".to_string();
        let result = apply_keys_to_toml(toml, &[("MAC_VENDORS_API_KEY", "mv_key".to_string())]);
        assert!(result.contains(r#"mac_vendors_api_key = "mv_key""#));
    }

    #[test]
    fn env_var_to_toml_key_maps_correctly() {
        assert_eq!(env_var_to_toml_key("NVD_API_KEY"), "nvd_api_key");
        assert_eq!(env_var_to_toml_key("MAC_VENDORS_API_KEY"), "mac_vendors_api_key");
    }

    #[test]
    fn env_var_to_section_maps_correctly() {
        assert_eq!(env_var_to_section("NVD_API_KEY"), "cve");
        assert_eq!(env_var_to_section("MAC_VENDORS_API_KEY"), "enrichment");
    }
}
