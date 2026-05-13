mod persist;
mod report;
mod scan;
pub mod serve;
mod update;

use clap::{Parser, Subcommand};
use ipnetwork::IpNetwork;
use std::path::PathBuf;

use crate::error::Error;
use crate::scanner::{Scanner, detect, detect_local_network};
use scan::{format_hosts_json, format_hosts_table};
use update::{UpdateArgs, handle_update};

/// netascan — Network security audit CLI
#[derive(Parser)]
#[command(name = "netascan", version = "0.1.0", about)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Scan a network range for devices and vulnerabilities
    Scan(scan::ScanArgs),
    /// View or generate reports from previous scans
    Report(report::ReportArgs),
    /// Start the local web dashboard server
    Serve(serve::ServeArgs),
    /// Update OUI database and default credential lists
    Update(UpdateArgs),
}

/// Parse CLI arguments and dispatch to the appropriate subcommand handler.
pub async fn run() -> Result<(), Error> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Scan(args) => {
            // Resolve network: "auto" or explicit CIDR
            let network = resolve_network(&args.network)?;

            // Resolve port range: --port-range > --full > config default
            let port_range = if let Some(ref pr) = args.port_range {
                pr.clone()
            } else if args.full {
                "full".into()
            } else {
                crate::config::ScanConfig::default().port_range
            };

            // Warn if --full is used on a large network
            if args.full && network.prefix() < 31 {
                tracing::warn!(
                    "--full scan on network /{} — this may take a very long time!",
                    network.prefix()
                );
            }

            // Build scan config from CLI args
            let config = crate::config::ScanConfig {
                default_network: args.network.clone(),
                port_range,
                timeout_ms: args.timeout_ms,
                banner_timeout_ms: args.banner_timeout_ms,
                concurrency: args.concurrency,
            };

            // Detect platform capabilities
            let caps = detect();

            // Warn about unavailable methods
            if !caps.can_icmp {
                eprintln!("[!] ICMP sweep unavailable (requires root or CAP_NET_RAW). Using TCP + ARP only.");
            }

            // Capture start time for persistence
            let started_at = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);

            eprintln!("[*] Scanning network {} ...", network);

            // Run discovery
            let scanner = Scanner::new(config);
            let hosts = scanner.discover_network(&network, &caps).await?;

            eprintln!("[+] Discovered {} host(s)", hosts.len());
            eprintln!("[*] Scanning ports ...");

            // Run port scanning on discovered hosts
            let mut hosts = scanner.scan_ports(hosts).await;

            // Enrich with OUI/vendor data
            eprintln!("[*] Enriching vendor data (OUI) ...");
            let oui_db = if args.no_update {
                crate::scanner::OuiDb::from_embedded()
            } else {
                crate::scanner::OUI_DB.clone()
            };
            crate::scanner::enrich_oui(&oui_db, &mut hosts);

            // Enrich with CVE data (unless skipped)
            if !args.no_cve {
                eprintln!("[*] Checking CVEs ...");
                let cache_path = cache_dir().join("netascan/cve.db");
                if let Some(parent) = cache_path.parent() {
                    let _ = std::fs::create_dir_all(parent);
                }

                let api_key = std::env::var("NVD_API_KEY").ok().or_else(|| {
                    crate::config::Config::load().ok().and_then(|cfg| {
                        let key = cfg.cve.nvd_api_key;
                        if key.is_empty() { None } else { Some(key) }
                    })
                });

                match crate::cve::cache::CveCache::open(cache_path.to_str().unwrap_or("cve.db")).await {
                    Ok(cache) => {
                        let client = crate::cve::client::NvdClient::new(api_key);
                        crate::cve::enrich_cve(&mut hosts, &cache, &client, false).await;
                    }
                    Err(e) => {
                        eprintln!("[!] Failed to open CVE cache: {}", e);
                    }
                }
            } else {
                eprintln!("[*] CVE enrichment skipped (--no-cve)");
            }

            // Run default credential checks (non-fatal)
            eprintln!("[*] Testing default credentials ...");
            let creds_config = crate::config::Config::load()
                .map(|cfg| cfg.credentials_check)
                .unwrap_or_default();
            if let Err(e) = crate::security::check_default_credentials(&mut hosts, &creds_config).await {
                eprintln!("[!] Credential check failed: {}", e);
            }

            // Persist scan results (non-fatal)
            if let Err(e) = persist::save_scan(&hosts, &args, &args.network, &started_at) {
                eprintln!("[!] Failed to persist scan results: {}", e);
            }

            eprintln!("[+] Scan complete.");
            eprintln!();

            // Output results
            if args.json {
                println!("{}", format_hosts_json(&hosts));
            } else {
                println!("{}", format_hosts_table(&hosts));
            }
        }
        Commands::Report(args) => {
            report::handle_report(&args).await?;
        }
        Commands::Serve(args) => {
            crate::server::run(args).await?;
        }
        Commands::Update(args) => {
            handle_update(&args).await?;
        }
    }

    Ok(())
}

/// Resolve the cache directory path.
///
/// When running under sudo, prefers the original user's cache dir via SUDO_USER
/// to avoid storing files in /root/.cache.
fn cache_dir() -> PathBuf {
    // If running under sudo, resolve the real user's home directory
    if let Ok(sudo_user) = std::env::var("SUDO_USER") {
        let home = PathBuf::from("/home").join(&sudo_user);
        if home.exists() {
            return home.join(".cache");
        }
    }
    dirs::cache_dir().unwrap_or_else(|| PathBuf::from("."))
}

/// Resolve the network argument to an IpNetwork.
///
/// - "auto" → detect from first non-loopback interface
/// - CIDR string → parse directly
fn resolve_network(network: &str) -> Result<IpNetwork, Error> {
    if network == "auto" {
        detect_local_network().ok_or_else(|| {
            Error::InterfaceNotFound(
                "No active non-loopback network interface found. Specify --network explicitly.".into(),
            )
        })
    } else {
        network
            .parse::<IpNetwork>()
            .map_err(|e| Error::Parse(format!("Invalid CIDR network '{network}': {e}")))
    }
}

#[cfg(test)]
mod tests {
    use super::{Cli, Commands};
    use clap::{CommandFactory, Parser};

    #[test]
    fn verify_cli() {
        Cli::command().debug_assert();
    }

    #[test]
    fn parse_scan_subcommand() {
        let cli = Cli::parse_from(["netascan", "scan", "--network", "192.168.1.0/24"]);
        assert!(matches!(cli.command, Commands::Scan(_)));
    }

    #[test]
    fn parse_report_subcommand() {
        let cli = Cli::parse_from(["netascan", "report"]);
        assert!(matches!(cli.command, Commands::Report(_)));
    }

    #[test]
    fn parse_serve_subcommand() {
        let cli = Cli::parse_from(["netascan", "serve"]);
        assert!(matches!(cli.command, Commands::Serve(_)));
    }

    #[test]
    fn parse_update_subcommand() {
        let cli = Cli::parse_from(["netascan", "update"]);
        assert!(matches!(cli.command, Commands::Update(_)));
    }

    #[test]
    fn parse_update_subcommand_with_source() {
        let cli = Cli::parse_from(["netascan", "update", "--source", "https://example.com/manuf"]);
        if let Commands::Update(args) = cli.command {
            assert_eq!(args.source, Some("https://example.com/manuf".to_string()));
        } else {
            panic!("Expected Update command");
        }
    }

    #[test]
    fn parse_scan_with_no_update() {
        let cli = Cli::parse_from(["netascan", "scan", "--no-update"]);
        if let Commands::Scan(args) = cli.command {
            assert!(args.no_update);
        } else {
            panic!("Expected Scan command");
        }
    }
}
