mod persist;
mod report;
mod scan;
pub mod serve;
mod setup;
mod update;

use clap::{Parser, Subcommand};
use ipnetwork::IpNetwork;
use std::path::PathBuf;

use crate::config::Config;
use crate::enrichment::{EnrichmentConfig, enrich_devices};
use crate::error::Error;
use crate::scanner::{Scanner, detect, detect_local_network};
use scan::{format_hosts_json, format_hosts_table};
use update::{UpdateArgs, handle_update};

/// netascan — Network security audit CLI
#[derive(Parser)]
#[command(name = "netascan", version = env!("CARGO_PKG_VERSION"), about)]
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
            let app_config = Config::load().unwrap_or_default();

            // First-run: prompt for missing API keys (non-blocking, TTY-only).
            setup::prompt_missing_keys_if_first_run(&app_config);

            // Reload config in case setup just saved new keys.
            let app_config = Config::load().unwrap_or_default();

            // Resolve network: "auto" or explicit CIDR
            let network = resolve_network(&args.network)?;

            // Resolve port range: --port-range > --full > config default
            let port_range = if let Some(ref pr) = args.port_range {
                pr.clone()
            } else if args.full {
                "full".into()
            } else {
                app_config.scan.port_range.clone()
            };

            // Warn if --full is used on a large network
            if args.full && network.prefix() < 31 {
                eprintln!(
                    "[!] --full scan on /{} — this may take a very long time!",
                    network.prefix()
                );
            }

            // Build scan config from CLI args
            let config = crate::config::ScanConfig {
                default_network: args.network.clone(),
                port_range: port_range.clone(),
                timeout_ms: args.timeout_ms,
                banner_timeout_ms: args.banner_timeout_ms,
                concurrency: args.concurrency,
            };

            // Detect platform capabilities
            let caps = detect();

            eprintln!("netascan v{}", env!("CARGO_PKG_VERSION"));
            eprintln!("--------------------------------------------------");

            if !caps.can_icmp {
                eprintln!("[!] ICMP unavailable — running without root/CAP_NET_RAW. Using TCP + ARP only.");
            }

            // Capture start time for persistence
            let started_at = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);

            eprintln!("[1/5] Discovering hosts on {} ...", network);

            // Run discovery
            let scanner = Scanner::new(config);
            let hosts = scanner.discover_network(&network, &caps).await?;

            if hosts.is_empty() {
                eprintln!("[!] No hosts found. Check network range or permissions.");
                return Ok(());
            }
            eprintln!("      Found {} live host(s)", hosts.len());

            eprintln!("[2/5] Scanning ports (range: {}) ...", port_range);

            // Run port scanning on discovered hosts
            let mut hosts = scanner.scan_ports(hosts).await;

            let open_ports: usize = hosts.iter().map(|h| h.open_ports.len()).sum();
            eprintln!("      Found {} open port(s) across {} host(s)", open_ports, hosts.len());

            // Enrich with OUI/vendor data
            eprintln!("[3/5] Enriching device info (OUI + SNMP + mDNS) ...");
            let oui_db = if args.no_update {
                crate::scanner::OuiDb::from_embedded()
            } else {
                crate::scanner::OUI_DB.clone()
            };
            crate::scanner::enrich_oui(&oui_db, &mut hosts);
            let with_vendor = hosts
                .iter()
                .filter(|h| h.vendor.as_deref().unwrap_or("-") != "-")
                .count();
            eprintln!("      Identified vendor for {}/{} host(s)", with_vendor, hosts.len());

            let enrichment_config = build_enrichment_config(&app_config, &args);
            enrich_devices(&mut hosts, &enrichment_config).await;

            let vendor_count = hosts.iter().filter(|host| host.vendor.is_some()).count();
            let hostname_count = hosts
                .iter()
                .filter(|host| host.hostname.as_deref().is_some_and(|value| !value.trim().is_empty()))
                .count();
            let model_count = hosts
                .iter()
                .filter(|host| host.device_model.as_deref().is_some_and(|value| !value.trim().is_empty()))
                .count();
            eprintln!(
                "[3/5] Enrichment complete: vendors found {}, hostnames resolved {}, models identified {}",
                vendor_count, hostname_count, model_count
            );

            // Enrich with CVE data (unless skipped)
            if !args.no_cve {
                eprintln!("[4/5] Checking CVEs (this may take a moment) ...");
                let cache_path = cache_dir().join("netascan/cve.db");
                if let Some(parent) = cache_path.parent() {
                    let _ = std::fs::create_dir_all(parent);
                }

                let api_key = std::env::var("NVD_API_KEY").ok().or_else(|| {
                    let key = app_config.cve.nvd_api_key.clone();
                    if key.is_empty() { None } else { Some(key) }
                });

                if api_key.is_none() {
                    eprintln!("      (tip: add NVD_API_KEY to ~/.netascan/config.toml to avoid rate limits)");
                }

                let db_uri = format!("sqlite:{}", cache_path.to_str().unwrap_or("cve.db"));
                match crate::cve::cache::CveCache::open(&db_uri).await {
                    Ok(cache) => {
                        let client = crate::cve::client::NvdClient::new(api_key);
                        crate::cve::enrich_cve(&mut hosts, &cache, &client, false).await;
                        let total_cves: usize = hosts.iter().flat_map(|h| &h.open_ports).map(|p| p.cves.len()).sum();
                        eprintln!("      Found {} CVE(s) total", total_cves);
                    }
                    Err(e) => {
                        eprintln!("[!] CVE cache unavailable: {} — skipping CVE enrichment", e);
                    }
                }
            } else {
                eprintln!("[4/5] CVE enrichment skipped (--no-cve)");
            }

            // Run default credential checks (non-fatal)
            eprintln!("[5/5] Testing default credentials ...");
            let creds_config = app_config.credentials_check;
            if let Err(e) = crate::security::check_default_credentials(&mut hosts, &creds_config).await {
                eprintln!("[!] Credential check error: {}", e);
            }
            let findings: usize = hosts.iter().map(|h| h.security_findings.len()).sum();
            if findings > 0 {
                eprintln!("      ALERT: {} default credential finding(s) detected!", findings);
            } else {
                eprintln!("      No default credentials found");
            }

            // Persist scan results (non-fatal)
            if let Err(e) = persist::save_scan(&hosts, &args, &args.network, &started_at) {
                eprintln!("[!] Failed to persist scan: {}", e);
            }

            eprintln!("--------------------------------------------------");
            eprintln!("Scan complete. {} host(s) scanned.", hosts.len());
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

fn build_enrichment_config(config: &Config, args: &scan::ScanArgs) -> EnrichmentConfig {
    EnrichmentConfig {
        snmp_enabled: config.enrichment.snmp_enabled,
        mdns_enabled: config.enrichment.mdns_enabled,
        mac_api_enabled: config.enrichment.mac_api_enabled && !args.no_mac_api,
        snmp_timeout_ms: config.enrichment.snmp_timeout_ms,
        mdns_timeout_ms: config.enrichment.mdns_timeout_ms,
        snmp_community: config.enrichment.snmp_community.clone(),
        mac_vendors_api_key: config.enrichment.mac_vendors_api_key.clone(),
    }
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
    use super::{Cli, Commands, build_enrichment_config};
    use crate::cli::scan;
    use clap::{CommandFactory, Parser};
    use crate::config::Config;

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

    #[test]
    fn parse_scan_with_mac_api_flag() {
        let cli = Cli::parse_from(["netascan", "scan", "--no-mac-api"]);
        if let Commands::Scan(args) = cli.command {
            assert!(args.no_mac_api);
        } else {
            panic!("Expected Scan command");
        }
    }

    #[test]
    fn build_enrichment_config_enables_mac_api_from_cli() {
        let args = scan::ScanArgs {
            network: "auto".into(),
            target: None,
            concurrency: 512,
            timeout_ms: 1500,
            banner_timeout_ms: 500,
            json: false,
            no_cve: false,
            full: false,
            port_range: None,
            report: "html".into(),
            no_update: false,
            no_mac_api: false,
        };

        let config = build_enrichment_config(&Config::default(), &args);

        assert!(config.mac_api_enabled);
        assert!(config.snmp_enabled);
        assert!(config.mdns_enabled);
        assert_eq!(config.snmp_community, "public");
    }

    #[test]
    fn build_enrichment_config_disables_mac_api_with_flag() {
        let args = scan::ScanArgs {
            network: "auto".into(),
            target: None,
            concurrency: 512,
            timeout_ms: 1500,
            banner_timeout_ms: 500,
            json: false,
            no_cve: false,
            full: false,
            port_range: None,
            report: "html".into(),
            no_update: false,
            no_mac_api: true,
        };

        let config = build_enrichment_config(&Config::default(), &args);

        assert!(!config.mac_api_enabled);
    }
}
