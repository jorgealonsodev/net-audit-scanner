mod report;
mod scan;
mod serve;
mod update;

use clap::{Parser, Subcommand};
use ipnetwork::IpNetwork;

use crate::error::Error;
use crate::scanner::{Scanner, detect, detect_local_network};
use scan::{format_hosts_json, format_hosts_table};

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
    Update,
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
                tracing::warn!("ICMP sweep unavailable (requires root or CAP_NET_RAW). Using TCP + ARP only.");
            }

            // Run discovery
            let scanner = Scanner::new(config);
            let hosts = scanner.discover_network(&network, &caps).await?;

            // Run port scanning on discovered hosts
            let hosts = scanner.scan_ports(hosts).await;

            // Output results
            if args.json {
                println!("{}", format_hosts_json(&hosts));
            } else {
                println!("{}", format_hosts_table(&hosts));
            }
        }
        Commands::Report(_args) => {
            println!("report subcommand (stub)");
        }
        Commands::Serve(_args) => {
            println!("serve subcommand (stub)");
        }
        Commands::Update => {
            println!("update subcommand (stub)");
        }
    }

    Ok(())
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
        assert!(matches!(cli.command, Commands::Update));
    }
}
