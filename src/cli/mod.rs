mod report;
mod scan;
mod serve;
mod update;

use clap::{Parser, Subcommand};

use crate::error::Error;

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
        Commands::Scan(_args) => {
            println!("scan subcommand (stub)");
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
