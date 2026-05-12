use clap::Args;

/// Arguments for the `scan` subcommand.
#[derive(Args)]
pub struct ScanArgs {
    /// Network range to scan (CIDR notation or "auto")
    #[arg(short, long, default_value = "auto")]
    pub network: String,

    /// Specific target IP to scan in depth
    #[arg(long)]
    pub target: Option<String>,

    /// Skip CVE lookup for faster results
    #[arg(long)]
    pub no_cve: bool,

    /// Full port scan instead of top-1000
    #[arg(long)]
    pub full: bool,

    /// Output report format (html, json)
    #[arg(short, long, default_value = "html")]
    pub report: String,
}
