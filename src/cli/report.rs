use clap::Args;

/// Arguments for the `report` subcommand.
#[derive(Args)]
pub struct ReportArgs {
    /// Output format (html, json)
    #[arg(short, long, default_value = "html")]
    pub format: String,

    /// Output file path
    #[arg(short, long)]
    pub output: Option<String>,

    /// Show the last generated report
    #[arg(long)]
    pub last: bool,
}
