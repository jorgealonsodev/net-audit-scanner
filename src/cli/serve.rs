use clap::Args;

/// Arguments for the `serve` subcommand.
#[derive(Args)]
pub struct ServeArgs {
    /// Port to bind the web server to
    #[arg(short, long, default_value_t = 7070)]
    pub port: u16,

    /// Bind address
    #[arg(long, default_value = "127.0.0.1")]
    pub bind: String,
}
