use netascan::cli;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Build env filter: if RUST_LOG is set, use it verbatim.
    // Otherwise default to ERROR-only and silence mdns_sd entirely
    // (it uses the `log` crate and emits noisy shutdown messages).
    let filter = if std::env::var("RUST_LOG").is_ok() {
        tracing_subscriber::EnvFilter::from_env("RUST_LOG")
    } else {
        tracing_subscriber::EnvFilter::new("error,mdns_sd=off")
    };

    // Bridge `log` crate records (used by mdns_sd and others) into tracing,
    // so the filter above applies to them as well.
    let _ = tracing_log::LogTracer::init();

    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .try_init();

    cli::run().await?;
    Ok(())
}
