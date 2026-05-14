use netascan::cli;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Only enable tracing output if RUST_LOG is explicitly set.
    // Normal users see clean progress messages via eprintln! in the pipeline.
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    cli::run().await?;
    Ok(())
}
