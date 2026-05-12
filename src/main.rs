use netascan::cli;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env().add_directive("netascan=info".parse()?))
        .init();

    cli::run().await?;
    Ok(())
}
