use clap::Args;
use std::io::Read;
use std::path::PathBuf;

use crate::error::Error;
use crate::report::ReportEngine;
use crate::scanner::models::DiscoveredHost;

/// Arguments for the `report` subcommand.
#[derive(Args)]
pub struct ReportArgs {
    /// Output format (html, json)
    #[arg(short, long, default_value = "html")]
    pub format: String,

    /// Output file path (defaults to stdout)
    #[arg(short, long)]
    pub output: Option<String>,

    /// Show the last generated report
    #[arg(long)]
    pub last: bool,

    /// Input file path (JSON scan result), or `-` for stdin
    #[arg(short, long)]
    pub input: Option<PathBuf>,
}

/// Reads scan data from a file or stdin and returns deserialized hosts.
fn read_input(path: &Option<PathBuf>) -> Result<Vec<DiscoveredHost>, Error> {
    let data = match path {
        Some(p) if p.to_str() == Some("-") => {
            let mut buf = String::new();
            std::io::stdin()
                .read_to_string(&mut buf)
                .map_err(|e| Error::Report(format!("Failed to read stdin: {e}")))?;
            buf
        }
        Some(p) => std::fs::read_to_string(p)
            .map_err(|e| Error::Report(format!("Failed to read input file '{}': {e}", p.display())))?,
        None => {
            let mut buf = String::new();
            std::io::stdin()
                .read_to_string(&mut buf)
                .map_err(|e| Error::Report(format!("Failed to read stdin: {e}")))?;
            buf
        }
    };

    serde_json::from_str(&data)
        .map_err(|e| Error::Report(format!("Failed to parse scan JSON: {e}")))
}

/// Handles the report subcommand: reads input, generates report, writes output.
pub async fn handle_report(args: &ReportArgs) -> Result<(), Error> {
    if args.last {
        eprintln!("not yet implemented");
        return Ok(());
    }

    // Validate format
    if args.format != "html" && args.format != "json" {
        return Err(Error::Report(format!(
            "Invalid format '{}'. Valid formats: html, json",
            args.format
        )));
    }

    let hosts = read_input(&args.input)?;
    let output_path = args.output.as_deref();

    let engine = ReportEngine::new().map_err(|e| Error::Template(e.to_string()))?;
    let ctx = crate::report::ReportContext::from(&hosts);

    match args.format.as_str() {
        "html" => {
            let html = engine.render_html(&ctx).map_err(|e| Error::Template(e.to_string()))?;
            write_output(&html, output_path)?;
        }
        "json" => {
            let json = engine.render_json(&ctx).map_err(|e| Error::Report(e.to_string()))?;
            write_output(&json, output_path)?;
        }
        _ => unreachable!("format validated above"),
    }

    Ok(())
}

fn write_output(content: &str, path: Option<&str>) -> Result<(), Error> {
    if let Some(p) = path {
        std::fs::write(p, content).map_err(|e| Error::Report(format!("Failed to write output to '{}': {e}", p)))
    } else {
        print!("{}", content);
        Ok(())
    }
}
