mod cli;
mod output;
mod port;
mod scanner;
mod target;

use anyhow::Result;
use clap::Parser;
use cli::Cli;
use output::{write_results, OutputConfig};
use port::resolve_ports;
use scanner::connect::ConnectScanner;
use target::resolve_targets;
use tracing::info;

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // ── Logging setup ────────────────────────────────────────────────────────
    // Silent mode: suppress all log output; only results go to stdout.
    // Otherwise gate on -debug / -v flags.
    if cli.silent {
        // Install a no-op subscriber so tracing macros don't panic.
        let _ = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::ERROR)
            .with_writer(std::io::sink)
            .try_init();
    } else {
        let level = if cli.debug {
            tracing::Level::DEBUG
        } else if cli.verbose {
            tracing::Level::INFO
        } else {
            tracing::Level::WARN
        };
        tracing_subscriber::fmt()
            .with_max_level(level)
            .with_target(false)
            .init();
    }

    // ── Version / misc early exits ───────────────────────────────────────────
    if cli.version_flag {
        println!("lancer-naabu {}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }

    if cli.list_output_fields {
        println!("host\nport\nprotocol");
        return Ok(());
    }

    // ── Resolve ports ────────────────────────────────────────────────────────
    let ports = resolve_ports(
        cli.port.as_deref(),
        cli.top_ports.as_deref(),
        cli.ports_file.as_deref(),
        cli.exclude_ports.as_deref(),
    )?;

    if ports.is_empty() {
        anyhow::bail!("no ports to scan");
    }

    info!("resolved {} ports to scan", ports.len());

    // ── Resolve targets ──────────────────────────────────────────────────────
    let targets = resolve_targets(
        cli.host.as_deref(),
        cli.list.as_deref(),
        cli.no_stdin,
        cli.exclude_host.as_deref(),
        cli.exclude_file.as_deref(),
        cli.scan_all_ips,
        cli.input_read_timeout,
    )
    .await?;

    if targets.is_empty() {
        anyhow::bail!(
            "no targets to scan — provide --host, -l, or pipe targets via stdin"
        );
    }

    info!("resolved {} target IPs", targets.len());

    // ── Run scanner ──────────────────────────────────────────────────────────
    let scanner = ConnectScanner::new(
        targets,
        ports,
        cli.rate,
        cli.workers,
        cli.timeout,
        cli.retries,
    );

    let results = scanner.run().await?;

    info!("scan complete — {} open ports found", results.len());

    // ── Output ───────────────────────────────────────────────────────────────
    let out_cfg = OutputConfig {
        json: cli.json,
        csv: cli.csv,
        silent: cli.silent,
        output_file: cli.output.clone(),
    };

    write_results(&results, &out_cfg)?;

    Ok(())
}
