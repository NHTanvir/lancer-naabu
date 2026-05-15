mod cli;
mod output;
mod port;
mod resume;
mod scanner;
mod target;

use anyhow::Result;
use clap::Parser;
use cli::Cli;
use output::{write_results, OutputConfig};
use port::resolve_ports;
use resume::ResumeState;
use scanner::connect::ConnectScanner;
use target::resolve_targets;
use tracing::info;

const RESUME_FILE: &str = "resume.json";

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // ── Logging setup ────────────────────────────────────────────────────────
    if cli.silent {
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
    if cli.list_output_fields {
        println!("host\nport\nprotocol\nip");
        return Ok(());
    }

    // ── Resume state ─────────────────────────────────────────────────────────
    // --stream is incompatible with resume; ignore resume flag when streaming.
    let use_resume = cli.resume && !cli.stream;
    let resume_path = std::path::Path::new(RESUME_FILE);

    let mut resume_state = if use_resume && resume_path.exists() {
        match ResumeState::load(resume_path) {
            Ok(s) => {
                info!(
                    "Loaded resume state: {} scanned, {} open",
                    s.scanned.len(),
                    s.completed.len()
                );
                s
            }
            Err(e) => {
                tracing::warn!("Could not load resume.json: {e} — starting fresh");
                ResumeState::default()
            }
        }
    } else {
        ResumeState::default()
    };

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
    if cli.scan_type.as_deref().map(|s| s.eq_ignore_ascii_case("SYN")).unwrap_or(false) {
        eprintln!("Warning: SYN scan is not yet implemented. Falling back to CONNECT.");
    }

    // Keep clones for resume book-keeping (scanner takes ownership).
    let targets_for_resume = if use_resume { targets.clone() } else { vec![] };
    let ports_for_resume   = if use_resume { ports.clone()   } else { vec![] };

    let mut scanner = ConnectScanner::new(
        targets.clone(),
        ports,
        cli.rate,
        cli.workers,
        cli.timeout,
        cli.retries,
    );

    // Wire up --port-threshold.
    if let Some(t) = cli.port_threshold {
        scanner.port_threshold = t as usize;
    }

    // Pre-scan: skip already-scanned (host, port) pairs.
    if use_resume && !resume_state.scanned.is_empty() {
        scanner.skip_pairs = resume_state.scanned.clone();
    }

    let mut results = scanner.run().await?;

    info!("scan complete — {} open ports found", results.len());

    // ── Verify pass (--verify) ───────────────────────────────────────────────
    if cli.verify && !results.is_empty() {
        if !cli.silent {
            eprintln!("[INFO] Verifying {} open ports...", results.len());
        }

        // Build synthetic targets and ports from the first-pass open results.
        // Each unique (ip, host) pair becomes a target; each open port becomes a
        // port to re-check.  We run a full second ConnectScanner and keep only
        // the intersection.
        use std::collections::HashMap;
        use crate::port::Port;

        // Deduplicate targets while preserving host label.
        let mut target_map: HashMap<std::net::IpAddr, target::Target> = HashMap::new();
        for r in &results {
            target_map.entry(r.ip).or_insert_with(|| target::Target {
                host: r.host.clone(),
                ip:   r.ip,
            });
        }
        let verify_targets: Vec<target::Target> = target_map.into_values().collect();

        // Deduplicate ports.
        let mut port_set: std::collections::HashSet<u16> = std::collections::HashSet::new();
        let verify_ports: Vec<Port> = results
            .iter()
            .filter_map(|r| {
                if port_set.insert(r.port.number) {
                    Some(r.port)
                } else {
                    None
                }
            })
            .collect();

        let verify_scanner = ConnectScanner::new(
            verify_targets,
            verify_ports,
            cli.rate,
            cli.workers,
            cli.timeout,
            cli.retries,
        );

        let verified = verify_scanner.run().await?;

        // Keep only results confirmed by the verify pass.
        let confirmed: std::collections::HashSet<(String, u16)> = verified
            .iter()
            .map(|r| (r.host.clone(), r.port.number))
            .collect();

        results.retain(|r| confirmed.contains(&(r.host.clone(), r.port.number)));

        if !cli.silent {
            eprintln!(
                "[INFO] Verify complete — {} port(s) confirmed open",
                results.len()
            );
        }
    }

    // ── Update resume state ──────────────────────────────────────────────────
    if use_resume {
        for t in &targets_for_resume {
            for p in &ports_for_resume {
                let key = format!("{}:{}", t.host, p.number);
                if !resume_state.scanned.contains(&key) {
                    resume_state.mark_scanned(&t.host, p.number);
                }
            }
        }
        for r in &results {
            resume_state.mark_open(&r.host, r.port.number);
        }

        if let Err(e) = resume_state.save(resume_path) {
            tracing::warn!("Could not save resume.json: {e}");
        }
        std::fs::remove_file(resume_path).ok();
    }

    // ── Output ───────────────────────────────────────────────────────────────
    let out_cfg = OutputConfig {
        json: cli.json,
        csv:  cli.csv,
        silent: cli.silent,
        output_file: cli.output.clone(),
        include_fields: cli.output_fields.clone(),
        exclude_fields: cli.exclude_output_fields.clone(),
    };

    write_results(&results, &out_cfg)?;

    Ok(())
}
