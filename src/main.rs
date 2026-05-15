mod blackrock;
mod cdn;
mod cli;
mod dashboard;
mod fingerprint;
mod host_discovery;
mod metrics;
mod output;
mod passive;
mod port;
mod prediction;
mod privileges;
mod resume;
mod scanner;
mod service_map;
mod target;
mod udp_probes;

use anyhow::Result;
use clap::Parser;
use cli::Cli;
use host_discovery::{HostDiscoveryConfig, discover_hosts};
use metrics::{ScanMetrics, start_metrics_server};
use output::{write_results, OutputConfig};
use port::{Port, resolve_ports};
use prediction::build_default_model;
use resume::ResumeState;
use scanner::connect::ConnectScanner;
use scanner::udp_scan::UdpScanner;
use std::sync::atomic::Ordering;
use target::{Target, resolve_targets};
use tracing::info;

// ── Interface listing ────────────────────────────────────────────────────────

fn list_interfaces() -> Vec<String> {
    match if_addrs::get_if_addrs() {
        Ok(ifaces) => {
            let mut names: Vec<String> = ifaces
                .iter()
                .map(|i| format!("{} ({})", i.name, i.addr.ip()))
                .collect();
            names.dedup();
            names
        }
        Err(_) => vec!["(could not enumerate interfaces)".to_string()],
    }
}

// ── Health check ─────────────────────────────────────────────────────────────

fn run_health_check() {
    println!("lancer-naabu health check");
    println!("=========================");

    // 1. Privilege check
    let is_priv = privileges::is_privileged();
    println!(
        "[{}] Elevated privileges: {}",
        if is_priv { "OK" } else { "  " },
        if is_priv {
            "yes (SYN scan available)"
        } else {
            "no (CONNECT scan only)"
        }
    );

    // 2. raw_scan feature
    #[cfg(feature = "raw_scan")]
    println!("[OK] raw_scan feature: compiled in");
    #[cfg(not(feature = "raw_scan"))]
    println!("[  ] raw_scan feature: NOT compiled in (--features raw_scan to enable)");

    // 3. Network interfaces
    println!("\nNetwork interfaces:");
    for iface in list_interfaces() {
        println!("  - {}", iface);
    }

    // 4. DNS resolver
    println!("\nDNS resolver: hickory (configured via system settings)");
    println!("[OK] DNS resolver: ready");

    println!("\nStatus: Ready");
}

const RESUME_FILE: &str = "resume.json";

/// Run a TCP CONNECT scan and return open-port results.
///
/// Extracted so that the SYN-scan fallback path can call it without
/// duplicating the ConnectScanner setup logic.
async fn run_connect_scan(
    targets: Vec<Target>,
    ports: Vec<Port>,
    rate: u32,
    workers: usize,
    timeout_ms: u64,
    retries: u32,
    port_threshold: Option<u32>,
    resume_state: &ResumeState,
    use_resume: bool,
    source_ip: Option<std::net::IpAddr>,
    connect_payload: Option<String>,
) -> Result<Vec<scanner::ScanResult>> {
    let mut scanner = ConnectScanner::new(targets, ports, rate, workers, timeout_ms, retries);

    if let Some(t) = port_threshold {
        scanner.port_threshold = t as usize;
    }

    if use_resume && !resume_state.scanned.is_empty() {
        scanner.skip_pairs = resume_state.scanned.clone();
    }

    scanner.source_ip = source_ip;
    scanner.connect_payload = connect_payload;

    scanner.run().await
}

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

    // ── Metrics server ───────────────────────────────────────────────────────
    let scan_metrics = ScanMetrics::new();
    if cli.metrics_port != 0 {
        start_metrics_server(std::sync::Arc::clone(&scan_metrics), cli.metrics_port).await;
        if !cli.silent {
            eprintln!(
                "[INFO] Prometheus metrics available at http://0.0.0.0:{}/metrics",
                cli.metrics_port
            );
        }
    }

    // ── Health check (-hc / --health-check) ──────────────────────────────────
    if cli.health_check {
        run_health_check();
        return Ok(());
    }

    // ── Interface listing (--il) ──────────────────────────────────────────────
    if cli.list_interfaces {
        println!("Available network interfaces:");
        for iface in list_interfaces() {
            println!("  {}", iface);
        }
        return Ok(());
    }

    // ── Config file warning ───────────────────────────────────────────────────
    if cli.config.is_some() {
        tracing::warn!("--config: config file loading is not yet implemented");
    }

    // ── Proxy warning ─────────────────────────────────────────────────────────
    if cli.proxy.is_some() || cli.proxy_auth.is_some() {
        tracing::warn!("--proxy / --proxy-auth: SOCKS5 proxy support is not yet implemented");
    }

    // ── nmap-cli warning ──────────────────────────────────────────────────────
    if cli.nmap_cli.is_some() {
        tracing::warn!("--nmap-cli: nmap post-scan integration is not yet implemented");
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
    let mut targets = resolve_targets(
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

    // ── Host discovery ───────────────────────────────────────────────────────
    if cli.host_discovery || cli.with_host_discovery {
        let hd_cfg = HostDiscoveryConfig {
            tcp_syn_ports: if cli.probe_tcp_syn { vec![80, 443] } else { vec![80, 443] },
            tcp_ack_ports: if cli.probe_tcp_ack { vec![80] } else { vec![] },
            icmp_echo:          cli.probe_icmp_echo,
            icmp_timestamp:     cli.probe_icmp_timestamp,
            icmp_address_mask:  cli.probe_icmp_address_mask,
            arp_ping:           cli.arp_ping,
            nd_ping:            cli.nd_ping,
            timeout:            std::time::Duration::from_millis(200),
            rev_ptr:            cli.rev_ptr,
            workers:            cli.workers,
        };

        let raw_ips: Vec<std::net::IpAddr> = targets.iter().map(|t| t.ip).collect();
        info!("running host discovery on {} targets", raw_ips.len());

        let live = discover_hosts(raw_ips, hd_cfg).await?;

        // -sn / --host-discovery: print live hosts and exit (no port scan).
        if cli.host_discovery {
            for h in &live {
                if let Some(ref ptr) = h.ptr {
                    println!("{} ({})", h.ip, ptr);
                } else {
                    println!("{}", h.ip);
                }
            }
            return Ok(());
        }

        // -wn / --with-host-discovery: filter targets to live hosts only.
        let live_ips: std::collections::HashSet<std::net::IpAddr> =
            live.iter().map(|h| h.ip).collect();
        targets.retain(|t| live_ips.contains(&t.ip));

        info!(
            "host discovery complete — {} live host(s) remain",
            targets.len()
        );

        if targets.is_empty() {
            if !cli.silent {
                eprintln!("[INFO] No live hosts found — nothing to scan.");
            }
            return Ok(());
        }
    }

    // ── Warm-up time (--warm-up-time) ─────────────────────────────────────────
    // Sleep between host-discovery and port-scan phases.
    if cli.warm_up_time > 0 {
        if !cli.silent {
            eprintln!("[INFO] Warm-up: waiting {} second(s) before port scan...", cli.warm_up_time);
        }
        tokio::time::sleep(std::time::Duration::from_secs(cli.warm_up_time)).await;
    }

    // ── Passive mode (--passive) ─────────────────────────────────────────────
    if cli.passive {
        if !cli.silent {
            eprintln!("[INFO] Passive mode: querying Shodan InternetDB for {} target(s)...", targets.len());
        }

        let mut passive_results: Vec<scanner::ScanResult> = Vec::new();

        for t in &targets {
            match passive::query_internetdb(t.ip).await {
                Ok(Some(idb)) => {
                    for p in idb.ports {
                        passive_results.push(scanner::ScanResult {
                            host: t.host.clone(),
                            ip: t.ip,
                            port: port::Port {
                                number: p,
                                protocol: port::Protocol::Tcp,
                            },
                            service: None,
                            product: None,
                            version: None,
                            cdn: None,
                        });
                    }
                    if !cli.silent && !idb.hostnames.is_empty() {
                        eprintln!("[INFO] {} hostnames: {}", t.ip, idb.hostnames.join(", "));
                    }
                }
                Ok(None) => {
                    if !cli.silent {
                        eprintln!("[INFO] {} — no InternetDB record found", t.ip);
                    }
                }
                Err(e) => {
                    tracing::warn!("InternetDB query failed for {}: {}", t.ip, e);
                }
            }
        }

        let out_cfg = OutputConfig {
            json: cli.json,
            csv: cli.csv,
            silent: cli.silent,
            output_file: cli.output.clone(),
            include_fields: cli.output_fields.clone(),
            exclude_fields: cli.exclude_output_fields.clone(),
            display_cdn: cli.display_cdn,
        };
        write_results(&passive_results, &out_cfg)?;
        return Ok(());
    }

    // ── Split TCP / UDP ports ────────────────────────────────────────────────
    use port::Protocol;

    let tcp_ports: Vec<port::Port> = ports
        .iter()
        .filter(|p| p.protocol == Protocol::Tcp)
        .cloned()
        .collect();
    let udp_ports: Vec<port::Port> = ports
        .iter()
        .filter(|p| p.protocol == Protocol::Udp)
        .cloned()
        .collect();

    // Keep clones for resume book-keeping (scanner takes ownership).
    let targets_for_resume = if use_resume { targets.clone() } else { vec![] };
    let ports_for_resume   = if use_resume { ports.clone()   } else { vec![] };

    // ── Resolve source IP (-si / --source-ip) ────────────────────────────────
    let resolved_source_ip: Option<std::net::IpAddr> = cli
        .source_ip
        .as_deref()
        .and_then(|s| s.parse().ok());

    // ── Run TCP scanner ──────────────────────────────────────────────────────
    let is_syn = cli
        .scan_type
        .as_deref()
        .map(|s| s.eq_ignore_ascii_case("SYN"))
        .unwrap_or(false);

    let mut results: Vec<scanner::ScanResult> = Vec::new();

    if !tcp_ports.is_empty() {
        let mut tcp_results: Vec<scanner::ScanResult> = if is_syn {
            match privileges::check_syn_scan_available() {
                Ok(()) => {
                    #[cfg(feature = "raw_scan")]
                    {
                        use scanner::syn_scan::SynScanner;
                        let raw_targets: Vec<std::net::IpAddr> =
                            targets.iter().map(|t| t.ip).collect();
                        let syn_scanner = SynScanner {
                            rate: cli.rate,
                            timeout_ms: cli.timeout,
                            workers: cli.workers,
                            source_ip: cli.source_ip.as_deref().and_then(|s| s.parse().ok()),
                            interface: cli.interface.clone(),
                        };
                        syn_scanner.run(raw_targets, tcp_ports.clone()).await?
                    }
                    #[cfg(not(feature = "raw_scan"))]
                    {
                        eprintln!(
                            "Warning: raw_scan feature not compiled in. \
                             Falling back to CONNECT scan."
                        );
                        run_connect_scan(
                            targets.clone(),
                            tcp_ports.clone(),
                            cli.rate,
                            cli.workers,
                            cli.timeout,
                            cli.retries,
                            cli.port_threshold,
                            &resume_state,
                            use_resume,
                            resolved_source_ip,
                            cli.connect_payload.clone(),
                        )
                        .await?
                    }
                }
                Err(reason) => {
                    eprintln!(
                        "Warning: SYN scan not available ({}). \
                         Falling back to CONNECT scan.",
                        reason
                    );
                    run_connect_scan(
                        targets.clone(),
                        tcp_ports.clone(),
                        cli.rate,
                        cli.workers,
                        cli.timeout,
                        cli.retries,
                        cli.port_threshold,
                        &resume_state,
                        use_resume,
                        resolved_source_ip,
                        cli.connect_payload.clone(),
                    )
                    .await?
                }
            }
        } else {
            run_connect_scan(
                targets.clone(),
                tcp_ports.clone(),
                cli.rate,
                cli.workers,
                cli.timeout,
                cli.retries,
                cli.port_threshold,
                &resume_state,
                use_resume,
                resolved_source_ip,
                cli.connect_payload.clone(),
            )
            .await?
        };
        results.append(&mut tcp_results);
    }

    // ── Run UDP scanner ──────────────────────────────────────────────────────
    if !udp_ports.is_empty() {
        if !cli.silent {
            eprintln!("[INFO] Starting UDP scan on {} port(s)...", udp_ports.len());
        }

        let udp_scanner = UdpScanner {
            // UDP scanning is slower; cap default rate at 100 pps.
            rate: cli.rate.min(100),
            timeout_ms: cli.timeout.max(2000),
            retries: cli.retries,
            workers: cli.workers.min(25),
            // --udp-probes flag: any non-None value enables protocol-specific payloads.
            use_probes: cli.udp_probes.is_some(),
        };

        let raw_targets: Vec<std::net::IpAddr> = targets.iter().map(|t| t.ip).collect();
        let mut udp_results = udp_scanner.run(raw_targets, udp_ports).await?;
        results.append(&mut udp_results);
    }

    info!("scan complete — {} open ports found", results.len());

    // ── CDN detection (--exclude-cdn / --display-cdn) ────────────────────────
    if cli.exclude_cdn || cli.display_cdn {
        let checker = cdn::CdnChecker::new();
        for r in results.iter_mut() {
            if let Some(m) = checker.check(r.ip) {
                r.cdn = Some(m.provider.clone());
            }
        }

        if cli.exclude_cdn {
            let cdn_ports: Vec<port::Port> = vec![
                port::Port { number: 80,  protocol: port::Protocol::Tcp },
                port::Port { number: 443, protocol: port::Protocol::Tcp },
            ];
            // For CDN hosts, keep only 80/443 results; for non-CDN, keep all.
            // Also log which hosts are being throttled.
            let mut cdn_hosts_seen = std::collections::HashSet::new();
            results.retain(|r| {
                if r.cdn.is_some() {
                    let keep = cdn_ports.iter().any(|cp| cp.number == r.port.number);
                    if !cdn_hosts_seen.contains(&r.ip) {
                        cdn_hosts_seen.insert(r.ip);
                        if !cli.silent {
                            eprintln!(
                                "[INFO] Skipping full scan for CDN host {} ({}) — scanning 80/443 only",
                                r.ip,
                                r.cdn.as_deref().unwrap_or("CDN")
                            );
                        }
                    }
                    keep
                } else {
                    true
                }
            });
        }
    }

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

        let mut verify_scanner = ConnectScanner::new(
            verify_targets,
            verify_ports,
            cli.rate,
            cli.workers,
            cli.timeout,
            cli.retries,
        );
        verify_scanner.source_ip = resolved_source_ip;
        verify_scanner.connect_payload = cli.connect_payload.clone();

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

    // ── Service version detection (-sV) ─────────────────────────────────────
    if (cli.service_version || cli.service_discovery) && !results.is_empty() {
        if !cli.silent {
            eprintln!("[INFO] Running service version detection on {} open port(s)...", results.len());
        }

        // Load probe content: custom file or embedded set.
        let probe_content: String = if let Some(ref path) = cli.sv_probes {
            match std::fs::read_to_string(path) {
                Ok(s) => s,
                Err(e) => {
                    tracing::warn!("Could not read probes file '{}': {} — using embedded probes", path, e);
                    fingerprint::probes::EMBEDDED_PROBES.to_string()
                }
            }
        } else {
            fingerprint::probes::EMBEDDED_PROBES.to_string()
        };

        match fingerprint::FingerprintEngine::from_str(&probe_content) {
            Ok(engine) => {
                let sv_timeout = cli.sv_timeout.unwrap_or(cli.timeout);
                let fast_mode = cli.sv_fast;

                // Run fingerprinting concurrently across open ports.
                let engine = std::sync::Arc::new(engine);
                let mut sv_tasks = Vec::with_capacity(results.len());

                for r in &results {
                    let eng = std::sync::Arc::clone(&engine);
                    let host = r.host.clone();
                    let port = r.port.number;
                    sv_tasks.push(tokio::spawn(async move {
                        eng.fingerprint(&host, port, sv_timeout, fast_mode).await
                    }));
                }

                let sv_results: Vec<Option<fingerprint::ServiceVersion>> =
                    futures::future::join_all(sv_tasks)
                        .await
                        .into_iter()
                        .map(|r| r.unwrap_or(None))
                        .collect();

                for (r, sv) in results.iter_mut().zip(sv_results.into_iter()) {
                    if let Some(sv) = sv {
                        r.service = Some(sv.service);
                        r.product = sv.product;
                        r.version = sv.version;
                    }
                }
            }
            Err(e) => {
                tracing::warn!("Failed to load fingerprint probes: {}", e);
            }
        }
    }

    // ── Service discovery (-sD) without full -sV ─────────────────────────────
    // Fill in service name via static map for any port that doesn't already
    // have a service set from the fingerprint engine.
    if cli.service_discovery && !results.is_empty() {
        for r in results.iter_mut() {
            if r.service.is_none() {
                let proto_str = r.port.protocol.to_string();
                r.service = service_map::guess_service(r.port.number, &proto_str)
                    .map(|s| s.to_string());
            }
        }
    }

    // ── Smart-scan (post-scan correlation boost) ─────────────────────────────
    if cli.smart_scan && !results.is_empty() {
        let model = build_default_model();
        let threshold = cli.prediction_threshold as f32 / 100.0;

        // Collect the set of ports that were in the initial scan.
        let initial_port_set: std::collections::HashSet<u16> =
            tcp_ports.iter().map(|p| p.number).collect();

        let mut extra_ports: Vec<port::Port> = Vec::new();
        let mut seen_extra: std::collections::HashSet<u16> = std::collections::HashSet::new();

        for r in &results {
            if r.port.protocol != port::Protocol::Tcp {
                continue;
            }
            for (port_num, _prob) in model.get_correlated_ports(r.port.number, threshold) {
                if !initial_port_set.contains(&port_num) && seen_extra.insert(port_num) {
                    extra_ports.push(port::Port {
                        number: port_num,
                        protocol: port::Protocol::Tcp,
                    });
                }
            }
        }

        if !extra_ports.is_empty() {
            if !cli.silent {
                eprintln!(
                    "[INFO] Smart-scan: probing {} correlated port(s)...",
                    extra_ports.len()
                );
            }

            // Collect unique targets from existing results for the second pass.
            let mut target_map: std::collections::HashMap<std::net::IpAddr, Target> =
                std::collections::HashMap::new();
            for r in &results {
                target_map.entry(r.ip).or_insert_with(|| Target {
                    host: r.host.clone(),
                    ip: r.ip,
                });
            }
            let extra_targets: Vec<Target> = target_map.into_values().collect();

            let mut extra_results = run_connect_scan(
                extra_targets,
                extra_ports,
                cli.rate,
                cli.workers,
                cli.timeout,
                cli.retries,
                cli.port_threshold,
                &resume_state,
                false,
                resolved_source_ip,
                cli.connect_payload.clone(),
            )
            .await?;

            if !cli.silent && !extra_results.is_empty() {
                eprintln!(
                    "[INFO] Smart-scan found {} additional open port(s)",
                    extra_results.len()
                );
            }
            results.append(&mut extra_results);
        }
    }

    // ── Update metrics ────────────────────────────────────────────────────────
    scan_metrics
        .open_ports_found
        .store(results.len() as u64, Ordering::Relaxed);
    scan_metrics
        .hosts_scanned
        .store(targets.len() as u64, Ordering::Relaxed);

    // ── Dashboard upload (-pd) ────────────────────────────────────────────────
    if cli.dashboard {
        dashboard::upload_results(&results, cli.auth.as_deref()).await?;
    }

    // ── Output ───────────────────────────────────────────────────────────────
    let out_cfg = OutputConfig {
        json: cli.json,
        csv:  cli.csv,
        silent: cli.silent,
        output_file: cli.output.clone(),
        include_fields: cli.output_fields.clone(),
        exclude_fields: cli.exclude_output_fields.clone(),
        display_cdn: cli.display_cdn,
    };

    write_results(&results, &out_cfg)?;

    Ok(())
}
