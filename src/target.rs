use anyhow::{Context, Result};
use hickory_resolver::TokioAsyncResolver;
use hickory_resolver::config::{ResolverConfig, ResolverOpts};
use ipnet::{Ipv4Net, Ipv6Net};
use std::collections::HashSet;
use std::net::IpAddr;
use std::str::FromStr;
use tokio::io::{AsyncBufReadExt, BufReader};

/// A resolved scan target — always a concrete IP address.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Target {
    /// Display name (original hostname or IP string)
    pub host: String,
    pub ip: IpAddr,
}

impl std::fmt::Display for Target {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.host)
    }
}

async fn build_resolver() -> Result<TokioAsyncResolver> {
    let resolver = TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default());
    Ok(resolver)
}

/// Expand a single target string into one or more `Target`s.
///
/// Handles:
///  - IPv4 literal
///  - IPv6 literal
///  - IPv4 CIDR  (e.g. `192.168.1.0/24`)
///  - IPv6 CIDR
///  - Hostname   (resolved via DNS)
async fn expand_single(
    s: &str,
    resolver: &TokioAsyncResolver,
    scan_all_ips: bool,
) -> Result<Vec<Target>> {
    let s = s.trim();
    if s.is_empty() {
        return Ok(vec![]);
    }

    // IPv4 literal?
    if let Ok(ip) = s.parse::<std::net::Ipv4Addr>() {
        return Ok(vec![Target { host: s.to_string(), ip: IpAddr::V4(ip) }]);
    }

    // IPv6 literal?
    if let Ok(ip) = s.parse::<std::net::Ipv6Addr>() {
        return Ok(vec![Target { host: s.to_string(), ip: IpAddr::V6(ip) }]);
    }

    // IPv4 CIDR?
    if let Ok(net) = Ipv4Net::from_str(s) {
        let targets = net
            .hosts()
            .map(|ip| Target { host: ip.to_string(), ip: IpAddr::V4(ip) })
            .collect();
        return Ok(targets);
    }

    // IPv6 CIDR?
    if let Ok(net) = Ipv6Net::from_str(s) {
        // Ipv6Net::hosts() is an iterator but can be huge — cap at a reasonable size
        let targets = net
            .hosts()
            .take(65536)
            .map(|ip| Target { host: ip.to_string(), ip: IpAddr::V6(ip) })
            .collect();
        return Ok(targets);
    }

    // Fall back to hostname resolution
    let lookup = resolver
        .lookup_ip(s)
        .await
        .with_context(|| format!("DNS resolution failed for '{s}'"))?;

    let addrs: Vec<IpAddr> = lookup.iter().collect();
    if addrs.is_empty() {
        return Ok(vec![]);
    }

    if scan_all_ips {
        Ok(addrs
            .into_iter()
            .map(|ip| Target { host: s.to_string(), ip })
            .collect())
    } else {
        Ok(vec![Target { host: s.to_string(), ip: addrs[0] }])
    }
}

/// Parse the exclude-host / exclude-file options into a set of IPs to skip.
async fn build_exclusion_set(
    exclude_host: Option<&str>,
    exclude_file: Option<&str>,
    resolver: &TokioAsyncResolver,
) -> Result<HashSet<IpAddr>> {
    let mut excl = HashSet::new();

    if let Some(eh) = exclude_host {
        for part in eh.split(',') {
            let targets = expand_single(part.trim(), resolver, true).await?;
            for t in targets {
                excl.insert(t.ip);
            }
        }
    }

    if let Some(ef) = exclude_file {
        let content = tokio::fs::read_to_string(ef)
            .await
            .with_context(|| format!("reading exclude-file: {ef}"))?;
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let targets = expand_single(line, resolver, true).await?;
            for t in targets {
                excl.insert(t.ip);
            }
        }
    }

    Ok(excl)
}

/// Main entry point: resolve all CLI inputs into a deduplicated list of targets.
pub async fn resolve_targets(
    host: Option<&str>,
    list: Option<&str>,
    no_stdin: bool,
    exclude_host: Option<&str>,
    exclude_file: Option<&str>,
    scan_all_ips: bool,
    input_read_timeout_secs: u64,
) -> Result<Vec<Target>> {
    let resolver = build_resolver().await?;

    let exclusions = build_exclusion_set(exclude_host, exclude_file, &resolver).await?;

    let mut seen_ips: HashSet<IpAddr> = HashSet::new();
    let mut targets: Vec<Target> = Vec::new();

    let mut add = |t: Target, seen: &mut HashSet<IpAddr>, excl: &HashSet<IpAddr>| {
        if !excl.contains(&t.ip) && seen.insert(t.ip) {
            targets.push(t);
        }
    };

    // -host flag (comma-separated)
    if let Some(h) = host {
        for part in h.split(',') {
            let expanded = expand_single(part.trim(), &resolver, scan_all_ips).await?;
            for t in expanded {
                add(t, &mut seen_ips, &exclusions);
            }
        }
    }

    // -list file
    if let Some(lf) = list {
        let content = tokio::fs::read_to_string(lf)
            .await
            .with_context(|| format!("reading list file: {lf}"))?;
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let expanded = expand_single(line, &resolver, scan_all_ips).await?;
            for t in expanded {
                add(t, &mut seen_ips, &exclusions);
            }
        }
    }

    // stdin (unless -no-stdin or a tty / data already provided via flags)
    if !no_stdin && host.is_none() && list.is_none() {
        use tokio::time::{timeout, Duration};
        let stdin = tokio::io::stdin();
        let mut reader = BufReader::new(stdin).lines();
        let deadline = Duration::from_secs(input_read_timeout_secs);
        loop {
            match timeout(deadline, reader.next_line()).await {
                Ok(Ok(Some(line))) => {
                    let line = line.trim().to_string();
                    if line.is_empty() || line.starts_with('#') {
                        continue;
                    }
                    let expanded = expand_single(&line, &resolver, scan_all_ips).await?;
                    for t in expanded {
                        add(t, &mut seen_ips, &exclusions);
                    }
                }
                Ok(Ok(None)) => break, // EOF
                Ok(Err(e)) => {
                    tracing::warn!("stdin read error: {e}");
                    break;
                }
                Err(_) => break, // timeout
            }
        }
    }

    Ok(targets)
}
