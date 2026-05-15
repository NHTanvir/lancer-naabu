use crate::port::{Port, Protocol};
use crate::scanner::ScanResult;
use crate::target::Target;
use anyhow::Result;
use dashmap::DashMap;
use futures::stream::{self, StreamExt};
use governor::{Quota, RateLimiter};
use governor::clock::DefaultClock;
use governor::state::{InMemoryState, NotKeyed};
use std::collections::HashSet;
use std::net::IpAddr;
use std::num::NonZeroU32;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio::time::Duration;
use tracing::debug;

type DirectLimiter = RateLimiter<NotKeyed, InMemoryState, DefaultClock>;

/// Consecutive HostUnreachable/NetworkUnreachable errors before we abandon a host.
const HOST_UNREACH_THRESHOLD: usize = 3;

pub struct ConnectScanner {
    targets: Vec<Target>,
    ports: Vec<Port>,
    rate: u32,
    workers: usize,
    timeout_ms: u64,
    retries: u32,
    pub skip_pairs: HashSet<String>,
    /// Per-host rate limiting — reserved for future use.
    #[allow(dead_code)]
    per_host_rate: Option<u32>,
    /// Stop scanning a host once this many open ports are found (0 = disabled).
    pub port_threshold: usize,
}

impl ConnectScanner {
    pub fn new(
        targets: Vec<Target>,
        ports: Vec<Port>,
        rate: u32,
        workers: usize,
        timeout_ms: u64,
        retries: u32,
    ) -> Self {
        Self {
            targets,
            ports,
            rate,
            workers,
            timeout_ms,
            retries,
            skip_pairs: HashSet::new(),
            per_host_rate: None,
            port_threshold: 0,
        }
    }

    pub async fn run(self) -> Result<Vec<ScanResult>> {
        let Self {
            targets,
            ports,
            rate,
            workers,
            timeout_ms,
            retries,
            skip_pairs,
            per_host_rate: _,
            port_threshold,
        } = self;

        let udp_count = ports.iter().filter(|p| p.protocol == Protocol::Udp).count();
        if udp_count > 0 {
            tracing::warn!(
                "{} UDP port(s) skipped (UDP not supported in CONNECT scan mode)",
                udp_count
            );
        }

        let rate = rate.max(1);
        let quota = Quota::per_second(NonZeroU32::new(rate).unwrap());
        let limiter: Arc<DirectLimiter> = Arc::new(RateLimiter::direct(quota));

        // Per-host open-port slot counter.
        // We use Arc<AtomicUsize> per host so we can do fetch_add atomically.
        // Claim a slot before connecting; release (fetch_sub) if the port is closed.
        let open_counts: Arc<DashMap<IpAddr, Arc<AtomicUsize>>> = Arc::new(DashMap::new());

        // Per-host consecutive unreachable-error counters (adaptive backoff).
        let err_counts: Arc<DashMap<IpAddr, Arc<AtomicUsize>>> = Arc::new(DashMap::new());

        // Build flat list of (ip, host_label, port) — TCP only, minus already-scanned.
        let scan_pairs: Vec<(IpAddr, String, Port)> = targets
            .iter()
            .flat_map(|t| {
                let ip = t.ip;
                let host = t.host.clone();
                ports.iter().filter_map({
                    let skip = &skip_pairs;
                    move |p| {
                        if p.protocol != Protocol::Tcp {
                            return None;
                        }
                        if skip.contains(&format!("{}:{}", host, p.number)) {
                            return None;
                        }
                        Some((ip, host.clone(), *p))
                    }
                })
            })
            .collect();

        // Helper: get-or-create an Arc<AtomicUsize> from a DashMap.
        // We inline this inline where needed — see closures below.

        let mut open_ports: Vec<ScanResult> = stream::iter(scan_pairs)
            .map(|(ip, host, port)| {
                let limiter      = Arc::clone(&limiter);
                let open_counts  = Arc::clone(&open_counts);
                let err_counts   = Arc::clone(&err_counts);
                async move {
                    // ── Adaptive backoff guard ───────────────────────────────
                    {
                        let errs = err_counts
                            .get(&ip)
                            .map(|v| v.load(Ordering::Relaxed))
                            .unwrap_or(0);
                        if errs > HOST_UNREACH_THRESHOLD {
                            debug!(
                                "host {} unreachable (>{} errors) — skipping port {}",
                                ip, HOST_UNREACH_THRESHOLD, port.number
                            );
                            return None;
                        }
                    }

                    // ── Port-threshold: claim a slot atomically ──────────────
                    // We fetch_add(1) first. If the *previous* value was already
                    // >= threshold we release the slot immediately and skip.
                    let slot_counter: Option<Arc<AtomicUsize>> = if port_threshold > 0 {
                        let counter = open_counts
                            .entry(ip)
                            .or_insert_with(|| Arc::new(AtomicUsize::new(0)))
                            .clone();
                        let prev = counter.fetch_add(1, Ordering::AcqRel);
                        if prev >= port_threshold {
                            // Release: we over-claimed, put the slot back.
                            counter.fetch_sub(1, Ordering::AcqRel);
                            debug!(
                                "threshold reached for {} — skipping port {}",
                                ip, port.number
                            );
                            return None;
                        }
                        // Hold the counter so we can release on non-open result.
                        Some(counter)
                    } else {
                        None
                    };

                    let addr = std::net::SocketAddr::new(ip, port.number);

                    for attempt in 0..=retries {
                        limiter.until_ready().await;

                        match tokio::time::timeout(
                            Duration::from_millis(timeout_ms),
                            TcpStream::connect(addr),
                        )
                        .await
                        {
                            // ── Open ─────────────────────────────────────────
                            Ok(Ok(_)) => {
                                debug!("open  {}:{}", host, port.number);
                                // Reset error counter for this host.
                                if let Some(c) = err_counts.get(&ip) {
                                    c.store(0, Ordering::Relaxed);
                                }
                                // Slot was already claimed; just keep it.
                                return Some(ScanResult { host, ip, port, service: None, product: None, version: None });
                            }

                            // ── Connect error ─────────────────────────────────
                            Ok(Err(e)) => {
                                use std::io::ErrorKind;
                                match e.kind() {
                                    // Definitively closed — never retry.
                                    ErrorKind::ConnectionRefused => {
                                        debug!("refused {}:{}", host, port.number);
                                        if let Some(ref c) = slot_counter {
                                            c.fetch_sub(1, Ordering::AcqRel);
                                        }
                                        return None;
                                    }

                                    // Host/network unreachable — bump error
                                    // counter; never retry.
                                    ErrorKind::HostUnreachable
                                    | ErrorKind::NetworkUnreachable => {
                                        let counter = err_counts
                                            .entry(ip)
                                            .or_insert_with(|| Arc::new(AtomicUsize::new(0)))
                                            .clone();
                                        let prev = counter.fetch_add(1, Ordering::AcqRel);
                                        if prev + 1 > HOST_UNREACH_THRESHOLD {
                                            tracing::warn!(
                                                "host {} unreachable {} times — \
                                                 skipping remaining ports",
                                                ip,
                                                prev + 1
                                            );
                                        } else {
                                            debug!(
                                                "unreachable {}:{} — no retry",
                                                host, port.number
                                            );
                                        }
                                        if let Some(ref c) = slot_counter {
                                            c.fetch_sub(1, Ordering::AcqRel);
                                        }
                                        return None;
                                    }

                                    // Transient reset — retry once.
                                    ErrorKind::ConnectionReset => {
                                        if attempt < retries {
                                            tracing::warn!(
                                                "reset {}:{} attempt {}/{} — retrying",
                                                host, port.number, attempt + 1, retries
                                            );
                                            continue;
                                        }
                                        debug!(
                                            "reset {}:{} after {} retries",
                                            host, port.number, retries
                                        );
                                        if let Some(ref c) = slot_counter {
                                            c.fetch_sub(1, Ordering::AcqRel);
                                        }
                                        return None;
                                    }

                                    // Any other error — no retry.
                                    _ => {
                                        debug!("closed {}:{} — {}", host, port.number, e);
                                        if let Some(ref c) = slot_counter {
                                            c.fetch_sub(1, Ordering::AcqRel);
                                        }
                                        return None;
                                    }
                                }
                            }

                            // ── Timeout — retry up to `retries` times ────────
                            Err(_elapsed) => {
                                if attempt < retries {
                                    tracing::warn!(
                                        "timeout {}:{} attempt {}/{}",
                                        host, port.number, attempt + 1, retries
                                    );
                                } else {
                                    debug!(
                                        "timeout {}:{} after {} retries",
                                        host, port.number, retries
                                    );
                                    if let Some(ref c) = slot_counter {
                                        c.fetch_sub(1, Ordering::AcqRel);
                                    }
                                    return None;
                                }
                            }
                        }
                    }
                    if let Some(ref c) = slot_counter {
                        c.fetch_sub(1, Ordering::AcqRel);
                    }
                    None
                }
            })
            .buffer_unordered(workers)
            .filter_map(|r| async move { r })
            .collect()
            .await;

        open_ports.sort_by(|a, b| {
            a.host
                .cmp(&b.host)
                .then(a.ip.cmp(&b.ip))
                .then(a.port.number.cmp(&b.port.number))
        });

        Ok(open_ports)
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::port::Protocol;
    use crate::target::Target;
    use std::net::{IpAddr, Ipv4Addr};

    fn make_target(ip: [u8; 4]) -> Target {
        let ip = IpAddr::V4(Ipv4Addr::new(ip[0], ip[1], ip[2], ip[3]));
        Target { host: ip.to_string(), ip }
    }

    fn tcp_port(n: u16) -> Port {
        Port { number: n, protocol: Protocol::Tcp }
    }

    // ── Port-threshold: at most N open ports reported per host ────────────────
    //
    // Bind 6 real listeners; set threshold to 3; expect <= 3 results.
    #[tokio::test]
    async fn test_port_threshold_stops_at_n() {
        use tokio::net::TcpListener;

        let mut listeners = Vec::new();
        let mut port_nums = Vec::new();
        for _ in 0..6 {
            let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
            port_nums.push(l.local_addr().unwrap().port());
            listeners.push(l);
        }
        // Keep listeners alive in the background.
        for l in listeners {
            tokio::spawn(async move {
                loop { let _ = l.accept().await; }
            });
        }

        let threshold = 3usize;
        let ports: Vec<Port> = port_nums.iter().map(|&n| tcp_port(n)).collect();
        let targets = vec![make_target([127, 0, 0, 1])];

        let mut scanner = ConnectScanner::new(targets, ports, 10000, 6, 500, 0);
        scanner.port_threshold = threshold;

        let results = scanner.run().await.unwrap();

        assert!(
            results.len() <= threshold,
            "expected at most {} open ports, got {}",
            threshold, results.len()
        );
    }

    // ── Port-threshold disabled: all open ports returned ─────────────────────
    #[tokio::test]
    async fn test_port_threshold_zero_means_no_limit() {
        use tokio::net::TcpListener;

        let mut listeners = Vec::new();
        let mut port_nums = Vec::new();
        for _ in 0..4 {
            let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
            port_nums.push(l.local_addr().unwrap().port());
            listeners.push(l);
        }
        for l in listeners {
            tokio::spawn(async move {
                loop { let _ = l.accept().await; }
            });
        }

        let ports: Vec<Port> = port_nums.iter().map(|&n| tcp_port(n)).collect();
        let n = ports.len();
        let targets = vec![make_target([127, 0, 0, 1])];

        let mut scanner = ConnectScanner::new(targets, ports, 10000, 6, 500, 0);
        scanner.port_threshold = 0;

        let results = scanner.run().await.unwrap();
        assert_eq!(results.len(), n, "with threshold=0 all {n} open ports should be returned");
    }

    // ── Retry logic (integration-only note) ───────────────────────────────────
    //
    // ECONNREFUSED → no retry: scan a port with no listener → closed immediately.
    // Timeout     → retry: requires artificial latency (e.g. `tc netem delay`).
    // ECONNRESET  → retry once: requires a peer that sends RST.
    //
    // These branches are tested via manual/integration QA, not unit tests, because
    // they require real or simulated network conditions beyond in-process mocking.
}
