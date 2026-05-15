use crate::port::{Port, Protocol};
use crate::scanner::ScanResult;
use crate::target::Target;
use anyhow::Result;
use futures::stream::{self, StreamExt};
use governor::{Quota, RateLimiter};
use governor::clock::DefaultClock;
use governor::state::{InMemoryState, NotKeyed};
use std::collections::HashSet;
use std::net::IpAddr;
use std::num::NonZeroU32;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio::time::Duration;
use tracing::debug;

type DirectLimiter = RateLimiter<NotKeyed, InMemoryState, DefaultClock>;

pub struct ConnectScanner {
    targets: Vec<Target>,
    ports: Vec<Port>,
    rate: u32,
    workers: usize,
    timeout_ms: u64,
    retries: u32,
    pub skip_pairs: HashSet<String>,
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
        Self { targets, ports, rate, workers, timeout_ms, retries, skip_pairs: HashSet::new() }
    }

    pub async fn run(self) -> Result<Vec<ScanResult>> {
        // Destructure self up-front so we can move fields independently.
        let Self { targets, ports, rate, workers, timeout_ms, retries, skip_pairs } = self;

        // Warn if any UDP ports were requested — they are not supported in CONNECT mode.
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

        // Build a flat list of (ip, host_label, port) pairs — only TCP, minus already-scanned.
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

        // Process with bounded concurrency: at most `workers` futures in flight.
        let mut open_ports: Vec<ScanResult> = stream::iter(scan_pairs)
            .map(|(ip, host, port)| {
                let limiter = Arc::clone(&limiter);
                async move {
                    let addr = std::net::SocketAddr::new(ip, port.number);
                    for attempt in 0..=retries {
                        // Consume a rate-limiter token immediately before each attempt.
                        limiter.until_ready().await;

                        match tokio::time::timeout(
                            Duration::from_millis(timeout_ms),
                            TcpStream::connect(addr),
                        )
                        .await
                        {
                            Ok(Ok(_)) => {
                                debug!("open  {}:{}", host, port.number);
                                return Some(ScanResult { host, ip, port });
                            }
                            Ok(Err(e)) => {
                                // Connection refused / unreachable — no point retrying.
                                debug!("closed {}:{} — {}", host, port.number, e);
                                return None;
                            }
                            Err(_elapsed) => {
                                // Timeout — retry if attempts remain.
                                if attempt < retries {
                                    tracing::warn!(
                                        "timeout {}:{} attempt {}/{}",
                                        host,
                                        port.number,
                                        attempt + 1,
                                        retries
                                    );
                                } else {
                                    debug!(
                                        "timeout {}:{} after {} retries",
                                        host, port.number, retries
                                    );
                                    return None;
                                }
                            }
                        }
                    }
                    None
                }
            })
            .buffer_unordered(workers) // only `workers` futures in flight at once
            .filter_map(|r| async move { r })
            .collect()
            .await;

        // Sort for deterministic output.
        open_ports.sort_by(|a, b| {
            a.host
                .cmp(&b.host)
                .then(a.ip.cmp(&b.ip))
                .then(a.port.number.cmp(&b.port.number))
        });

        Ok(open_ports)
    }
}
