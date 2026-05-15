use crate::port::{Port, Protocol};
use crate::scanner::ScanResult;
use crate::target::Target;
use anyhow::Result;
use governor::{Quota, RateLimiter};
use governor::clock::DefaultClock;
use governor::state::{InMemoryState, NotKeyed};
use std::num::NonZeroU32;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tokio::time::{timeout, Duration};
use tracing::{debug, warn};

type DirectLimiter = RateLimiter<NotKeyed, InMemoryState, DefaultClock>;

pub struct ConnectScanner {
    targets: Vec<Target>,
    ports: Vec<Port>,
    rate: u32,
    workers: usize,
    timeout_ms: u64,
    retries: u32,
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
        Self { targets, ports, rate, workers, timeout_ms, retries }
    }

    pub async fn run(self) -> Result<Vec<ScanResult>> {
        let rate = self.rate.max(1);
        let quota = Quota::per_second(NonZeroU32::new(rate).unwrap());
        let limiter: Arc<DirectLimiter> = Arc::new(RateLimiter::direct(quota));
        let semaphore = Arc::new(Semaphore::new(self.workers));
        let timeout_ms = self.timeout_ms;
        let retries = self.retries;

        let mut set: JoinSet<Option<ScanResult>> = JoinSet::new();

        for target in &self.targets {
            for port in &self.ports {
                // Only TCP connect is supported; skip UDP ports silently
                if port.protocol != Protocol::Tcp {
                    continue;
                }

                let limiter = Arc::clone(&limiter);
                let sem = Arc::clone(&semaphore);
                let host = target.host.clone();
                let ip = target.ip;
                let port = *port;

                set.spawn(async move {
                    // Rate-limit before acquiring the semaphore slot
                    limiter.until_ready().await;

                    let _permit = sem.acquire().await.expect("semaphore closed");

                    let addr = std::net::SocketAddr::new(ip, port.number);
                    let mut attempt = 0u32;
                    loop {
                        let connect_future = TcpStream::connect(addr);
                        match timeout(Duration::from_millis(timeout_ms), connect_future).await {
                            Ok(Ok(_stream)) => {
                                debug!("open  {}:{}", host, port.number);
                                return Some(ScanResult { host, ip, port });
                            }
                            Ok(Err(e)) => {
                                // Connection refused / unreachable — no retry needed
                                debug!("closed {}:{} — {}", host, port.number, e);
                                return None;
                            }
                            Err(_elapsed) => {
                                // Timeout — retry if attempts remain
                                attempt += 1;
                                if attempt > retries {
                                    debug!("timeout {}:{} after {} retries", host, port.number, retries);
                                    return None;
                                }
                                warn!("timeout {}:{} attempt {}/{}", host, port.number, attempt, retries);
                            }
                        }
                    }
                });
            }
        }

        let mut open_ports = Vec::new();
        while let Some(res) = set.join_next().await {
            match res {
                Ok(Some(r)) => open_ports.push(r),
                Ok(None) => {}
                Err(e) => warn!("task panicked: {e}"),
            }
        }

        // Sort for deterministic output
        open_ports.sort_by(|a, b| {
            a.host.cmp(&b.host)
                .then(a.ip.cmp(&b.ip))
                .then(a.port.number.cmp(&b.port.number))
        });

        Ok(open_ports)
    }
}
