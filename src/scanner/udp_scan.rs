use crate::port::{Port, Protocol};
use crate::scanner::ScanResult;
use crate::udp_probes::get_probe_payload;
use anyhow::Result;
use futures::stream::{self, StreamExt};
use governor::clock::DefaultClock;
use governor::state::{InMemoryState, NotKeyed};
use governor::{Quota, RateLimiter};
use std::net::{IpAddr, UdpSocket};
use std::num::NonZeroU32;
use std::sync::Arc;
use std::time::Duration;
use tracing::debug;

type DirectLimiter = RateLimiter<NotKeyed, InMemoryState, DefaultClock>;

/// Result of probing a single UDP port.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UdpStatus {
    /// Received a UDP response — port is definitively open.
    Open,
    /// Timed out or other non-ICMP error — port is open|filtered.
    OpenFiltered,
    /// ICMP Port Unreachable received (ConnectionRefused on Windows) — port is closed.
    Closed,
}

/// Probe a single UDP port synchronously.
///
/// # Behaviour
/// - Sends `payload` (may be empty) to `target:port`.
/// - Waits up to `timeout_ms` milliseconds for a reply on the same socket.
/// - `Ok(_)` on recv  → [`UdpStatus::Open`]
/// - `WouldBlock` / `TimedOut` → [`UdpStatus::OpenFiltered`] (no ICMP back)
/// - `ConnectionRefused`       → [`UdpStatus::Closed`]   (ICMP port unreach / WSAECONNRESET)
/// - Any other error           → [`UdpStatus::OpenFiltered`]
pub fn probe_udp_port(target: IpAddr, port: u16, payload: &[u8], timeout_ms: u64) -> UdpStatus {
    let socket = match UdpSocket::bind("0.0.0.0:0") {
        Ok(s) => s,
        Err(e) => {
            debug!("udp bind failed for {}:{} — {}", target, port, e);
            return UdpStatus::OpenFiltered;
        }
    };

    if let Err(e) = socket.set_read_timeout(Some(Duration::from_millis(timeout_ms))) {
        debug!("set_read_timeout failed for {}:{} — {}", target, port, e);
        return UdpStatus::OpenFiltered;
    }

    let addr = format!("{}:{}", target, port);
    if let Err(e) = socket.send_to(payload, &addr) {
        debug!("udp send_to {}:{} failed — {}", target, port, e);
        return UdpStatus::OpenFiltered;
    }

    let mut buf = [0u8; 4096];
    match socket.recv_from(&mut buf) {
        Ok(_) => {
            debug!("udp open (response) {}:{}", target, port);
            UdpStatus::Open
        }
        Err(e) => {
            use std::io::ErrorKind;
            match e.kind() {
                // Timeout / no ICMP received → open|filtered
                ErrorKind::WouldBlock | ErrorKind::TimedOut => {
                    debug!("udp open|filtered (timeout) {}:{}", target, port);
                    UdpStatus::OpenFiltered
                }
                // ICMP Port Unreachable manifests as ConnectionRefused on Windows
                // (WSAECONNRESET) and on some Linux stacks as well.
                ErrorKind::ConnectionRefused => {
                    debug!("udp closed (icmp port unreach) {}:{}", target, port);
                    UdpStatus::Closed
                }
                _ => {
                    debug!("udp open|filtered (other error: {}) {}:{}", e, target, port);
                    UdpStatus::OpenFiltered
                }
            }
        }
    }
}

pub struct UdpScanner {
    pub rate: u32,
    /// Receive timeout per probe attempt (default 2000 ms).
    pub timeout_ms: u64,
    /// Number of retries on OpenFiltered result (default 3).
    pub retries: u32,
    pub workers: usize,
    /// Send protocol-specific probe payloads when true.
    pub use_probes: bool,
}

impl UdpScanner {
    /// Scan all `targets × ports` (UDP only) and return open / open|filtered results.
    ///
    /// Closed ports are silently discarded (same semantics as naabu).
    /// OpenFiltered is treated as open (false negative is worse than false positive
    /// for a scanner).
    pub async fn run(
        &self,
        targets: Vec<IpAddr>,
        ports: Vec<Port>,
    ) -> Result<Vec<ScanResult>> {
        let rate = self.rate.max(1);
        let quota = Quota::per_second(NonZeroU32::new(rate).unwrap());
        let limiter: Arc<DirectLimiter> = Arc::new(RateLimiter::direct(quota));

        let timeout_ms = self.timeout_ms;
        let retries = self.retries;
        let use_probes = self.use_probes;

        // Build flat list of (ip, host_label, port) — UDP ports only.
        let scan_pairs: Vec<(IpAddr, String, Port)> = targets
            .iter()
            .flat_map(|ip| {
                let ip_str = ip.to_string();
                ports.iter().filter_map({
                    let ip_str = ip_str.clone();
                    let ip = *ip;
                    move |p| {
                        if p.protocol != Protocol::Udp {
                            return None;
                        }
                        Some((ip, ip_str.clone(), *p))
                    }
                })
            })
            .collect();

        let mut results: Vec<ScanResult> = stream::iter(scan_pairs)
            .map(|(ip, host, port)| {
                let limiter = Arc::clone(&limiter);
                async move {
                    limiter.until_ready().await;

                    // Pick probe payload.
                    let payload: &[u8] = if use_probes {
                        get_probe_payload(port.number)
                    } else {
                        b""
                    };

                    // Run blocking probe on a thread-pool thread so we don't block
                    // the async executor.
                    let port_num = port.number;
                    let payload_owned: Vec<u8> = payload.to_vec();

                    let status = tokio::task::spawn_blocking(move || {
                        // Retry loop: only retry OpenFiltered (timeout).
                        let mut last = UdpStatus::OpenFiltered;
                        for attempt in 0..=retries {
                            let s = probe_udp_port(ip, port_num, &payload_owned, timeout_ms);
                            match &s {
                                UdpStatus::Open | UdpStatus::Closed => {
                                    // Definitive answer — stop immediately.
                                    return s;
                                }
                                UdpStatus::OpenFiltered => {
                                    last = s;
                                    if attempt < retries {
                                        debug!(
                                            "udp {}:{} open|filtered attempt {}/{} — retrying",
                                            ip, port_num, attempt + 1, retries
                                        );
                                    }
                                }
                            }
                        }
                        last
                    })
                    .await;

                    match status {
                        Ok(UdpStatus::Open) | Ok(UdpStatus::OpenFiltered) => {
                            debug!("udp reporting open {}:{}", host, port.number);
                            Some(ScanResult { host, ip, port, service: None, product: None, version: None, cdn: None })
                        }
                        Ok(UdpStatus::Closed) => None,
                        Err(e) => {
                            debug!("udp spawn_blocking error {}:{} — {}", host, port.number, e);
                            // Treat spawn failure as open|filtered (conservative).
                            Some(ScanResult { host, ip, port, service: None, product: None, version: None, cdn: None })
                        }
                    }
                }
            })
            .buffer_unordered(self.workers)
            .filter_map(|r| async move { r })
            .collect()
            .await;

        results.sort_by(|a, b| {
            a.host
                .cmp(&b.host)
                .then(a.ip.cmp(&b.ip))
                .then(a.port.number.cmp(&b.port.number))
        });

        Ok(results)
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::port::Protocol;
    use std::net::{IpAddr, Ipv4Addr};

    fn udp_port(n: u16) -> Port {
        Port { number: n, protocol: Protocol::Udp }
    }

    #[tokio::test]
    async fn udp_scanner_does_not_panic_on_localhost() {
        let scanner = UdpScanner {
            rate: 100,
            timeout_ms: 500, // short for tests
            retries: 1,
            workers: 4,
            use_probes: false,
        };

        let targets = vec![IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))];
        // Port 9 (discard) — likely no listener, but should not panic.
        let ports = vec![udp_port(9)];

        let result = scanner.run(targets, ports).await;
        assert!(result.is_ok(), "UdpScanner::run should not return Err");
    }

    #[tokio::test]
    async fn udp_scanner_with_probes_does_not_panic() {
        let scanner = UdpScanner {
            rate: 100,
            timeout_ms: 500,
            retries: 1,
            workers: 4,
            use_probes: true,
        };

        let targets = vec![IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))];
        let ports = vec![udp_port(53), udp_port(161)];

        let result = scanner.run(targets, ports).await;
        assert!(result.is_ok());
    }

    #[test]
    fn probe_closed_port_returns_closed_or_filtered() {
        // Probe a port number that should be closed on localhost.
        // We can't guarantee ICMP will be returned, so we just check it doesn't panic.
        let status = probe_udp_port(
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            19999, // very likely nothing is listening
            b"",
            300,
        );
        // Status must be one of the three variants — just ensure no panic.
        let _: UdpStatus = status;
    }
}
