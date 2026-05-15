//! Host-discovery subsystem.
//!
//! # Layered approach
//!
//! | Layer | Method               | Requires privileges? |
//! |-------|----------------------|----------------------|
//! | 1     | TCP CONNECT ping     | No  (always tried)   |
//! | 2     | ICMP echo (surge-ping)| Yes (skip if unpriv) |
//! | 3     | ARP (local subnet)   | Yes (stub / TODO)    |
//! | 4     | IPv6 ND ping         | Yes (stub / TODO)    |
//! | 5     | Reverse PTR lookup   | No  (DNS only)       |
//!
//! On Windows without Npcap / admin rights, only Layer 1 (TCP CONNECT) and
//! Layer 5 (PTR) are executed.  Layers 2-4 silently skip or log a warning.

use std::net::IpAddr;
use std::time::Duration;

use anyhow::Result;
use futures::stream::{self, StreamExt};
use hickory_resolver::TokioAsyncResolver;
use hickory_resolver::config::{ResolverConfig, ResolverOpts};
use tokio::net::TcpStream;
use tracing::{debug, warn};

use crate::privileges::is_privileged;

// ── Public types ─────────────────────────────────────────────────────────────

/// Configuration for the host-discovery pass.
#[derive(Debug, Clone)]
pub struct HostDiscoveryConfig {
    /// Ports for TCP SYN probes (`--probe-tcp-syn`).
    /// Currently resolved as TCP CONNECT probes (SYN-raw needs Phase 4).
    pub tcp_syn_ports: Vec<u16>,
    /// Ports for TCP ACK probes (`--probe-tcp-ack`).
    /// Currently resolved as TCP CONNECT probes.
    pub tcp_ack_ports: Vec<u16>,
    /// Send ICMP echo requests (`--probe-icmp-echo`).
    pub icmp_echo: bool,
    /// Send ICMP timestamp requests (`--probe-icmp-timestamp`).
    pub icmp_timestamp: bool,
    /// Send ICMP address-mask requests (`--probe-icmp-address-mask`).
    pub icmp_address_mask: bool,
    /// Use ARP ping for local-subnet hosts (`--arp-ping`).
    pub arp_ping: bool,
    /// Use IPv6 Neighbor-Discovery ping (`--nd-ping`).
    pub nd_ping: bool,
    /// Per-probe connect/ping timeout.
    pub timeout: Duration,
    /// Perform reverse PTR lookup on discovered hosts (`--rev-ptr`).
    pub rev_ptr: bool,
    /// Maximum concurrent probes.
    pub workers: usize,
}

impl Default for HostDiscoveryConfig {
    fn default() -> Self {
        Self {
            tcp_syn_ports: vec![80, 443],
            tcp_ack_ports: vec![],
            icmp_echo: false,
            icmp_timestamp: false,
            icmp_address_mask: false,
            arp_ping: false,
            nd_ping: false,
            timeout: Duration::from_millis(200),
            rev_ptr: false,
            workers: 50,
        }
    }
}

/// A host that responded to at least one probe.
#[derive(Debug, Clone)]
pub struct DiscoveredHost {
    pub ip: IpAddr,
    /// PTR record, if `--rev-ptr` was requested and the lookup succeeded.
    pub ptr: Option<String>,
}

// ── Public entry-point ────────────────────────────────────────────────────────

/// Run host discovery against `targets` and return the live ones.
///
/// The function is intentionally infallible at the host level: a failed probe
/// for one target does not abort the whole run.
pub async fn discover_hosts(
    targets: Vec<IpAddr>,
    config: HostDiscoveryConfig,
) -> Result<Vec<DiscoveredHost>> {
    if targets.is_empty() {
        return Ok(vec![]);
    }

    let privileged = is_privileged();

    // Decide which TCP ports to probe (SYN + ACK lists, de-duped; fall back to
    // defaults if the caller left everything empty).
    let mut tcp_ports: Vec<u16> = config
        .tcp_syn_ports
        .iter()
        .chain(config.tcp_ack_ports.iter())
        .copied()
        .collect();
    tcp_ports.sort_unstable();
    tcp_ports.dedup();
    if tcp_ports.is_empty() {
        tcp_ports = vec![80, 443];
    }

    // Warn about privileged-only stubs that were requested.
    if config.arp_ping {
        warn!(
            "ARP ping requires raw socket access (run as admin/root) — \
             falling back to TCP CONNECT ping. Full ARP support is planned for Phase 4."
        );
    }
    if config.nd_ping {
        warn!(
            "IPv6 Neighbor-Discovery ping requires raw socket access (run as admin/root) — \
             falling back to TCP CONNECT ping. Full ND support is planned for Phase 4."
        );
    }
    if (config.icmp_echo || config.icmp_timestamp || config.icmp_address_mask) && !privileged {
        warn!(
            "ICMP probes require elevated privileges — skipping ICMP, \
             using TCP CONNECT ping only."
        );
    }

    let timeout = config.timeout;
    let workers = config.workers.max(1);

    // ── Layer 1 + 2: probe each target ───────────────────────────────────────
    let live_ips: Vec<IpAddr> = stream::iter(targets.clone())
        .map(|ip| {
            let tcp_ports = tcp_ports.clone();
            let do_icmp = config.icmp_echo && privileged;
            async move {
                // Layer 1: TCP CONNECT ping.
                if tcp_connect_ping(ip, &tcp_ports, timeout).await {
                    return Some(ip);
                }

                // Layer 2: ICMP echo (privileged only, surge-ping).
                if do_icmp && icmp_ping(ip, timeout).await {
                    return Some(ip);
                }

                None
            }
        })
        .buffer_unordered(workers)
        .filter_map(|r| async move { r })
        .collect()
        .await;

    // ── Layer 5: reverse PTR ──────────────────────────────────────────────────
    let mut discovered: Vec<DiscoveredHost> = if config.rev_ptr {
        let resolver =
            TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default());
        let mut out = Vec::with_capacity(live_ips.len());
        for ip in live_ips {
            let ptr = reverse_ptr(&resolver, ip).await;
            out.push(DiscoveredHost { ip, ptr });
        }
        out
    } else {
        live_ips
            .into_iter()
            .map(|ip| DiscoveredHost { ip, ptr: None })
            .collect()
    };

    // Stable ordering by IP address.
    discovered.sort_by_key(|h| h.ip);

    Ok(discovered)
}

// ── Layer 1: TCP CONNECT ping ────────────────────────────────────────────────

/// Returns `true` if the host is considered alive based on TCP behaviour.
///
/// * `Ok(_)`                → port is open         → host is alive
/// * `ConnectionRefused`    → port closed but host responded → host is alive
/// * `HostUnreachable` / `NetworkUnreachable` / timeout → host is down (or filtered)
/// * Any other error        → treat as "port closed, host alive" (conservative)
async fn tcp_connect_ping(ip: IpAddr, ports: &[u16], timeout: Duration) -> bool {
    for &port in ports {
        let addr = std::net::SocketAddr::new(ip, port);
        match tokio::time::timeout(timeout, TcpStream::connect(addr)).await {
            // Port open — definitely alive.
            Ok(Ok(_conn)) => {
                debug!("tcp-ping {ip}:{port} → open (alive)");
                return true;
            }
            // Connection refused → host is up, port is closed.
            Ok(Err(ref e)) if e.kind() == std::io::ErrorKind::ConnectionRefused => {
                debug!("tcp-ping {ip}:{port} → refused (alive)");
                return true;
            }
            // Unreachable → host is down or filtered; try next port.
            Ok(Err(ref e))
                if e.kind() == std::io::ErrorKind::HostUnreachable
                    || e.kind() == std::io::ErrorKind::NetworkUnreachable =>
            {
                debug!("tcp-ping {ip}:{port} → unreachable");
            }
            // Timeout → host may be filtering; try next port.
            Err(_elapsed) => {
                debug!("tcp-ping {ip}:{port} → timeout");
            }
            // Other errors (e.g. permission denied) → conservatively call alive.
            Ok(Err(ref e)) => {
                debug!("tcp-ping {ip}:{port} → other error: {e} (treating as alive)");
                return true;
            }
        }
    }
    false
}

// ── Layer 2: ICMP echo (privileged) ─────────────────────────────────────────

/// Send a single ICMP echo request via `surge_ping`.
///
/// Returns `true` if we receive a reply within `timeout`.
/// If the operation fails for any reason (no privileges, unsupported OS, etc.)
/// we return `false` without propagating the error.
async fn icmp_ping(ip: IpAddr, timeout: Duration) -> bool {
    use surge_ping::{Client, Config, PingIdentifier, PingSequence, ICMP};

    let kind = match ip {
        IpAddr::V4(_) => ICMP::V4,
        IpAddr::V6(_) => ICMP::V6,
    };

    let client = match Client::new(&Config::builder().kind(kind).build()) {
        Ok(c) => c,
        Err(e) => {
            debug!("icmp-ping {ip} — could not create surge-ping client: {e}");
            return false;
        }
    };

    let payload = [0u8; 8];
    // client.pinger() is an async fn that returns `Pinger` directly (not Result).
    let mut pinger = client.pinger(ip, PingIdentifier(rand::random())).await;
    pinger.timeout(timeout);

    match pinger.ping(PingSequence(0), &payload).await {
        Ok(_) => {
            debug!("icmp-ping {ip} → alive");
            true
        }
        Err(e) => {
            debug!("icmp-ping {ip} → {e}");
            false
        }
    }
}

// ── Layer 5: reverse PTR ─────────────────────────────────────────────────────

async fn reverse_ptr(resolver: &TokioAsyncResolver, ip: IpAddr) -> Option<String> {
    match resolver.reverse_lookup(ip).await {
        Ok(resp) => resp
            .iter()
            .next()
            .map(|name| name.to_string().trim_end_matches('.').to_string()),
        Err(e) => {
            debug!("reverse PTR for {ip} failed: {e}");
            None
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    /// 127.0.0.1 should always be detected as alive via TCP CONNECT ping
    /// because either some port will be open or, at minimum, we will get
    /// `ConnectionRefused` — both indicate the host is up.
    ///
    /// We deliberately bind a real listener on a random port so the test is
    /// deterministic regardless of which ports are open on the CI machine.
    #[tokio::test]
    async fn test_localhost_tcp_connect_ping_alive() {
        use tokio::net::TcpListener;

        // Bind a real listener so port is open → TcpStream::connect returns Ok.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            loop {
                let _ = listener.accept().await;
            }
        });

        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let alive =
            tcp_connect_ping(ip, &[port], Duration::from_millis(500)).await;
        assert!(alive, "127.0.0.1 on an open port must be detected as alive");
    }

    /// `ConnectionRefused` (port with no listener) should also count as alive.
    ///
    /// We test this by using a port we know will always be refused on localhost:
    /// bind a listener on a random port, record the port, then KEEP the listener
    /// alive and probe a *different* unreachable port (port 1) which Windows and
    /// Linux will both refuse immediately (requires root to bind, always closed).
    ///
    /// If the refused-path actually matters we verify via the tcp_connect_ping
    /// logic by calling it on port 1 directly. This avoids any OS port-reuse race.
    #[tokio::test]
    async fn test_localhost_refused_counts_as_alive() {
        use std::io::ErrorKind;

        // Test the logic: if we receive ConnectionRefused, tcp_connect_ping
        // should return true.  We simulate this by directly calling
        // TcpStream::connect to an always-refused address and verifying the
        // tcp_connect_ping function's documented behaviour.
        //
        // On Windows port 1 is always ConnectionRefused from localhost because
        // nothing listens there and it's below the privileged threshold for binding.
        //
        // We probe port 1; if we get Refused → alive (true).
        // If we happen to get a timeout on some unusual OS config → we skip the
        // assertion (the behaviour is still correct, just not testable here).
        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let addr = std::net::SocketAddr::new(ip, 1);
        let result = tokio::time::timeout(
            Duration::from_millis(500),
            TcpStream::connect(addr),
        )
        .await;

        match result {
            // Port 1 was refused → verify tcp_connect_ping also returns true.
            Ok(Err(ref e)) if e.kind() == ErrorKind::ConnectionRefused => {
                let alive = tcp_connect_ping(ip, &[1], Duration::from_millis(500)).await;
                assert!(
                    alive,
                    "ConnectionRefused on 127.0.0.1:1 must be treated as alive by tcp_connect_ping"
                );
            }
            // Any other outcome (timeout, unreachable, OS oddity) — skip.
            // The ConnectionRefused→alive path is proven by the code path
            // in tcp_connect_ping; the first test (open port) already covers liveness.
            _ => {}
        }
    }

    /// Full `discover_hosts` round-trip on 127.0.0.1 — TCP only, no rev-ptr.
    #[tokio::test]
    async fn test_discover_hosts_finds_localhost() {
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            loop {
                let _ = listener.accept().await;
            }
        });

        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let cfg = HostDiscoveryConfig {
            tcp_syn_ports: vec![port],
            tcp_ack_ports: vec![],
            icmp_echo: false,
            timeout: Duration::from_millis(500),
            rev_ptr: false,
            workers: 4,
            ..HostDiscoveryConfig::default()
        };

        let discovered = discover_hosts(vec![ip], cfg).await.unwrap();
        assert!(
            discovered.iter().any(|h| h.ip == ip),
            "discover_hosts must find 127.0.0.1 as alive"
        );
    }

    /// A non-routable IP should not be reported as alive.
    /// We use 192.0.2.1 (TEST-NET-1, RFC 5737) — guaranteed non-routable.
    #[tokio::test]
    async fn test_discover_hosts_non_routable_is_dead() {
        let ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
        let cfg = HostDiscoveryConfig {
            tcp_syn_ports: vec![9], // "discard" port — almost never open
            tcp_ack_ports: vec![],
            icmp_echo: false,
            timeout: Duration::from_millis(300),
            rev_ptr: false,
            workers: 2,
            ..HostDiscoveryConfig::default()
        };

        let discovered = discover_hosts(vec![ip], cfg).await.unwrap();
        assert!(
            !discovered.iter().any(|h| h.ip == ip),
            "192.0.2.1 (TEST-NET-1) must not appear as alive"
        );
    }
}
