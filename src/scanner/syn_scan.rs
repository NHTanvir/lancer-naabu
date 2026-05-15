//! SYN scanner — feature-gated behind `raw_scan`.
//!
//! When the `raw_scan` feature is NOT compiled in this module is entirely
//! empty, which is intentional.  All user-visible behaviour is handled in
//! `main.rs` via `privileges::check_syn_scan_available()`.

#[cfg(feature = "raw_scan")]
pub use inner::SynScanner;

#[cfg(feature = "raw_scan")]
mod inner {
    use crate::blackrock::Blackrock;
    use crate::port::Port;
    use crate::privileges;
    use crate::scanner::tcp_sequencer::TcpSequencer;
    use crate::scanner::ScanResult;
    use anyhow::{anyhow, Result};
    use pnet_datalink::{self, NetworkInterface};
    use pnet_packet::ip::IpNextHeaderProtocols;
    use pnet_packet::tcp::{MutableTcpPacket, TcpFlags, TcpPacket};
    use pnet_packet::Packet;
    use pnet_transport::{
        tcp_packet_iter, transport_channel, TransportChannelType, TransportProtocol,
    };
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    /// Raw-socket SYN scanner.
    ///
    /// Sends TCP SYN packets using `pnet`'s raw transport channel and listens
    /// for SYN-ACK / RST replies on a separate thread.  Reply correlation is
    /// performed via `TcpSequencer` so no per-connection state table is needed.
    pub struct SynScanner {
        /// Maximum packets per second (send rate).
        pub rate: u32,
        /// How long to wait after the last SYN is sent for late replies (ms).
        pub timeout_ms: u64,
        /// Number of send workers (unused in the simple implementation below,
        /// kept for API compatibility with ConnectScanner).
        pub workers: usize,
        /// Source IP override (None = auto-detect from outgoing interface).
        pub source_ip: Option<IpAddr>,
        /// Interface name override (None = use default route interface).
        pub interface: Option<String>,
    }

    impl SynScanner {
        /// Run a SYN scan against `targets × ports`.
        ///
        /// Returns all ports that responded with SYN-ACK (open).
        pub async fn run(
            &self,
            targets: Vec<IpAddr>,
            ports: Vec<Port>,
        ) -> Result<Vec<ScanResult>> {
            // ── 1. Privilege check ────────────────────────────────────────────
            privileges::check_syn_scan_available()
                .map_err(|e| anyhow!("SYN scan unavailable: {}", e))?;

            // ── 2. Resolve source interface / IP ──────────────────────────────
            let src_ip = self.resolve_source_ip()?;

            // ── 3. Build sequencer and Blackrock shuffler ─────────────────────
            let sequencer = Arc::new(TcpSequencer::new());
            let total = targets.len() as u64 * ports.len() as u64;
            let br = Blackrock::new(total, rand_seed());

            // ── 4. Open raw transport channels ────────────────────────────────
            let (mut tx, mut rx) = transport_channel(
                65536,
                TransportChannelType::Layer4(TransportProtocol::Ipv4(
                    IpNextHeaderProtocols::Tcp,
                )),
            )
            .map_err(|e| anyhow!("failed to open raw transport channel: {}", e))?;

            // ── 5. Spawn receiver thread ──────────────────────────────────────
            let open_ports: Arc<Mutex<Vec<ScanResult>>> = Arc::new(Mutex::new(Vec::new()));
            let open_ports_rx = Arc::clone(&open_ports);
            let seq_rx = Arc::clone(&sequencer);
            let targets_rx = targets.clone();

            // Build a host-label lookup (ip → host string).
            let host_map: std::collections::HashMap<IpAddr, String> = targets_rx
                .iter()
                .map(|ip| (*ip, ip.to_string()))
                .collect();

            let timeout_ms = self.timeout_ms;
            let recv_handle = std::thread::spawn(move || {
                let deadline = std::time::Instant::now()
                    + Duration::from_millis(timeout_ms + 500 /* grace */);
                let mut iter = tcp_packet_iter(&mut rx);
                loop {
                    if std::time::Instant::now() > deadline {
                        break;
                    }
                    match iter.next_with_timeout(Duration::from_millis(100)) {
                        Ok(Some((pkt, src_addr))) => {
                            let src_ip = IpAddr::V4(match src_addr {
                                std::net::IpAddr::V4(v4) => v4,
                                _ => continue,
                            });
                            if !host_map.contains_key(&src_ip) {
                                continue;
                            }
                            // SYN-ACK: flags = SYN | ACK
                            let flags = pkt.get_flags();
                            if flags & (TcpFlags::SYN | TcpFlags::ACK)
                                != (TcpFlags::SYN | TcpFlags::ACK)
                            {
                                continue;
                            }
                            let src_port = pkt.get_source();
                            let ack_num = pkt.get_acknowledgement();
                            if seq_rx.verify_reply(src_ip, src_port, ack_num) {
                                let host = host_map
                                    .get(&src_ip)
                                    .cloned()
                                    .unwrap_or_else(|| src_ip.to_string());
                                let mut guard = open_ports_rx.lock().unwrap();
                                guard.push(ScanResult {
                                    host,
                                    ip: src_ip,
                                    port: crate::port::Port {
                                        number: src_port,
                                        protocol: crate::port::Protocol::Tcp,
                                    },
                                    service: None,
                                    product: None,
                                    version: None,
                                });
                            }
                        }
                        Ok(None) => {} // timeout on this slice — continue polling
                        Err(_) => break,
                    }
                }
            });

            // ── 6. Send SYNs in permuted order ────────────────────────────────
            use std::time::{Duration, Instant};
            let interval = if self.rate > 0 {
                Duration::from_nanos(1_000_000_000 / self.rate as u64)
            } else {
                Duration::from_nanos(0)
            };

            let src_port_base: u16 = 40000;

            for idx in 0..total {
                let permuted = br.permute(idx);
                let target_idx = (permuted / ports.len() as u64) as usize;
                let port_idx = (permuted % ports.len() as u64) as usize;

                let dst_ip = match targets[target_idx] {
                    IpAddr::V4(v4) => v4,
                    IpAddr::V6(_) => continue, // IPv6 not yet supported
                };
                let dst_port = ports[port_idx].number;
                let src_port = src_port_base.wrapping_add((permuted & 0xfff) as u16);

                let seq_num = sequencer.sequence_for(IpAddr::V4(dst_ip), dst_port);

                // Build TCP SYN packet (20 bytes, no options).
                let mut raw = [0u8; 20];
                {
                    let mut pkt = MutableTcpPacket::new(&mut raw).unwrap();
                    pkt.set_source(src_port);
                    pkt.set_destination(dst_port);
                    pkt.set_sequence(seq_num);
                    pkt.set_acknowledgement(0);
                    pkt.set_data_offset(5); // 20 bytes / 4
                    pkt.set_flags(TcpFlags::SYN);
                    pkt.set_window(65535);
                    pkt.set_urgent_ptr(0);
                    // Checksum is computed by the kernel for raw IP sockets.
                }

                let dst_addr = std::net::IpAddr::V4(dst_ip);
                if let Err(e) = tx.send_to(
                    TcpPacket::new(&raw).unwrap(),
                    dst_addr,
                ) {
                    tracing::warn!("SYN send error to {}:{}: {}", dst_ip, dst_port, e);
                }

                // Rate-limit.
                if !interval.is_zero() {
                    std::thread::sleep(interval);
                }
            }

            // ── 7. Wait for receiver to finish ────────────────────────────────
            // Sleep for the configured timeout so the receiver thread collects late replies.
            std::thread::sleep(Duration::from_millis(self.timeout_ms));
            let _ = recv_handle.join();

            // ── 8. Return results ─────────────────────────────────────────────
            let mut results = Arc::try_unwrap(open_ports)
                .unwrap_or_else(|arc| {
                    // Fallback: clone from the Arc if try_unwrap fails.
                    let guard = arc.lock().unwrap();
                    let v = guard.clone();
                    drop(guard);
                    Mutex::new(v)
                })
                .into_inner()
                .unwrap();

            results.sort_by(|a, b| {
                a.host
                    .cmp(&b.host)
                    .then(a.ip.cmp(&b.ip))
                    .then(a.port.number.cmp(&b.port.number))
            });

            Ok(results)
        }

        // ── Helpers ───────────────────────────────────────────────────────────

        fn resolve_source_ip(&self) -> Result<Ipv4Addr> {
            if let Some(IpAddr::V4(v4)) = self.source_ip {
                return Ok(v4);
            }
            // Pick the first non-loopback IPv4 interface.
            for iface in pnet_datalink::interfaces() {
                if iface.is_loopback() {
                    continue;
                }
                for ip in &iface.ips {
                    if let IpAddr::V4(v4) = ip.ip() {
                        return Ok(v4);
                    }
                }
            }
            Err(anyhow!(
                "could not determine source IPv4 address — use --source-ip"
            ))
        }
    }

    fn rand_seed() -> u64 {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        use std::time::SystemTime;
        let mut h = DefaultHasher::new();
        SystemTime::now().hash(&mut h);
        h.finish()
    }
}
