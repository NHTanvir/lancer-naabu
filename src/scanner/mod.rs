pub mod connect;
pub mod syn_scan;
pub mod tcp_sequencer;
pub mod udp_scan;

use crate::port::Port;

/// A single open-port result.
#[derive(Debug, Clone)]
pub struct ScanResult {
    pub host: String,
    pub ip: std::net::IpAddr,
    pub port: Port,
}
