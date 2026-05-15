pub mod connect;
pub mod syn_scan;
pub mod tcp_sequencer;

use crate::port::Port;

/// A single open-port result.
#[derive(Debug, Clone)]
pub struct ScanResult {
    pub host: String,
    pub ip: std::net::IpAddr,
    pub port: Port,
}
