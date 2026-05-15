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
    /// Detected service name (e.g. "http", "ssh").
    pub service: Option<String>,
    /// Product name from service fingerprint (e.g. "OpenSSH").
    pub product: Option<String>,
    /// Version string from service fingerprint (e.g. "8.9p1").
    pub version: Option<String>,
}
