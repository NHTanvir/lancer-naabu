//! lancer-naabu: Rust port scanner library
//!
//! # Example
//! ```rust,no_run
//! use lancer_naabu::{Scanner, ScanOptions};
//!
//! #[tokio::main]
//! async fn main() {
//!     let opts = ScanOptions::default();
//!     let scanner = Scanner::new(opts);
//!     let results = scanner.scan(vec!["127.0.0.1".to_string()], vec![80, 443]).await.unwrap();
//!     for r in results {
//!         println!("{}:{}", r.host, r.port.number);
//!     }
//! }
//! ```

pub mod blackrock;
pub mod cdn;
pub mod output;
pub mod port;
pub mod scanner;
pub mod service_map;
pub mod target;
pub mod udp_probes;

// These modules are used internally; expose them for downstream crates that need them.
pub mod fingerprint;
pub mod passive;
pub mod prediction;
pub mod privileges;

// Re-export the main types
pub use scanner::ScanResult;
pub use port::{Port, Protocol};

/// High-level scanner options for library API
#[derive(Debug, Clone)]
pub struct ScanOptions {
    /// Scan type: "CONNECT" (default) or "SYN" (requires privileges)
    pub scan_type: String,
    /// Rate limit in connections/second (default: 1000)
    pub rate: u32,
    /// Concurrent workers (default: 25)
    pub workers: usize,
    /// Timeout per port in ms (default: 1500)
    pub timeout_ms: u64,
    /// Retries on timeout (default: 3)
    pub retries: u32,
    /// Enable service version detection
    pub service_version: bool,
    /// Enable smart-scan port correlation
    pub smart_scan: bool,
    /// CDN port restriction
    pub exclude_cdn: bool,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            scan_type: "CONNECT".to_string(),
            rate: 1000,
            workers: 25,
            timeout_ms: 1500,
            retries: 3,
            service_version: false,
            smart_scan: false,
            exclude_cdn: false,
        }
    }
}

/// Main scanner struct for library use
pub struct Scanner {
    opts: ScanOptions,
}

impl Scanner {
    pub fn new(opts: ScanOptions) -> Self {
        Self { opts }
    }

    /// Scan a list of hosts on the given TCP ports.
    /// Returns a Vec of open-port results, sorted by host then port.
    pub async fn scan(
        &self,
        hosts: Vec<String>,
        ports: Vec<u16>,
    ) -> anyhow::Result<Vec<ScanResult>> {
        use crate::port::Protocol;
        use crate::scanner::connect::ConnectScanner;
        use crate::target::Target;
        use hickory_resolver::TokioAsyncResolver;
        use hickory_resolver::config::{ResolverConfig, ResolverOpts};

        let resolver =
            TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default());

        // Resolve host strings to concrete Targets.
        let mut targets: Vec<Target> = Vec::new();
        for host in &hosts {
            if let Ok(ip) = host.parse::<std::net::IpAddr>() {
                targets.push(Target { host: host.clone(), ip });
            } else {
                match resolver.lookup_ip(host.as_str()).await {
                    Ok(lookup) => {
                        if let Some(ip) = lookup.iter().next() {
                            targets.push(Target { host: host.clone(), ip });
                        }
                    }
                    Err(e) => {
                        tracing::warn!("DNS resolution failed for '{}': {}", host, e);
                    }
                }
            }
        }

        if targets.is_empty() {
            return Ok(vec![]);
        }

        let port_list: Vec<Port> = ports
            .iter()
            .map(|&n| Port { number: n, protocol: Protocol::Tcp })
            .collect();

        let scanner = ConnectScanner::new(
            targets,
            port_list,
            self.opts.rate,
            if self.opts.workers > 0 { self.opts.workers } else { 25 },
            self.opts.timeout_ms,
            self.opts.retries,
        );

        scanner.run().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Basic smoke-test: Scanner::new + scan against localhost on a bound port.
    #[tokio::test]
    async fn test_library_api_finds_open_port() {
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        // Accept connections in background so connect succeeds.
        tokio::spawn(async move {
            loop {
                let _ = listener.accept().await;
            }
        });

        let opts = ScanOptions::default();
        let scanner = Scanner::new(opts);
        let results = scanner
            .scan(vec!["127.0.0.1".to_string()], vec![port])
            .await
            .unwrap();

        assert_eq!(results.len(), 1, "expected exactly one open port");
        assert_eq!(results[0].port.number, port);
    }

    /// Scan against a port with no listener — should return empty.
    #[tokio::test]
    async fn test_library_api_closed_port_returns_empty() {
        // Bind then drop immediately so port is closed.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);

        let opts = ScanOptions { timeout_ms: 500, retries: 0, ..Default::default() };
        let scanner = Scanner::new(opts);
        let results = scanner
            .scan(vec!["127.0.0.1".to_string()], vec![port])
            .await
            .unwrap();

        assert!(results.is_empty(), "expected no open ports on a closed listener");
    }
}
