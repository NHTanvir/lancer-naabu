use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

pub struct ScanMetrics {
    pub packets_sent: AtomicU64,
    pub responses_received: AtomicU64,
    pub open_ports_found: AtomicU64,
    pub hosts_scanned: AtomicU64,
    pub start_time: std::time::Instant,
}

impl ScanMetrics {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            packets_sent: AtomicU64::new(0),
            responses_received: AtomicU64::new(0),
            open_ports_found: AtomicU64::new(0),
            hosts_scanned: AtomicU64::new(0),
            start_time: std::time::Instant::now(),
        })
    }

    pub fn to_prometheus(&self) -> String {
        let elapsed = self.start_time.elapsed().as_secs_f64();
        format!(
            "# HELP packets_sent Total packets sent\n\
             # TYPE packets_sent counter\n\
             packets_sent {}\n\
             # HELP responses_received Total responses received\n\
             # TYPE responses_received counter\n\
             responses_received {}\n\
             # HELP open_ports_found Total open ports discovered\n\
             # TYPE open_ports_found counter\n\
             open_ports_found {}\n\
             # HELP time_elapsed Scan duration in seconds\n\
             # TYPE time_elapsed gauge\n\
             time_elapsed {:.2}\n",
            self.packets_sent.load(Ordering::Relaxed),
            self.responses_received.load(Ordering::Relaxed),
            self.open_ports_found.load(Ordering::Relaxed),
            elapsed,
        )
    }
}

pub async fn start_metrics_server(metrics: Arc<ScanMetrics>, port: u16) {
    use axum::{routing::get, Router};

    let app = Router::new().route(
        "/metrics",
        get({
            let m = Arc::clone(&metrics);
            move || {
                let m = Arc::clone(&m);
                async move { m.to_prometheus() }
            }
        }),
    );

    let addr = format!("0.0.0.0:{}", port);
    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .expect("Failed to bind metrics port");

    tokio::spawn(async move {
        axum::serve(listener, app).await.ok();
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_prometheus_output_contains_expected_fields() {
        let m = ScanMetrics::new();
        m.open_ports_found.store(5, Ordering::Relaxed);
        m.packets_sent.store(100, Ordering::Relaxed);
        m.responses_received.store(50, Ordering::Relaxed);

        let output = m.to_prometheus();
        assert!(output.contains("packets_sent 100"), "missing packets_sent");
        assert!(output.contains("responses_received 50"), "missing responses_received");
        assert!(output.contains("open_ports_found 5"), "missing open_ports_found");
        assert!(output.contains("time_elapsed"), "missing time_elapsed");
    }

    #[test]
    fn test_prometheus_output_has_help_type_lines() {
        let m = ScanMetrics::new();
        let output = m.to_prometheus();
        assert!(output.contains("# HELP packets_sent"));
        assert!(output.contains("# TYPE packets_sent counter"));
        assert!(output.contains("# TYPE time_elapsed gauge"));
    }
}
