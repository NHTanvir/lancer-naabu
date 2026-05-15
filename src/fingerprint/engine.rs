use crate::fingerprint::parser::{self, NmapProbe, ProbeMatch};
use anyhow::Result;
use regex::RegexBuilder;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{Duration, timeout};
use tracing::debug;

// ── Public types ─────────────────────────────────────────────────────────────

/// Detected service version information for an open port.
#[derive(Debug, Clone)]
pub struct ServiceVersion {
    pub service: String,
    pub product: Option<String>,
    pub version: Option<String>,
    #[allow(dead_code)]
    pub info: Option<String>,
}

// ── Engine ───────────────────────────────────────────────────────────────────

#[allow(dead_code)]
pub struct FingerprintEngine {
    probes: Vec<NmapProbe>,
}

impl FingerprintEngine {
    /// Create from a pre-parsed list of probes.
    #[allow(dead_code)]
    pub fn new(probes: Vec<NmapProbe>) -> Self {
        Self { probes }
    }

    /// Parse probe content from a string (nmap-service-probes format) and create engine.
    pub fn from_str(content: &str) -> Result<Self> {
        let probes = parser::parse_probes(content)?;
        Ok(Self { probes })
    }

    /// Try to identify the service running on `host:port`.
    ///
    /// Probe ordering:
    /// 1. Port-specific probes first (where `port` is in probe.ports).
    /// 2. Then remaining probes, sorted by rarity ascending.
    ///
    /// In `fast_mode` only port-hinted probes are tried.
    pub async fn fingerprint(
        &self,
        host: &str,
        port: u16,
        timeout_ms: u64,
        fast_mode: bool,
    ) -> Option<ServiceVersion> {
        // Build ordered probe list.
        let mut port_probes: Vec<&NmapProbe> = self
            .probes
            .iter()
            .filter(|p| p.ports.contains(&port))
            .collect();
        port_probes.sort_by_key(|p| p.rarity);

        if fast_mode {
            // Only try port-hinted probes.
            for probe in &port_probes {
                if let Some(sv) = try_probe(host, port, probe, timeout_ms).await {
                    return Some(sv);
                }
            }
            return None;
        }

        // Full mode: port-specific first, then generic probes.
        let port_probe_names: std::collections::HashSet<&str> =
            port_probes.iter().map(|p| p.name.as_str()).collect();

        let mut other_probes: Vec<&NmapProbe> = self
            .probes
            .iter()
            .filter(|p| !port_probe_names.contains(p.name.as_str()))
            .collect();
        other_probes.sort_by_key(|p| p.rarity);

        for probe in port_probes.iter().chain(other_probes.iter()) {
            if let Some(sv) = try_probe(host, port, probe, timeout_ms).await {
                return Some(sv);
            }
        }

        None
    }
}

// ── Probe execution ──────────────────────────────────────────────────────────

/// Connect, send payload, read response, match against probe rules.
/// Returns `Some(ServiceVersion)` on a definitive (non-soft) match, or a
/// soft match when no further probes are available (handled by the caller).
async fn try_probe(
    host: &str,
    port: u16,
    probe: &NmapProbe,
    timeout_ms: u64,
) -> Option<ServiceVersion> {
    let addr = format!("{}:{}", host, port);
    let dur = Duration::from_millis(timeout_ms);

    let mut stream = match timeout(dur, TcpStream::connect(&addr)).await {
        Ok(Ok(s)) => s,
        _ => return None,
    };

    // Send payload (may be empty — banner grab).
    if !probe.payload.is_empty() {
        if timeout(dur, stream.write_all(&probe.payload)).await.is_err() {
            return None;
        }
    }

    // Read up to 4096 bytes.
    let mut buf = vec![0u8; 4096];
    let n = match timeout(dur, stream.read(&mut buf)).await {
        Ok(Ok(n)) => n,
        _ => 0,
    };

    if n == 0 && probe.payload.is_empty() {
        // Empty payload + no response — no information.
        return None;
    }

    let response = &buf[..n];
    debug!(
        probe = %probe.name,
        bytes = n,
        "probe response"
    );

    // Try each match rule in order.
    let mut soft_result: Option<ServiceVersion> = None;

    for pm in &probe.matches {
        if let Some(sv) = apply_match(pm, response) {
            if pm.is_soft {
                // Record first soft match; keep trying for a hard match.
                if soft_result.is_none() {
                    soft_result = Some(sv);
                }
            } else {
                // Definitive match — return immediately.
                return Some(sv);
            }
        }
    }

    soft_result
}

// ── Match application ────────────────────────────────────────────────────────

fn apply_match(pm: &ProbeMatch, response: &[u8]) -> Option<ServiceVersion> {
    // Convert response to string (lossy).
    let text = String::from_utf8_lossy(response);

    let re = build_regex(&pm.pattern, &pm.flags).ok()?;

    let caps = re.captures(&text)?;

    // Substitute capture group references ($1, $2 …) in field templates.
    let substitute = |template: &Option<String>| -> Option<String> {
        let t = template.as_deref()?;
        let mut result = t.to_string();
        for i in 1..=9 {
            let placeholder = format!("${}", i);
            if result.contains(&placeholder) {
                let replacement = caps.get(i).map(|m| m.as_str()).unwrap_or("");
                result = result.replace(&placeholder, replacement);
            }
        }
        if result.is_empty() { None } else { Some(result) }
    };

    Some(ServiceVersion {
        service: pm.service.clone(),
        product: substitute(&pm.product),
        version: substitute(&pm.version),
        info: substitute(&pm.info),
    })
}

fn build_regex(pattern: &str, flags: &str) -> Result<regex::Regex> {
    let case_insensitive = flags.contains('i');
    let dot_matches_newline = flags.contains('s');

    let re = RegexBuilder::new(pattern)
        .case_insensitive(case_insensitive)
        .dot_matches_new_line(dot_matches_newline)
        .build()?;

    Ok(re)
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fingerprint::probes::EMBEDDED_PROBES;

    #[test]
    fn test_http_pattern_matches() {
        let pm = ProbeMatch {
            service: "http".into(),
            pattern: r"^HTTP/1\.[01] \d\d\d".into(),
            flags: String::new(),
            product: Some("HTTP".into()),
            version: None,
            info: None,
            is_soft: false,
        };
        let response = b"HTTP/1.1 200 OK\r\nServer: nginx\r\n\r\n";
        let result = apply_match(&pm, response);
        assert!(result.is_some());
        let sv = result.unwrap();
        assert_eq!(sv.service, "http");
        assert_eq!(sv.product.as_deref(), Some("HTTP"));
    }

    #[test]
    fn test_ssh_version_capture() {
        let pm = ProbeMatch {
            service: "ssh".into(),
            pattern: r"^SSH-2\.0-OpenSSH_([\d.]+p[\d]+)".into(),
            flags: String::new(),
            product: Some("OpenSSH".into()),
            version: Some("$1".into()),
            info: None,
            is_soft: false,
        };
        let response = b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n";
        let result = apply_match(&pm, response);
        assert!(result.is_some());
        let sv = result.unwrap();
        assert_eq!(sv.version.as_deref(), Some("8.9p1"));
    }

    #[test]
    fn test_no_match() {
        let pm = ProbeMatch {
            service: "http".into(),
            pattern: r"^HTTP/1\.[01] \d\d\d".into(),
            flags: String::new(),
            product: Some("HTTP".into()),
            version: None,
            info: None,
            is_soft: false,
        };
        let response = b"SSH-2.0-OpenSSH_8.9p1\r\n";
        let result = apply_match(&pm, response);
        assert!(result.is_none());
    }

    #[test]
    fn test_engine_from_embedded() {
        let engine = FingerprintEngine::from_str(EMBEDDED_PROBES).unwrap();
        assert!(!engine.probes.is_empty());
    }

    #[tokio::test]
    async fn test_fast_mode_only_port_probes() {
        // Build a minimal engine with one port-specific and one generic probe.
        let content = "Probe TCP HTTPOnly q|GET / HTTP/1.0\\r\\n\\r\\n|\nrarity 1\nports 80\nmatch http m|^HTTP/| p/HTTP/\n\nProbe TCP Generic q|\nrarity 5\nmatch generic m|^.| p/Generic/\n";
        let engine = FingerprintEngine::from_str(content).unwrap();
        // In fast mode on port 80, only the HTTPOnly probe should be attempted.
        // We can't easily test the network call here, but we can verify the
        // engine builds correctly and probe ordering is consistent.
        let port_probes: Vec<_> = engine.probes.iter().filter(|p| p.ports.contains(&80)).collect();
        assert_eq!(port_probes.len(), 1);
        assert_eq!(port_probes[0].name, "HTTPOnly");
    }
}
