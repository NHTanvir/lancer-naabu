/// Parsed representation of a single nmap-service-probes probe block.
#[derive(Debug, Clone)]
pub struct NmapProbe {
    pub name: String,
    #[allow(dead_code)]
    pub protocol: String, // "TCP" or "UDP"
    pub payload: Vec<u8>, // decoded from q|...|
    pub rarity: u8,       // 1-9
    pub ports: Vec<u16>,  // specific ports this probe targets
    pub matches: Vec<ProbeMatch>,
}

/// A single match (or softmatch) rule within a probe.
#[derive(Debug, Clone)]
pub struct ProbeMatch {
    pub service: String,
    pub pattern: String, // raw regex from m|...|
    pub flags: String,   // "si", "i", etc.
    pub product: Option<String>,
    pub version: Option<String>,
    pub info: Option<String>,
    pub is_soft: bool,
}

// ── Payload decoder ──────────────────────────────────────────────────────────

/// Decode a q|...| payload string, resolving `\r`, `\n`, `\t`, `\xHH` escapes.
fn decode_payload(raw: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(raw.len());
    let bytes = raw.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\' && i + 1 < bytes.len() {
            match bytes[i + 1] {
                b'r' => {
                    out.push(b'\r');
                    i += 2;
                }
                b'n' => {
                    out.push(b'\n');
                    i += 2;
                }
                b't' => {
                    out.push(b'\t');
                    i += 2;
                }
                b'0' => {
                    out.push(0);
                    i += 2;
                }
                b'x' if i + 3 < bytes.len() => {
                    let hi = bytes[i + 2];
                    let lo = bytes[i + 3];
                    if hi.is_ascii_hexdigit() && lo.is_ascii_hexdigit() {
                        let val = u8::from_str_radix(
                            std::str::from_utf8(&[hi, lo]).unwrap_or("00"),
                            16,
                        )
                        .unwrap_or(0);
                        out.push(val);
                        i += 4;
                    } else {
                        out.push(bytes[i]);
                        i += 1;
                    }
                }
                b'\\' => {
                    out.push(b'\\');
                    i += 2;
                }
                _ => {
                    // Unknown escape — keep as-is
                    out.push(bytes[i]);
                    i += 1;
                }
            }
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    out
}

/// Extract the value of a field like `p/Apache httpd/` or `v/$1/` from a
/// match-rule tail string.  Handles `/`, `|`, and other common delimiters.
fn extract_field(s: &str, prefix: char) -> Option<String> {
    // Find `<prefix><delim>...<delim>` where delim is the char after prefix.
    let start = s.find(prefix)?;
    let rest = &s[start + prefix.len_utf8()..];
    if rest.is_empty() {
        return None;
    }
    let delim = rest.chars().next()?;
    let inner = &rest[delim.len_utf8()..];
    let end = inner.find(delim)?;
    let value = &inner[..end];
    if value.is_empty() {
        None
    } else {
        Some(value.to_string())
    }
}

// ── Match-line parser ────────────────────────────────────────────────────────

/// Parse a `match` or `softmatch` line (after stripping the keyword).
///
/// Format: `<service> m|<pattern>|[flags] [p/<product>/] [v/<version>/] [i/<info>/]`
fn parse_match_line(line: &str, is_soft: bool) -> Option<ProbeMatch> {
    let line = line.trim();

    // Split off the service name (first whitespace-delimited token).
    let (service, rest) = {
        let mut parts = line.splitn(2, char::is_whitespace);
        let svc = parts.next()?.trim();
        let r = parts.next().unwrap_or("").trim();
        (svc.to_string(), r)
    };

    if rest.is_empty() {
        return None;
    }

    // The regex part starts with `m` followed by a delimiter.
    if !rest.starts_with('m') {
        return None;
    }
    let after_m = &rest[1..];
    if after_m.is_empty() {
        return None;
    }

    let delim = after_m.chars().next()?;
    let inner = &after_m[delim.len_utf8()..];

    // Find the closing delimiter (unescaped).
    let mut pattern = String::new();
    let mut chars = inner.char_indices();
    let mut close_pos = None;
    while let Some((idx, ch)) = chars.next() {
        if ch == '\\' {
            // skip next char
            if let Some((_, esc)) = chars.next() {
                pattern.push('\\');
                pattern.push(esc);
            }
        } else if ch == delim {
            close_pos = Some(idx);
            break;
        } else {
            pattern.push(ch);
        }
    }

    let tail = if let Some(cp) = close_pos {
        // rest after closing delimiter
        let offset = 1 /* 'm' */ + delim.len_utf8() + cp + delim.len_utf8();
        if offset <= rest.len() {
            rest[offset..].trim()
        } else {
            ""
        }
    } else {
        ""
    };

    // Parse optional flags: letters before first space.
    let (flags, tail) = {
        let mut f = String::new();
        let mut t = tail;
        let first_space = tail.find(char::is_whitespace).unwrap_or(tail.len());
        let candidate = &tail[..first_space];
        // Flags are only lowercase letters (i, s, etc.)
        if candidate.chars().all(|c| c.is_ascii_lowercase()) && !candidate.starts_with('p') {
            f = candidate.to_string();
            t = tail[first_space..].trim();
        }
        (f, t)
    };

    let product = extract_field(tail, 'p');
    let version = extract_field(tail, 'v');
    let info = extract_field(tail, 'i');

    Some(ProbeMatch {
        service,
        pattern,
        flags,
        product,
        version,
        info,
        is_soft,
    })
}

// ── Probe-line parser ────────────────────────────────────────────────────────

/// Parse `Probe TCP GetRequest q|...|` into (protocol, name, payload).
fn parse_probe_header(line: &str) -> Option<(String, String, Vec<u8>)> {
    // Format: Probe <PROTO> <NAME> q|...|
    let mut parts = line.splitn(4, char::is_whitespace);
    parts.next()?; // "Probe"
    let proto = parts.next()?.trim().to_uppercase();
    let name = parts.next()?.trim().to_string();
    let q_part = parts.next()?.trim();

    // q|payload| — find the delimiter after 'q'
    if !q_part.starts_with('q') {
        return None;
    }
    let after_q = &q_part[1..];
    if after_q.is_empty() {
        // empty payload is valid (q||)
        return Some((proto, name, Vec::new()));
    }
    let delim = after_q.chars().next()?;
    if delim == '|' || delim == '/' || delim == '!' || delim == '@' {
        let inner = &after_q[delim.len_utf8()..];
        // Find closing delimiter
        let close = inner.find(delim).unwrap_or(inner.len());
        let raw = &inner[..close];
        Some((proto, name, decode_payload(raw)))
    } else {
        Some((proto, name, Vec::new()))
    }
}

// ── Public parser ────────────────────────────────────────────────────────────

/// Parse a full nmap-service-probes file (or a subset) into a list of probes.
pub fn parse_probes(content: &str) -> anyhow::Result<Vec<NmapProbe>> {
    let mut probes: Vec<NmapProbe> = Vec::new();
    let mut current: Option<NmapProbe> = None;

    for raw_line in content.lines() {
        let line = raw_line.trim();

        // Skip comments and blank lines between probe blocks.
        if line.starts_with('#') || line.is_empty() {
            continue;
        }

        if line.starts_with("Probe ") {
            // Flush current probe.
            if let Some(p) = current.take() {
                probes.push(p);
            }
            if let Some((proto, name, payload)) = parse_probe_header(line) {
                current = Some(NmapProbe {
                    name,
                    protocol: proto,
                    payload,
                    rarity: 5, // default mid-range
                    ports: Vec::new(),
                    matches: Vec::new(),
                });
            }
        } else if line.starts_with("rarity ") {
            if let Some(ref mut p) = current {
                let val: u8 = line["rarity ".len()..].trim().parse().unwrap_or(5);
                p.rarity = val;
            }
        } else if line.starts_with("ports ") {
            if let Some(ref mut p) = current {
                let port_str = line["ports ".len()..].trim();
                for part in port_str.split(',') {
                    if let Ok(n) = part.trim().parse::<u16>() {
                        p.ports.push(n);
                    }
                }
            }
        } else if line.starts_with("match ") {
            if let Some(ref mut p) = current {
                let rest = &line["match ".len()..];
                if let Some(m) = parse_match_line(rest, false) {
                    p.matches.push(m);
                }
            }
        } else if line.starts_with("softmatch ") {
            if let Some(ref mut p) = current {
                let rest = &line["softmatch ".len()..];
                if let Some(m) = parse_match_line(rest, true) {
                    p.matches.push(m);
                }
            }
        }
        // Ignore unrecognised directives (totalwaitms, tcpwrappedms, etc.)
    }

    // Flush the last probe.
    if let Some(p) = current.take() {
        probes.push(p);
    }

    Ok(probes)
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_payload_escapes() {
        let decoded = decode_payload(r"GET / HTTP/1.0\r\n\r\n");
        assert_eq!(decoded, b"GET / HTTP/1.0\r\n\r\n");
    }

    #[test]
    fn test_decode_hex_escape() {
        let decoded = decode_payload(r"\x16\x03");
        assert_eq!(decoded, &[0x16, 0x03]);
    }

    #[test]
    fn test_parse_http_match() {
        let line = r#"http m|^HTTP/1\.[01] \d\d\d| p/HTTP/"#;
        let m = parse_match_line(line, false).unwrap();
        assert_eq!(m.service, "http");
        assert_eq!(m.product.as_deref(), Some("HTTP"));
        assert!(!m.is_soft);
    }

    #[test]
    fn test_parse_match_with_flags() {
        let line = r#"http m|^HTTP/1\.[01] \d\d\d .*<title>(.+?)</title>|si p/HTTP/ i/$1/"#;
        let m = parse_match_line(line, false).unwrap();
        assert_eq!(m.service, "http");
        assert_eq!(m.flags, "si");
        assert_eq!(m.info.as_deref(), Some("$1"));
    }

    #[test]
    fn test_parse_softmatch() {
        let line = r"http m|^HTTP/|";
        let m = parse_match_line(line, true).unwrap();
        assert!(m.is_soft);
    }

    #[test]
    fn test_parse_embedded_probes_count() {
        let content = crate::fingerprint::probes::EMBEDDED_PROBES;
        let probes = parse_probes(content).unwrap();
        // We have 11 probes in our embedded set.
        assert_eq!(probes.len(), 11, "expected 11 embedded probes, got {}", probes.len());
    }

    #[test]
    fn test_probe_ports_parsed() {
        let content = crate::fingerprint::probes::EMBEDDED_PROBES;
        let probes = parse_probes(content).unwrap();
        let http = probes.iter().find(|p| p.name == "GetRequest").unwrap();
        assert!(http.ports.contains(&80));
        assert!(http.ports.contains(&8080));
    }
}
