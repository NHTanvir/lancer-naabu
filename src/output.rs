use crate::scanner::ScanResult;
use anyhow::Result;
use serde::Serialize;
use std::collections::HashSet;
use std::io::Write;

// ── Field filtering helpers ──────────────────────────────────────────────────

/// Resolved set of fields to include in structured (JSON/CSV) output.
#[derive(Debug)]
pub struct FieldSet {
    pub host: bool,
    pub port: bool,
    pub protocol: bool,
    pub ip: bool,
    pub service: bool,
    pub product: bool,
    pub version: bool,
}

impl FieldSet {
    /// All fields enabled.
    fn all() -> Self {
        Self { host: true, port: true, protocol: true, ip: true, service: true, product: true, version: true }
    }

    /// Parse `--list-output-fields` / `--exclude-output-fields` into a FieldSet.
    ///
    /// If `include` is Some, only those fields are shown.
    /// Then fields in `exclude` are removed.
    pub fn resolve(include: Option<&str>, exclude: Option<&str>) -> Self {
        let mut fs = Self::all();

        if let Some(inc) = include {
            // Start with nothing, then enable requested fields.
            fs.host = false;
            fs.port = false;
            fs.protocol = false;
            fs.ip = false;
            fs.service = false;
            fs.product = false;
            fs.version = false;
            for field in inc.split(',').map(str::trim) {
                match field.to_ascii_lowercase().as_str() {
                    "host" => fs.host = true,
                    "port" => fs.port = true,
                    "protocol" => fs.protocol = true,
                    "ip" => fs.ip = true,
                    "service" => fs.service = true,
                    "product" => fs.product = true,
                    "version" => fs.version = true,
                    _ => {}
                }
            }
        }

        if let Some(ex) = exclude {
            for field in ex.split(',').map(str::trim) {
                match field.to_ascii_lowercase().as_str() {
                    "host" => fs.host = false,
                    "port" => fs.port = false,
                    "protocol" => fs.protocol = false,
                    "ip" => fs.ip = false,
                    "service" => fs.service = false,
                    "product" => fs.product = false,
                    "version" => fs.version = false,
                    _ => {}
                }
            }
        }

        fs
    }
}

// ── Output config ────────────────────────────────────────────────────────────

pub struct OutputConfig {
    pub json: bool,
    pub csv: bool,
    pub silent: bool,
    pub output_file: Option<String>,
    /// Fields to include (None = all).
    pub include_fields: Option<String>,
    /// Fields to exclude (None = none excluded).
    pub exclude_fields: Option<String>,
}

// ── Serialisation helpers ────────────────────────────────────────────────────

#[derive(Serialize)]
struct JsonResultDyn {
    #[serde(skip_serializing_if = "Option::is_none")]
    host: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    protocol: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ip: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    service: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    product: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    version: Option<String>,
}

fn build_json_line(r: &ScanResult, fs: &FieldSet) -> Result<String> {
    let obj = JsonResultDyn {
        host:     if fs.host     { Some(r.host.clone()) }          else { None },
        port:     if fs.port     { Some(r.port.number) }            else { None },
        protocol: if fs.protocol { Some(r.port.protocol.to_string()) } else { None },
        ip:       if fs.ip       { Some(r.ip.to_string()) }         else { None },
        service:  if fs.service  { r.service.clone() }              else { None },
        product:  if fs.product  { r.product.clone() }              else { None },
        version:  if fs.version  { r.version.clone() }              else { None },
    };
    Ok(serde_json::to_string(&obj)?)
}

fn build_csv_line(r: &ScanResult, fs: &FieldSet) -> String {
    let mut fields: Vec<String> = Vec::new();
    if fs.host     { fields.push(r.host.clone()); }
    if fs.port     { fields.push(r.port.number.to_string()); }
    if fs.protocol { fields.push(r.port.protocol.to_string()); }
    if fs.ip       { fields.push(r.ip.to_string()); }
    if fs.service  { fields.push(r.service.clone().unwrap_or_default()); }
    if fs.product  { fields.push(r.product.clone().unwrap_or_default()); }
    if fs.version  { fields.push(r.version.clone().unwrap_or_default()); }
    fields.join(",")
}

fn build_csv_header(fs: &FieldSet) -> String {
    let mut fields: Vec<&str> = Vec::new();
    if fs.host     { fields.push("host"); }
    if fs.port     { fields.push("port"); }
    if fs.protocol { fields.push("protocol"); }
    if fs.ip       { fields.push("ip"); }
    if fs.service  { fields.push("service"); }
    if fs.product  { fields.push("product"); }
    if fs.version  { fields.push("version"); }
    fields.join(",")
}

// ── Summary helpers ──────────────────────────────────────────────────────────

fn compute_stats(results: &[ScanResult]) -> (usize, usize) {
    let total_ports = results.len();
    let total_hosts = results
        .iter()
        .map(|r| &r.host)
        .collect::<HashSet<_>>()
        .len();
    (total_hosts, total_ports)
}

// ── Public API ────────────────────────────────────────────────────────────────

pub fn write_results(results: &[ScanResult], cfg: &OutputConfig) -> Result<()> {
    let fs = FieldSet::resolve(cfg.include_fields.as_deref(), cfg.exclude_fields.as_deref());

    let mut lines: Vec<String> = Vec::with_capacity(results.len());

    if cfg.json {
        for r in results {
            lines.push(build_json_line(r, &fs)?);
        }
    } else if cfg.csv {
        lines.push(build_csv_header(&fs));
        for r in results {
            lines.push(build_csv_line(r, &fs));
        }
    } else {
        for r in results {
            // Append "(service/version)" suffix when version info is present.
            let suffix = match (&r.service, &r.product, &r.version) {
                (Some(svc), Some(prod), Some(ver)) => {
                    format!(" ({}/{} {})", svc, prod, ver)
                }
                (Some(svc), Some(prod), None) => format!(" ({}/{})", svc, prod),
                (Some(svc), None, Some(ver)) => format!(" ({} {})", svc, ver),
                (Some(svc), None, None) => format!(" ({})", svc),
                _ => String::new(),
            };
            lines.push(format!("{}:{}{}", r.host, r.port.number, suffix));
        }
    }

    // Write to stdout.
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    for line in &lines {
        writeln!(out, "{line}")?;
    }
    drop(out);

    // Optionally write to file as well.
    if let Some(ref path) = cfg.output_file {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(path)?;
        for line in &lines {
            writeln!(f, "{line}")?;
        }
    }

    // ── Post-scan summary to stderr ──────────────────────────────────────────
    if !cfg.silent {
        let (total_hosts, total_ports) = compute_stats(results);
        if cfg.json {
            eprintln!(
                "{{\"summary\":{{\"total_hosts\":{total_hosts},\"total_ports\":{total_ports}}}}}"
            );
        } else {
            eprintln!(
                "[INFO] Found {total_ports} open ports across {total_hosts} hosts"
            );
        }
    }

    Ok(())
}
