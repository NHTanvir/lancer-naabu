use crate::scanner::ScanResult;
use anyhow::Result;
use serde::Serialize;
use std::io::Write;

#[derive(Serialize)]
struct JsonResult<'a> {
    host: &'a str,
    port: u16,
    protocol: &'a str,
}

pub struct OutputConfig {
    pub json: bool,
    pub csv: bool,
    #[allow(dead_code)]
    pub silent: bool,
    pub output_file: Option<String>,
}

pub fn write_results(results: &[ScanResult], cfg: &OutputConfig) -> Result<()> {
    // Collect all formatted lines first, then write to file if requested
    let mut lines: Vec<String> = Vec::with_capacity(results.len());

    if cfg.json {
        for r in results {
            let obj = JsonResult {
                host: &r.host,
                port: r.port.number,
                protocol: &r.port.protocol.to_string(),
            };
            lines.push(serde_json::to_string(&obj)?);
        }
    } else if cfg.csv {
        lines.push("host,port,protocol".to_string());
        for r in results {
            lines.push(format!("{},{},{}", r.host, r.port.number, r.port.protocol));
        }
    } else {
        for r in results {
            lines.push(format!("{}:{}", r.host, r.port.number));
        }
    }

    // Write to stdout
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    for line in &lines {
        writeln!(out, "{line}")?;
    }

    // Optionally write to file as well
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

    Ok(())
}
