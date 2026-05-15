use anyhow::Result;
use crate::scanner::ScanResult;

/// Upload scan results to a PDCP-style dashboard endpoint.
///
/// Currently a stub: logs a warning when no auth key is configured, and
/// an info message otherwise. Actual upload requires a Lancer cloud
/// endpoint to be configured.
pub async fn upload_results(results: &[ScanResult], auth_key: Option<&str>) -> Result<()> {
    if auth_key.is_none() {
        eprintln!(
            "[WARN] --dashboard requires --auth to specify the API key. Skipping upload."
        );
        return Ok(());
    }
    // TODO: actual upload when Lancer cloud endpoint is configured
    eprintln!(
        "[INFO] Dashboard upload: {} results (endpoint not configured)",
        results.len()
    );
    Ok(())
}
