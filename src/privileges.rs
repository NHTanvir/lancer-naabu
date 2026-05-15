/// Returns `true` when the current process has the privileges required
/// to open raw sockets (ICMP, ARP, SYN-scan, etc.).
///
/// * Windows — conservative `false`; raw-socket support requires Npcap and an
///   admin token, neither of which is easy to detect without pulling in winapi.
///   Phase 4 will add a proper `IsUserAnAdmin()` check.
/// * Unix — check if the effective UID is 0.  `CAP_NET_RAW` without root is
///   not detected here; Phase 4 will use the `caps` crate for that.
pub fn is_privileged() -> bool {
    #[cfg(windows)]
    {
        // Conservative: assume we are NOT privileged.
        // Phase 4 will use IsUserAnAdmin() / try-bind a raw socket.
        false
    }

    #[cfg(unix)]
    {
        // SAFETY: getuid() is always safe to call.
        unsafe { libc::getuid() == 0 }
    }
}

/// Returns `Ok(())` if SYN scan should be available, or `Err(reason)` if not.
///
/// Checks:
///   1. The `raw_scan` feature must be compiled in.
///   2. The process must be running with elevated privileges.
pub fn check_syn_scan_available() -> Result<(), String> {
    #[cfg(not(feature = "raw_scan"))]
    return Err("raw_scan feature not enabled at compile time".to_string());

    #[cfg(feature = "raw_scan")]
    {
        if !is_privileged() {
            return Err(
                "SYN scan requires elevated privileges (admin/root)".to_string(),
            );
        }
        // Basic sanity-check: enumerate interfaces via pnet_datalink.
        // If this panics or returns empty the OS likely has no raw-socket support.
        let ifaces = pnet_datalink::interfaces();
        if ifaces.is_empty() {
            return Err(
                "no network interfaces found — cannot perform SYN scan".to_string(),
            );
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_syn_scan_available_without_feature_returns_err() {
        // When compiled without raw_scan the function must return Err.
        #[cfg(not(feature = "raw_scan"))]
        {
            let result = check_syn_scan_available();
            assert!(result.is_err());
            assert!(result
                .unwrap_err()
                .contains("raw_scan feature not enabled"));
        }
        // When compiled with raw_scan the function returns Err on an
        // unprivileged process (which is the typical CI environment).
        #[cfg(feature = "raw_scan")]
        {
            // We can't guarantee privileges in tests, so just ensure it doesn't panic.
            let _ = check_syn_scan_available();
        }
    }
}
