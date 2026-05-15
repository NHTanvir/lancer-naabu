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
