/// Minimal embedded probe set in nmap-service-probes format.
///
/// Users can supply a full nmap-service-probes file via `--sV-probes <path>`.
pub const EMBEDDED_PROBES: &str = include_str!("../../probes.txt");
