use clap::Parser;

#[derive(Parser, Debug, Clone)]
#[command(
    name = "lancer-naabu",
    version,
    about = "Rust clone of naabu — fast port scanner",
    long_about = None
)]
pub struct Cli {
    // ─── Input ───────────────────────────────────────────────────────────────
    #[arg(long = "host", help_heading = "Input",
          help = "Comma-separated IPs/CIDRs/hostnames to scan")]
    pub host: Option<String>,

    #[arg(long = "list", short = 'l', help_heading = "Input",
          help = "File containing targets (one per line)")]
    pub list: Option<String>,

    #[arg(long = "eh", help_heading = "Input",
          help = "Exclude host(s) from scan")]
    pub exclude_host: Option<String>,

    #[arg(long = "ef", help_heading = "Input",
          help = "File of hosts to exclude")]
    pub exclude_file: Option<String>,

    #[arg(long = "no-stdin", help_heading = "Input",
          help = "Disable reading targets from stdin")]
    pub no_stdin: bool,

    #[arg(long = "input-read-timeout", help_heading = "Input",
          help = "Timeout (seconds) when reading stdin", default_value = "3")]
    pub input_read_timeout: u64,

    // ─── Port ────────────────────────────────────────────────────────────────
    #[arg(long = "port", short = 'p', help_heading = "Port",
          help = "Ports to scan: 80,443,1-1024,u:53")]
    pub port: Option<String>,

    #[arg(long = "top-ports", short_alias = 't', value_name = "PRESET",
          help_heading = "Port",
          help = "Scan top N ports: 100 | 1000 | full (default: 100)")]
    pub top_ports: Option<String>,

    #[arg(long = "ports-file", help_heading = "Port",
          help = "File containing port spec")]
    pub ports_file: Option<String>,

    #[arg(long = "exclude-ports", help_heading = "Port",
          help = "Ports to exclude from final set")]
    pub exclude_ports: Option<String>,

    #[arg(long = "port-threshold", help_heading = "Port",
          help = "Stop host scan when open port count exceeds threshold")]
    pub port_threshold: Option<u32>,

    // ─── Rate / Concurrency ──────────────────────────────────────────────────
    #[arg(long = "rate", help_heading = "Rate/Concurrency",
          help = "Packets/connections per second", default_value = "1000")]
    pub rate: u32,

    #[arg(short = 'c', help_heading = "Rate/Concurrency",
          help = "Concurrent worker count", default_value = "25")]
    pub workers: usize,

    #[arg(long = "timeout", help_heading = "Rate/Concurrency",
          help = "Connection timeout (ms)", default_value = "1500")]
    pub timeout: u64,

    #[arg(long = "retries", help_heading = "Rate/Concurrency",
          help = "Number of retries on timeout", default_value = "3")]
    pub retries: u32,

    #[arg(long = "warm-up-time", help_heading = "Rate/Concurrency",
          help = "Warm-up time (seconds) before scanning", default_value = "2")]
    pub warm_up_time: u64,

    // ─── Output ──────────────────────────────────────────────────────────────
    #[arg(long = "output", short = 'o', help_heading = "Output",
          help = "Write output to file")]
    pub output: Option<String>,

    #[arg(long = "json", help_heading = "Output",
          help = "Output results as JSON lines")]
    pub json: bool,

    #[arg(long = "csv", help_heading = "Output",
          help = "Output results as CSV")]
    pub csv: bool,

    #[arg(long = "silent", help_heading = "Output",
          help = "Suppress all logging; only print results")]
    pub silent: bool,

    #[arg(short = 'v', help_heading = "Output",
          help = "Verbose output (info level)")]
    pub verbose: bool,

    #[arg(long = "debug", help_heading = "Output",
          help = "Debug output")]
    pub debug: bool,

    #[arg(long = "nc", help_heading = "Output",
          help = "Disable color output")]
    pub no_color: bool,

    #[arg(long = "version-flag", help_heading = "Output",
          help = "Print version and exit")]
    pub version_flag: bool,

    #[arg(long = "list-output-fields", help_heading = "Output",
          help = "List available output fields")]
    pub list_output_fields: bool,

    #[arg(long = "exclude-output-fields", help_heading = "Output",
          help = "Comma-separated output fields to exclude")]
    pub exclude_output_fields: Option<String>,

    // ─── Scan ────────────────────────────────────────────────────────────────
    #[arg(long = "scan-type", short = 's', value_name = "TYPE",
          help_heading = "Scan",
          help = "Scan type: SYN | CONNECT (default: CONNECT)")]
    pub scan_type: Option<String>,

    #[arg(long = "source-ip", help_heading = "Scan",
          help = "Source IP to use for packets")]
    pub source_ip: Option<String>,

    #[arg(long = "interface", short = 'i', help_heading = "Scan",
          help = "Network interface to use")]
    pub interface: Option<String>,

    #[arg(long = "connect-payload", help_heading = "Scan",
          help = "Payload to send on connect")]
    pub connect_payload: Option<String>,

    #[arg(long = "stream", help_heading = "Scan",
          help = "Stream results as they are found")]
    pub stream: bool,

    #[arg(long = "verify", help_heading = "Scan",
          help = "Verify open ports with a second connect")]
    pub verify: bool,

    #[arg(long = "passive", help_heading = "Scan",
          help = "Use passive sources (Shodan etc.)")]
    pub passive: bool,

    #[arg(long = "scan-all-ips", short_alias = 'a', help_heading = "Scan",
          help = "Scan all IPs for a hostname (not just first)")]
    pub scan_all_ips: bool,

    #[arg(long = "iv", value_name = "VER", help_heading = "Scan",
          help = "IP version to prefer: 4 | 6 | 46", default_value = "4")]
    pub ip_version: String,

    // ─── Host-Discovery ──────────────────────────────────────────────────────
    #[arg(long = "host-discovery", short_alias = 'n', help_heading = "Host-Discovery",
          help = "Run host discovery before port scan")]
    pub host_discovery: bool,

    #[arg(long = "skip-host-discovery", help_heading = "Host-Discovery",
          help = "Skip host discovery (treat all hosts as up)")]
    pub skip_host_discovery: bool,

    #[arg(long = "with-host-discovery", help_heading = "Host-Discovery",
          help = "Run host discovery alongside port scan")]
    pub with_host_discovery: bool,

    #[arg(long = "probe-tcp-syn", help_heading = "Host-Discovery",
          help = "Use TCP SYN probes for host discovery")]
    pub probe_tcp_syn: bool,

    #[arg(long = "probe-tcp-ack", help_heading = "Host-Discovery",
          help = "Use TCP ACK probes for host discovery")]
    pub probe_tcp_ack: bool,

    #[arg(long = "probe-icmp-echo", help_heading = "Host-Discovery",
          help = "Use ICMP echo probes for host discovery")]
    pub probe_icmp_echo: bool,

    #[arg(long = "probe-icmp-timestamp", help_heading = "Host-Discovery",
          help = "Use ICMP timestamp probes for host discovery")]
    pub probe_icmp_timestamp: bool,

    #[arg(long = "probe-icmp-address-mask", help_heading = "Host-Discovery",
          help = "Use ICMP address-mask probes for host discovery")]
    pub probe_icmp_address_mask: bool,

    #[arg(long = "arp-ping", help_heading = "Host-Discovery",
          help = "Use ARP ping for host discovery")]
    pub arp_ping: bool,

    #[arg(long = "nd-ping", help_heading = "Host-Discovery",
          help = "Use IPv6 neighbor discovery ping")]
    pub nd_ping: bool,

    #[arg(long = "rev-ptr", help_heading = "Host-Discovery",
          help = "Perform reverse PTR lookup on discovered hosts")]
    pub rev_ptr: bool,

    #[arg(long = "ping", help_heading = "Host-Discovery",
          help = "Ping hosts before scanning")]
    pub ping: bool,

    // ─── Service-Discovery ───────────────────────────────────────────────────
    #[arg(long = "service-discovery", help_heading = "Service-Discovery",
          help = "Enable service discovery")]
    pub service_discovery: bool,

    #[arg(long = "service-version", help_heading = "Service-Discovery",
          help = "Probe for service versions")]
    pub service_version: bool,

    #[arg(long = "sV-fast", help_heading = "Service-Discovery",
          help = "Fast service version detection")]
    pub sv_fast: bool,

    #[arg(long = "sV-timeout", help_heading = "Service-Discovery",
          help = "Timeout (ms) for service version probes")]
    pub sv_timeout: Option<u64>,

    #[arg(long = "sV-workers", help_heading = "Service-Discovery",
          help = "Worker count for service version probes")]
    pub sv_workers: Option<usize>,

    #[arg(long = "sV-probes", help_heading = "Service-Discovery",
          help = "Number of service version probes")]
    pub sv_probes: Option<usize>,

    #[arg(long = "udp-probes", help_heading = "Service-Discovery",
          help = "UDP probe strings")]
    pub udp_probes: Option<String>,

    #[arg(long = "nmap-cli", help_heading = "Service-Discovery",
          help = "nmap CLI arguments for service detection")]
    pub nmap_cli: Option<String>,

    // ─── Optimization ────────────────────────────────────────────────────────
    #[arg(long = "resume", help_heading = "Optimization",
          help = "Resume a previous scan")]
    pub resume: bool,

    #[arg(long = "smart-scan", help_heading = "Optimization",
          help = "Use smart scan heuristics")]
    pub smart_scan: bool,

    #[arg(long = "prediction-threshold", value_name = "N", help_heading = "Optimization",
          help = "Smart scan prediction threshold", default_value = "20")]
    pub prediction_threshold: u32,

    #[arg(long = "exclude-cdn", help_heading = "Optimization",
          help = "Exclude CDN IPs from scan")]
    pub exclude_cdn: bool,

    #[arg(long = "display-cdn", help_heading = "Optimization",
          help = "Show CDN status in output")]
    pub display_cdn: bool,

    // ─── Debug / Cloud ───────────────────────────────────────────────────────
    #[arg(long = "health-check", help_heading = "Debug/Cloud",
          help = "Run a health check and exit")]
    pub health_check: bool,

    #[arg(long = "il", help_heading = "Debug/Cloud",
          help = "List network interfaces and exit")]
    pub list_interfaces: bool,

    #[arg(long = "stats", help_heading = "Debug/Cloud",
          help = "Show scanning statistics")]
    pub stats: bool,

    #[arg(long = "metrics-port", help_heading = "Debug/Cloud",
          help = "Port for Prometheus metrics endpoint", default_value = "63636")]
    pub metrics_port: u16,

    #[arg(long = "config", help_heading = "Debug/Cloud",
          help = "Path to config file")]
    pub config: Option<String>,

    #[arg(long = "auth", help_heading = "Debug/Cloud",
          help = "Auth token for cloud features")]
    pub auth: Option<String>,

    #[arg(long = "dashboard", help_heading = "Debug/Cloud",
          help = "Enable dashboard endpoint")]
    pub dashboard: bool,

    #[arg(long = "team-id", help_heading = "Debug/Cloud",
          help = "Cloud team ID")]
    pub team_id: Option<String>,

    #[arg(long = "asset-id", help_heading = "Debug/Cloud",
          help = "Cloud asset ID")]
    pub asset_id: Option<String>,

    #[arg(long = "asset-name", help_heading = "Debug/Cloud",
          help = "Cloud asset name")]
    pub asset_name: Option<String>,

    #[arg(short = 'r', help_heading = "Debug/Cloud",
          help = "Comma-separated DNS resolvers")]
    pub resolvers: Option<String>,

    #[arg(long = "proxy", help_heading = "Debug/Cloud",
          help = "HTTP/SOCKS5 proxy URL")]
    pub proxy: Option<String>,

    #[arg(long = "proxy-auth", help_heading = "Debug/Cloud",
          help = "Proxy auth credentials (user:pass)")]
    pub proxy_auth: Option<String>,

    #[arg(long = "dns-order", help_heading = "Debug/Cloud",
          help = "DNS query order (ipv4|ipv6|both)")]
    pub dns_order: Option<String>,

    #[arg(long = "system-resolver", help_heading = "Debug/Cloud",
          help = "Use system DNS resolver")]
    pub system_resolver: bool,
}
