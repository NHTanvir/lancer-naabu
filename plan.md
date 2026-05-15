# RESEARCH DOSSIER: naabu

> Part of the Lancer ecosystem. A Rust clone of ProjectDiscovery's naabu, the fast port scanner. Build with Claude Code.
> Upstream: github.com/projectdiscovery/naabu (Go, v2.6.1 May 2026, 6.0k stars)

## Feature Parity Mandate

**`lancer-naabu` MUST ship with 100% feature parity to the upstream `naabu` tool — every flag, every subcommand, every output format, every probe / detector / module / payload / mode — plus a native Rust GUI on top.** This is not a "subset clone" — this is a full reimplementation in Rust with a GUI wrapper.

### Parity contract

- **Every CLI flag** documented in upstream `naabu --help` (and the long-form man page / docs) must work in `lancer-naabu --cli`.
- **Every output format** the upstream tool emits (text, JSON, XML, CSV, SARIF, custom formats) must round-trip through `lancer-naabu` byte-equivalent where the format allows.
- **Every probe / detector / module / category / payload class / built-in script** must be ported. None silently dropped.
- **Every supported target type / input format / protocol / file format / language** must work.
- **Every configuration option** (config files, env vars, registry / settings entries) must be honoured.
- **Companion binaries / sub-tools** in the upstream suite (if any) must each get their own binary in this workspace.

### GUI on top

Every feature reachable via CLI is also reachable from the GUI (see `## GUI (Lancer-standard pattern)` below). The GUI is not a subset — it is an alternate frontend over the same `core` library that the CLI uses. The `core` crate is GUI-agnostic.

### Verification

- The `## Granular feature catalog` section below enumerates everything that must be supported.
- Reference: `tests/upstream_parity/` will pin upstream flag combinations + canned outputs as parity tests. CI fails if any flag is unsupported or output diverges.
- A `lancer-naabu --self-test` flag runs the full parity matrix against a bundled reference target and prints pass/fail per upstream feature group.

### What is allowed to diverge

- **Performance** — Rust-native, async-first; we are allowed to be faster.
- **Memory footprint** — we are allowed to be smaller.
- **GUI** — entirely new (no upstream GUI to copy except where the upstream ships its own GUI like Zenmap / Wireshark UI / Ghidra GUI / jadx-gui — in which case our GUI must cover every panel the upstream GUI has, plus the Lancer-standard layout from `## GUI` below).
- **AI augmentation** — net-new (see `## AI augmentation ideas`).

### What is NOT allowed to diverge

- Any flag silently dropped, renamed, or behavior-changed compared to upstream.
- Any output format / record schema diverging in field names, types, or semantics.
- Any built-in script / detector / module not ported (mark explicitly with `[N/A — see note]` if genuinely impossible in Rust, e.g. NSE Lua scripts requiring features not in `mlua`).

## What it actually does (1-paragraph)
naabu is a packet-driven TCP port scanner aimed at bug bounty / pentest pipelines. Given a list of hosts (IP, CIDR, ASN, hostname), it scans a configurable port set (default top-100, configurable up to all 65k) and prints `host:port` for each open port. Default mode is `connect` (full TCP handshake, no privileges) but with root/CAP_NET_RAW it can do SYN scan (gopacket+pcap raw sockets at packet rate) which is 5-10× faster. As of 2026 it also supports UDP probes (`-uP`), host-discovery prelude (ICMP/ARP/TCP-SYN/TCP-ACK ping), service-version detection (`-sV` using nmap-service-probes), smart-scan (port-prediction model boosts correlated ports), CDN/WAF exclusion (`-ec`), and PDCP-cloud upload. The output is grep-friendly `1.2.3.4:443` lines for pipelining into httpx/nuclei/etc.

## Internal architecture (file-level, dev branch as of May 2026)

- **`cmd/naabu/main.go`** — entrypoint. Parses options, instantiates `runner.NewRunner`, runs.
- **`pkg/runner/`** — orchestration.
  - `options.go` (~700 LOC) — `Options` struct with **80+ flags** in 9 groups (input/port/rate-limit/output/config/host-discovery/services-discovery/optimization/debug/cloud). `goflags` parsing.
  - `runner.go` — `Runner` holds `*scan.Scanner`, `*ips.IpRanger`, host-discovery state, stream-mode handling. `RunEnumeration` is the main entry; it: (1) parses targets, (2) parses ports, (3) optionally runs host-discovery, (4) chooses scan path (raw or connect), (5) runs scan, (6) optional `-verify` CONNECT re-check, (7) optional `nmap-cli` invocation on results, (8) writes output.
  - `ports.go` — parses `-p 80,443,1-65535,u:53`, expands `-tp top-100/1000/full`. **NmapTop100 and NmapTop1000 are hardcoded comma-separated port strings** (copied verbatim from nmap-services). UDP port prefix `u:53`. Exclude-port handling.
  - `targets.go` — parses single IP, CIDR (via `mapcidr`), hostname (resolves via `-dns-order`), ASN (via `asnmap`). Handles `-eh`/`-ef` exclusions. Stream mode reads STDIN incrementally.
  - `ips.go` — IP rangering (uses `projectdiscovery/ipranger` for hostname↔IP↔CIDR lookup).
  - `fastsend.go` — direct raw-socket SYN sender (bypasses gopacket+channel) for smart-scan path. Pre-computes a SYN packet template and just rewrites IP+port per send.
  - `nmap.go` — shells out to `nmap-cli` after naabu finishes, feeding it the open `host:port` list. **Deprecated** — `-sV` is the preferred path.
  - `output.go` — txt/JSON/CSV writers; field filtering.
  - `resume.go` — `resume.cfg` JSON: `{ip, port}` checkpoints.
  - `smartscan.go` — **2026 feature.** Replaces Blackrock shuffle loop with a priority-queue scan: ports are dequeued in predicted-likelihood order; when a port opens, correlated ports (from `prediction.DefaultModel`) get boosted. See `pkg/prediction/default_model.go` (Set(srcPort, dstPort, probability) entries derived from real-world scan data).
  - `udp_probes.go` — port-specific UDP payloads (DNS, NetBIOS, SNMP, etc.) loaded from nmap-service-probes.
  - `healthcheck.go` — `-hc` diagnostic.
- **`pkg/scan/`** — packet engine (the core).
  - `scan.go` (~700 LOC) — `Scanner` struct holds retries, rate, timeout, port set, `*ipranger.IPRanger`, `*cdncheck.Client`, TCP sequencer, `*ListenHandler`, phase state (`Init|HostDiscovery|Scan|Done|Guard`), workers wait-group, optional `UDPProbeProvider`.
  - `scan_common.go` — shared helpers; `EnableTLSDetection` env-var hook.
  - `scan_raw.go` (Linux/Darwin/Windows-gated) — **raw socket path.** Uses `Mzack9999/gopacket` (PD fork of `google/gopacket`) + `gopacket/pcap`. Sets up `pcap.Handle` per interface, `icmp.PacketConn` for ping, listens via libpcap for SYN-ACK/RST replies. Has **8 ICMP write workers** (concrete fix in issue #1672 — single-writer ICMP serialized the whole scan).
  - `connect.go` — `net.DialTimeout(p.Protocol.String(), host:port, timeout)` per-port. Optional `proxy.SOCKS5` dialer. `ConnectVerify(host, ports)` re-checks open ports after a SYN scan.
  - `arp.go`, `ndp.go`, `ping.go`, `icmp.go` — host-discovery layer-2/3 probes.
  - `tcpsequencer.go` — predictable seq numbers for SYN scan reply correlation.
  - `udpprobe.go` — UDP probing (with optional payload provider).
  - `cdn.go` — `CdnCheck(ip)` wraps `cdncheck.Client.CheckCDN`.
  - `externalip.go` — discovers own external IP for source-IP selection.
  - `option.go` — `Acquire(options)` builds a `ListenHandler` (one of N pre-allocated; uses `freeport.GetFreeTCPPort()` for the SYN-ACK return port).
- **`pkg/fingerprint/`** — service version detection (the `-sV` engine).
  - `parser.go` — parses nmap-service-probes file (the `Probe`/`match`/`softmatch`/`rarity` grammar).
  - `engine.go` — applies probes in rarity order, regex-matches responses.
  - `udp_probes.go` — UDP payload provider; ships nmap-service-probes embedded.
  - `nmap_comparison_test.go` — measures parity with nmap.
- **`pkg/port/port.go`** — `Port { Port int, Protocol Protocol }`.
- **`pkg/protocol/protocol.go`** — `Protocol TCP/UDP`.
- **`pkg/prediction/`** — port correlation model (smart-scan).
  - `default_model.go` — hardcoded correlations: `m.Set(7, 13, 0.5984)` (port 7→13 is 60% likely), `m.Set(21, 80, 0.7957)` (FTP host very likely also has HTTP), etc. Derived from real scan data.
  - `model.go` — `Model::Set/Get/MergeNew/Stats`.
- **`pkg/result/results.go`** — concurrent result store (`HostResult { Host, IPs, Ports }`).
- **`pkg/privileges/`** — OS-specific capability check (`CAP_NET_RAW` on Linux, admin on Windows). Recent harden of `capget` (May 2026 #1691).
- **`pkg/routing/`** — OS-specific default gateway resolution (for raw scan source-iface).
- **`pkg/result/confidence/`** — confidence scoring for SYN-scan ambiguous results.
- **Concurrency model.** Raw scan: separate goroutines for `TransportWriteWorker` (send SYNs), `TransportReadWorker` (recv via pcap), 8 ICMPWriteWorker, EthernetWriteWorker. Connect scan: simple `golang.org/x/sync/semaphore` of N workers. Rate-limiting via `projectdiscovery/ratelimit.Limiter`. Blackrock RNG provides the IP×Port permutation order (so traffic looks pseudo-random vs. sequential).
- **Total LOC.** ~12-14k Go (excluding tests).
- **2024-2026 trends in commits.**
  - **May 2026:** UDP probes (`-uP`) shipped (#1689). ICMP workers fix (#1672). isPrivileged hardening (#1691). Service-version detection migrated to native (no nmap shell-out) — `pkg/fingerprint/` is the new home (#1667).
  - **2025:** smart-scan (`-ss`, `-pt`), PDCP cloud upload integration, `-cdn`/`-ec` integration with cdncheck, ARP/NDP host discovery, IPv6 support.
  - **Performance regression (2025).** v2.3.4 had a CPU-utilization drop bug (vs v2.3.3) — fixed in v2.4. Lesson: benchmark every release.

## Granular feature list

1. `-host 1.2.3.4,acme.com` — comma-separated targets (CIDR, IP, hostname, ASN like `AS123`).
2. `-list hosts.txt` — file targets.
3. `-eh badhost.com` / `-ef excludes.txt` — exclude.
4. `-port 80,443,1-65535,u:53` — explicit ports; `u:53` for UDP.
5. `-top-ports 100|1000|full` — preset (top-100 default).
6. `-exclude-ports 22,3389` — port exclude.
7. `-ports-file ports.txt` — port file.
8. `-port-threshold 50` — skip host after N ports found (likely firewall).
9. `-exclude-cdn` — for CDN/WAF hosts, only scan 80/443.
10. `-display-cdn` (`-cdn`) — annotate output with CDN provider name.
11. `-c 25` — internal worker count.
12. `-rate 1000` — packets/sec global cap (default for SYN: ~1000; for CONNECT: lower).
13. `-output out.txt` / `-json` / `-csv` — output formats.
14. `-list-output-fields` / `-exclude-output-fields field1,field2` — column control.
15. `-scan-type SYN|CONNECT` (`-s`) — scan mode (CONNECT default).
16. `-source-ip x.x.x.x:port` — spoofed source.
17. `-interface eth0` (`-i`) — bind interface.
18. `-connect-payload "..."` — payload to send after CONNECT (for banner-grab triggers).
19. `-nmap-cli "nmap -sV -O"` — post-process via nmap (deprecated, use `-sV`).
20. `-r 8.8.8.8,1.1.1.1` — DNS resolvers.
21. `-proxy host:port` — SOCKS5.
22. `-proxy-auth user:pass` — SOCKS5 auth.
23. `-dns-order p|l|lp|pl` — order of preferring custom (l)ist vs (p)latform DNS.
24. `-system-resolver` (`-sr`) — fallback to OS resolver.
25. `-resume` — read `resume.cfg` JSON.
26. `-stream` — disable resume/nmap/verify/retries/shuffle; immediate stream output.
27. `-passive` — query shodan internetdb (no packets sent).
28. `-iv 4,6` — IP version selection.
29. `-scan-all-ips` (`-sa`) — scan every A/AAAA, not just first.
30. `-input-read-timeout 3m` — stdin read timeout.
31. `-host-discovery` (`-sn`) — only do host discovery, no port scan.
32. `-skip-host-discovery` (`-Pn`) — deprecated; default now skips.
33. `-with-host-discovery` (`-wn`) — opt-in.
34. `-probe-tcp-syn 80,443` (`-ps`) — TCP SYN ping.
35. `-probe-tcp-ack 80,443` (`-pa`) — TCP ACK ping.
36. `-probe-icmp-echo` (`-pe`) — ICMP echo ping.
37. `-probe-icmp-timestamp` (`-pp`) — ICMP timestamp ping.
38. `-probe-icmp-address-mask` (`-pm`) — ICMP address-mask ping.
39. `-arp-ping` (`-arp`) — ARP layer-2 ping.
40. `-nd-ping` (`-nd`) — IPv6 ND ping.
41. `-rev-ptr` — reverse-PTR resolve discovered IPs.
42. `-service-discovery` (`-sD`) — service guess from port number.
43. `-service-version` (`-sV`) — active probe nmap-service-probes-style.
44. `-sV-fast` — only probe port-hinted services.
45. `-sV-timeout 5s` — per-probe timeout.
46. `-sV-workers 25` — concurrent sV workers.
47. `-sV-probes path/to/nmap-service-probes` — override probe file.
48. `-udp-probes` (`-uP`) — UDP send protocol-specific payloads.
49. `-retries 3` — port-scan retries (default 3 for SYN).
50. `-timeout 1000` (ms) — per-port timeout (default 1000ms SYN, 1500ms CONNECT).
51. `-warm-up-time 2` — sec between phases.
52. `-ping` — host alive verification before scan.
53. `-verify` — TCP-CONNECT verify after SYN-scan opens.
54. `-smart-scan` (`-ss`) — predictive scan (port-correlation model).
55. `-prediction-threshold 20` (`-pt`) — min confidence to boost (%, default 20).
56. `-config naabu.yaml` — config file.
57. `-stats` (deprecated; metrics-port now) — stats display.
58. `-metrics-port 63636` (`-mp`) — Prometheus-style metrics endpoint.
59. `-health-check` (`-hc`) — diagnostic.
60. `-auth pdcp_key` — PDCP cloud auth.
61. `-dashboard` (`-pd`) — upload results to PDCP dashboard.
62. `-team-id` / `-asset-id` / `-asset-name` — PDCP grouping.
63. `-no-stdin` — disable stdin.
64. `-il` — list available interfaces.
65. `-silent` / `-v` / `-debug` / `-nc` / `-version` — display.
66. `-no-color` (`-nc`) — disable ANSI color in stdout/stderr (separate flag from `-silent`).
67. `-stats-json` — emit periodic stats as JSON (machine-readable progress feed; pairs with `-stats-interval`).
68. `-stats-interval N` — seconds between stats emissions (default 5s).
69. `-ac` (`-auth-config`) — PDCP credential file path override (separate from `-auth` interactive flow).
70. `-pdu` (`-dashboard-upload`) — upload an existing JSONL output file to the PDCP dashboard (offline-first workflow).
71. `-pd-tags` — comma-separated tags applied when uploading to PDCP dashboard.
72. `-randomize-ip` / `-randomize-ports` — explicit randomization toggle (independent of Blackrock-order default).
73. `-input-read-timeout 3m` (`-irt`) — stdin read timeout for stream mode (default 3m).
74. `-no-stdin` — refuse to read targets from stdin (CI hardening).
75. SDK callback hooks: `Runner.OnResult(func(*Result))` and `Runner.OnReceive(func(host, ip, port))` — library users register callbacks for stream-style consumption. Lancer mirrors these as `Scanner::on_result(impl Fn(Result))` and `Scanner::on_receive(impl Fn(Host,IP,Port))`.
76. `DisableStdout` SDK option — suppresses tool's own stdout when embedded as a library (for GUI / IDE integrations).
77. CPE field on `Service` struct — Common Platform Enumeration string emitted alongside name/version for `-sV` results (consumed by nuclei/CVE pipelines).

**Hidden features.**

- **Stream mode** (`-stream`) doesn't shuffle or rate-correlate; useful for paranoid IDS-evasion (ports look fully random in time too).
- **`-passive` mode** uses Shodan InternetDB (no packets to target) — `https://internetdb.shodan.io/{ip}`.
- **`-cdn` and `-ec`** integrate cdncheck *automatically* — cdncheck is a Go dep of naabu.
- **`-rev-ptr`** auto-resolves PTR for output rows.
- **`-sV-fast`** skips the full nmap-services-probes sweep and only probes the *port-hinted* service (e.g., on port 22 → SSH probe only).
- **TLS detection.** `ENABLE_TLS_DETECTION=true` env-var enables TLS handshake check on CONNECT scan opens.
- **Metrics endpoint.** `:63636/metrics` exposes Prometheus-format scan stats (`packets_sent`, `responses_received`, `time_elapsed`).

## Engineering hard parts

1. **Raw sockets are an OS minefield.** Linux: requires `CAP_NET_RAW` (or root). Windows: requires admin + Npcap installed. macOS: BPF device permissions. The `Mzack9999/gopacket` PD-fork exists *because* upstream gopacket has historical Windows quirks. In Rust: `pnet` works on all three but Npcap install detection needs separate code.
2. **The send-rate / receive-rate balance.** SYN scan at 10k pkt/s with default kernel receive buffer drops SYN-ACKs silently. Must `setsockopt(SO_RCVBUF, ...)` to >= 8MB on the pcap handle. naabu's `chanSize=1000` + `packetSendSize=2500` are empirical sweet spots.
3. **Rate too high → host kernel filters.** Modern Linux `nf_conntrack` will start dropping outbound SYNs over ~50k/s per source IP. naabu's `-rate 1000` default is conservative for this reason. naabu issue #1685 (May 2026): high-rate values cause missed open ports — caller must lower rate.
4. **CDN/WAF detection must happen before full-port scan.** Scanning a Cloudflare-protected `host` for 65k ports just hammers Cloudflare's edge — useless. `-ec` flag drops all ports except 80/443 for CDN hosts. Requires up-to-date cdncheck dataset.
5. **Wildcard DNS resolves everything.** Hostname `foo-bar-quux-not-real.acme.com` may resolve to a wildcard IP, sending the scan against innocent infrastructure. naabu uses an IP-ranger that requires the hostname A-record before scan; user must pre-filter via dnsx.
6. **Blackrock cipher for IP×Port permutation.** Sending SYNs in IP-then-port order trips IDS instantly. `projectdiscovery/blackrock` is a Feistel cipher that uniformly permutes the IP×Port space — same speed, indistinguishable from random sampling.
7. **Smart-scan model is *trained on internet-scale data*.** Just blindly copying naabu's `default_model.go` correlations might over-fit to web-heavy hosts. Re-train per-deployment for best results.
8. **Service version detection (-sV) is fragile.** Nmap's service-probes file is a 2MB Perl-like DSL with `Probe`, `match`, `softmatch`, `rarity`, fallback rules. Parsing it correctly is non-trivial — naabu's `pkg/fingerprint/parser.go` is ~400 LOC and still has edge cases.
9. **UDP scanning is inherently slow.** No response = could be filtered or open. Default UDP scan timeout is 2s with 3 retries → 6s per port. Even at 100 concurrent that's 30 minutes for 1000 ports.
10. **OS-level packet handlers leak.** Long-running scans accumulate `pcap.Handle` file descriptors. naabu pre-allocates `NumberOfHandlers` (10) handles via `buildListenHandler()` at startup; if your code creates a new one per host you'll exhaust FDs.

## Rust library mapping

| Original Go component | Recommended Rust crate | Version | Notes |
| --- | --- | --- | --- |
| `goflags` | `clap` (derive) | 4.5.x | Group via `next_help_heading`. |
| `gologger` | `tracing` + `tracing-subscriber` | 0.1 / 0.3 | — |
| `net.DialTimeout` (CONNECT scan) | `tokio::net::TcpStream::connect` + `tokio::time::timeout` | 1.40+ | Per-port futures + `tokio::task::JoinSet`. |
| `Mzack9999/gopacket` + `pcap` (SYN scan) | `pnet` (with `pnet_packet`, `pnet_datalink`) | 0.35.x | Cross-platform raw socket + packet building. Pair with `pcap` 2.x crate for libpcap binding (or roll a Linux AF_PACKET path for binary). |
| `pcap.OpenLive` | `pcap::Capture::from_device` | 2.x | Use `pcap-async` for tokio integration, or run pcap in a dedicated thread and shovel to `tokio::sync::mpsc`. |
| `gopacket.SerializeLayers` (build SYN) | `pnet::packet::tcp::MutableTcpPacket` + `MutableIpv4Packet` + `ethernet::MutableEthernetPacket` | 0.35 | Manual layer build; same control as gopacket. |
| `mapcidr` (CIDR iter) | `ipnet` | 2.10 | `Ipv4Net::hosts()`. |
| `ipranger` (host↔IP↔CIDR) | `prefix-trie` or `ipnet-trie` | 0.4 / 0.4 | Longest-prefix-match in microseconds. |
| `asnmap` (ASN expansion) | call `https://api.bgpview.io/asn/{asn}/prefixes` via `reqwest`; or embed a `pyasn`-style RIB dump | — | No Rust crate has full ASN→prefix DB. Hit BGPView or RIPEstat REST. |
| `projectdiscovery/freeport` | `tokio::net::TcpListener::bind("127.0.0.1:0")` then read assigned port | 1.40+ | Trivial. |
| `projectdiscovery/blackrock` (RNG shuffler) | port directly: ~50 LOC Feistel | — | No mature Rust crate; copy the Perl-ish Feistel algorithm verbatim. |
| `projectdiscovery/ratelimit` | `governor` | 0.6 | `RateLimiter::direct(Quota::per_second(NonZero::new(rate)))`. |
| `projectdiscovery/networkpolicy` | hand-roll: deny-list + allow-list `prefix-trie` | — | Match user-specified exclusions per packet. |
| `projectdiscovery/cdncheck` (Go dep) | Use **our own** LancerCDN crate (see cdncheck plan.md) | — | Same data file, Rust impl. |
| `projectdiscovery/retryabledns` | `hickory-resolver` with custom retry wrapper | 0.24 | Use it for host resolution + DoH endpoints. |
| ICMP echo | `pnet::transport::transport_channel(layer=IcmpTypes::EchoRequest, ...)` | 0.35 | Multiple ICMP write workers (8) matches naabu's #1672 fix. |
| `proxy.SOCKS5` | `tokio-socks` or `fast-socks5` | 0.5 / 0.10 | SOCKS5 dialer for CONNECT scan only (raw can't proxy). |
| `goleak` | `tokio::test` + `console-subscriber` for task leak | — | — |
| nmap-service-probes parser | hand-roll in `nom` or `winnow` | 0.7 | ~500 LOC parser; output `Vec<Probe { string, ports, rarity, matches }>`. |
| Stream mode prevention of shuffle | `futures::stream::iter(...)` instead of pre-shuffled vec | — | — |
| Output formatting | `serde_json` + custom Display | 1.0 | — |
| Metrics endpoint | `prometheus` crate + `axum` for `/metrics` | 0.13 / 0.7 | Same convention as `:63636`. |

## Data sources (port lists)

| Source | Origin | Content |
| --- | --- | --- |
| **NmapTop100** | Hardcoded in `pkg/runner/ports.go` | `7,9,13,21-23,25-26,37,53,79-81,88,106,110-111,113,119,135,139,143-144,179,199,389,427,443-445,465,513-515,543-544,548,554,587,631,646,873,990,993,995,1025-1029,1110,1433,1720,1723,1755,1900,2000-2001,2049,2121,2717,3000,3128,3306,3389,3986,4899,5000,5009,5051,5060,5101,5190,5357,5432,5631,5666,5800,5900,6000-6001,6646,7070,8000,8008-8009,8080-8081,8443,8888,9100,9999-10000,32768,49152-49157` |
| **NmapTop1000** | Hardcoded in `pkg/runner/ports.go` | (1000 comma-separated ports, derived from nmap's `services` file ranked by frequency) |
| **Full** | Hardcoded | `1-65535` |
| **nmap-service-probes** | Embedded `pkg/fingerprint/nmap-service-probes.txt` (2MB) | Each `Probe TCP HTTP "GET / HTTP/1.0\r\n\r\n"` block followed by `match` lines. Origin: github.com/nmap/nmap/blob/master/nmap-service-probes |
| **UDP probes** | `pkg/fingerprint/udp_probes.go` (curated subset) | DNS query, SNMP getRequest, NetBIOS name service, NTP, etc. |
| **PortPrediction model** | Hardcoded `pkg/prediction/default_model.go` | 100+ port-pair correlations like `(22, 80) → 0.6468`, `(443, 80) → 0.9x`. Derived from internet-scale scan data. |

## 2024-2026 state (what changed)

- **Native service-version detection (May 2026).** Until 2026, `-nmap-cli` was the only way to get banners/versions. v2.6+ ships a native `pkg/fingerprint/` engine that parses nmap-service-probes embedded — no nmap shell dependency.
- **UDP probes (May 2026).** `-uP` sends protocol-specific UDP payloads (DNS, NetBIOS, NTP) instead of empty datagrams — fixes silent ports.
- **Smart-scan (2025).** Replaces Blackrock-order with priority-queue order using a port-correlation model. Finds open ports faster on partial-knowledge targets.
- **PDCP cloud upload (2024).** `-pd` uploads JSONL to ProjectDiscovery dashboard.
- **Performance regression in v2.3.4** (CPU dropped to <1%) — fixed v2.4.
- **Forks worth knowing:**
  - **RustScan** (rust-scan/RustScan) — Rust, ~14k stars, *very fast* connect scan (claims 65k ports in 3 sec) but no SYN, no service detection, no host discovery. The "fast first-pass" tool. Often chained with nmap/naabu for the deep pass.
  - **masscan** (Robert Graham) — C, the OG packet-rate king (millions of pkts/s), but very few features beyond raw discovery.
  - **zmap** (academic) — internet-scale scanning research tool.
  - **nmap** — still the deepest feature set (NSE scripting, OS fingerprinting, IPv6 idiosyncrasies) but slow.
- **Community sentiment.** naabu wins on "best balance of speed and features." RustScan wins on raw speed. nmap wins on depth. Modern recipe: `rustscan -a target | nmap -sV -sC` OR `naabu -host target -sV -json | jq`.
- **CGO-free build (v2.6.0, April 2024).** Removed cgo dependency for cross-platform portability — naabu now ships as a pure static Go binary across Linux/macOS/Windows. Rust port already gets this for free (no cgo concept), but **the libpcap dep is the equivalent boundary** — must offer a pure-Rust `socket2` AF_PACKET fallback path on Linux so users without libpcap installed still get SYN scans.
- **SYN scan on Windows via Npcap (v2.6.0).** Windows raw-socket scanning previously required WinPcap (EOL) or odd shims; v2.6.0 standardised on Npcap with an explicit DLL search-path probe. Rust port must mirror: detect Npcap via `SOFTWARE\Npcap` registry key and `wpcap.dll` presence; emit a clear actionable error (with install URL) when missing.
- **DNS-over-SOCKS5 (v2.6.0).** New `-dns-order p|l|lp|pl` controls custom-resolver-vs-platform-DNS preference; resolver traffic now also flows through `-proxy` SOCKS5 (was direct-only). Rust: `hickory-resolver` + `tokio-socks` for proxied DNS.
- **MAC address detection (v2.3.6).** ARP/NDP discovery now surfaces the MAC alongside the IP in JSON output. Rust mirror: `pnet_datalink` raw-frame inspect to extract `eth.src` on returning ARP/NA frames; emit `mac_address` field in JSON.
- **`Service.CPE` field (v2.5.0).** `-sV` results now include the CPE (Common Platform Enumeration) URI for downstream CVE pipelines. Rust port: parse the `cpe:` field out of nmap-service-probes `match` lines and propagate to `ScanResult { cpe: Option<String> }`.
- **`DisableStdout` SDK option (v2.4.0).** Library consumers (GUIs, IDE plugins) can suppress the tool's own stdout. Rust mirror: `ScannerBuilder::with_disable_stdout(true)` plus structured logging via `tracing` rather than `println!` anywhere in the library.

### Note — 2026-05-30 (deep-research pass)

Re-validated upstream surface against `projectdiscovery/naabu` README (main + dev), v2.6.x release notes, docs site, and 2026 community write-ups. Confirmed all 65 originally-catalogued flags still apply. **Added** 12 missing items to the granular feature list (entries 66-77 above): `-no-color`/`-nc`, `-stats-json`, `-stats-interval`, `-ac`/`-auth-config`, `-pdu`/`-dashboard-upload`, `-pd-tags`, `-randomize-ip`/`-randomize-ports`, `-input-read-timeout`/`-irt`, `-no-stdin`, SDK `OnResult`/`OnReceive` callbacks, `DisableStdout` library option, and the `Service.CPE` field. **Added** 6 missing entries to the 2024-2026 state log (above): CGO-free build, Windows-Npcap SYN path, DNS-over-SOCKS5, MAC address detection, CPE field, and DisableStdout. **Confirmed N/A**: Censys integration is *not* present in upstream naabu — only Shodan InternetDB via `-passive`; Lancer should leave this as a Lancer-net-new under `## AI augmentation ideas` rather than claim parity. Source-port spoofing is rolled into `-source-ip x.x.x.x:port` (port half of the tuple) — upstream does not expose a standalone `-source-port` flag, so do not add one. Exclude lists already covered: `-eh`/`-ef` (hosts), `-exclude-ports` (ports), `-ec`/`-exclude-cdn` (CDN-IP class). No new scan modes beyond CONNECT/SYN/UDP (DNS/passive remain non-active modes). Top-port presets remain `100|1000|full` — no `top-65535` or per-protocol top-list shipped upstream.

### Research note — 2026-05-31 (third-pass deep dive — micro-flags + per-version semantics)

Direct walk of `github.com/projectdiscovery/naabu/releases` v2.3.0 → v2.6.1. Per-version deltas not yet captured:

- **v2.3.4 — Duration parsing.** `-timeout` / `-warm-up-time` / `-stats-interval` / `-input-read-timeout` now accept Go duration strings (`5s`, `100ms`, `2m`, `1h30m`). Plain integers remain interpreted as ms for `-timeout` only (backwards-compat). Our `clap` parser must accept both via `humantime`-backed deserializer; honor the legacy integer-is-ms rule on the `-timeout` flag specifically.
- **v2.3.5 — CONNECT-scan timeout floor.** Default `-timeout` for `-scan-type c` raised from 100ms to 1000ms (loaded-network false-negatives). Our `connect.rs` must use the same default.
- **v2.3.6 — `-pf <path>` port file.** Newline-separated port file (mirrors `-p` semantics, supports `80-443` range syntax per line). Our argparse must accept `-pf` and `--ports-file` aliases.
- **v2.3.6 — `-udp-payloads <path>` custom payload map.** YAML/JSON `{port: hex-payload}` overrides embedded nmap-service-probes defaults (IoT/proprietary protocols). Our `udp_probes.rs` must merge overrides over embedded.
- **v2.3.6 — `-eof field1,field2` field omission.** Drops named JSON fields before printing (saves bytes on huge runs). Schema names: `ip`, `port`, `host`, `timestamp`, `protocol`, `tls`, `mac_address`, `cpe`, `banner`, `up_reason`. Our JSON emitter applies the filter post-serialization.
- **v2.3.6 — `-asset-id`/`-asset-name`/`-team-id` semantics.** When PDCP upload is enabled (`-pdu`), these attach as record metadata; when not, they're silently ignored (no error). Already listed flag-wise but not behaviorally documented.
- **v2.4.0 — `-nmap-cli` shell-quoting fix.** `nmap -oX -` previously broke because naabu reinterpreted the trailing `-`. Now passed verbatim. Our shell-quoting layer must preserve `-`/`--` tokens exactly.
- **v2.4.0 — `-sn` host-discovery JSON schema.** When in host-discovery mode the `port` field is omitted and a new `up_reason: arp|icmp-echo|icmp-timestamp|tcp-ack|udp-unreachable` field appears. CSV header changes correspondingly. Our `output.rs` must branch on `Sn` mode.
- **v2.6.0 — `pkg/runner` SDK observer hooks.** `OnResult(*Result)` and `OnReceive(*Result)` callbacks let library consumers integrate without subprocess fork+exec. Our Rust API exposes the equivalent as a trait: `trait NaabuObserver { fn on_result(&self, r: &PortResult); fn on_receive(&self, r: &PortResult); }`, registered on the `Runner` builder. Plan mentions these but adds no signature.
- **v2.6.0 — Predictive scanning (`-smart-scan` / `-ss`) algorithm.** Conditional probability model: P(port_Y_open | port_X_open) precomputed from millions of public scans. Algorithm: scan an anchor set (default top-50), feed observed open ports into the model, schedule predicted high-probability ports next, time-bounded by `-smart-scan-timeout` (default 30s). Our `predict.rs` must ship the precomputed `port_correlation.bin` (~200 KB) and the inference loop.
- **v2.6.x — Deterministic-seed `-randomize-ports`.** Optional `-seed N` reproduces randomized port order across runs (CI parity diffs). Add to randomizer RNG init.
- **v2.6.x — `Service.Banner` field.** Opportunistic first-packet text capture during `-sV`, distinct from full version detection. Our `ScanResult` includes `banner: Option<String>` alongside the already-listed `cpe: Option<String>`.

Sources: [naabu releases](https://github.com/projectdiscovery/naabu/releases), [naabu README](https://github.com/projectdiscovery/naabu/blob/main/README.md), [naabu install/use guide 2026](https://ringsafe.in/naabu/).

## Real-world pipeline patterns

```bash
# Canonical: subfinder → dnsx → naabu → httpx
subfinder -d acme.com -silent \
  | dnsx -silent -a -resp-only \
  | naabu -top-ports 1000 -ec -rate 5000 -silent \
  | httpx -silent -title -tech-detect

# Top-1000 + service-version
naabu -host acme.com -top-ports 1000 -sV -json -o naabu.json

# Find admin panels
naabu -list hosts.txt -p 3000,3001,4000,5000,5601,5900,8000-8090,8443,8888,9000,9090,9200 -silent

# Bulk recon with CDN skip + smart-scan
naabu -list assets.txt -p - -ec -ss -pt 30 -rate 2000 -silent

# IPv6-aware
naabu -host acme.com -iv 4,6 -silent

# UDP scan with protocol probes
naabu -host acme.com -p u:53,u:67,u:69,u:123,u:161,u:500,u:1900 -uP -silent

# Passive only
naabu -host 1.2.3.4 -passive

# Host discovery only (find live hosts in /16)
naabu -host 10.0.0.0/16 -sn -arp -pe -silent
```

**Failure modes in production:**

- **Cloudflare-protected target.** Open ports include 80/443/8080/2052/2053/2082/2083/2086/2087/2095/2096/8443/8880 (CF allow list) — none actually reachable. Solution: `-ec` or pre-filter via cdncheck.
- **Stateful firewall sees scan, blocks source IP for the day.** Use `-rate` below ~200 and randomize source-port; for stealth, `-stream` disables shuffle (counter-intuitive but trips less heuristic alerts on some IDSs).
- **NAT timeouts.** Default `-timeout 1000` is okay for SYN but for high-RTT (overseas) you'll miss SYN-ACKs. Bump to 3000 for paranoia.
- **macOS BPF.** Without `chmod g+rw /dev/bpf*` the SYN scan silently falls back to CONNECT.

## Bug bounty value + AI augmentation ideas

**Why a hunter cares in 2026.**

Port scanning is the *second* recon phase (after subdomain enum). It uncovers:
- **Forgotten admin panels** on non-standard ports (3000/Grafana, 5601/Kibana, 8090/Confluence, 9200/Elasticsearch).
- **Database exposures** (3306/MySQL, 5432/Postgres, 6379/Redis, 27017/MongoDB, 9042/Cassandra) — often Internet-exposed with default creds.
- **Backup/dev services** (8080/Jenkins, 8081/Nexus, 3306/MySQL, 6379/Redis with no auth).
- **VPN endpoints** (500/IKE, 4500/IPsec NAT-T, 1701/L2TP).
- **Old/insecure mgmt** (23/Telnet, 161/SNMP with `public`, 21/FTP anon, 5900/VNC no-auth).
- **Container/cloud APIs** (2375/Docker, 6443/k8s, 10250/Kubelet, 8500/Consul).
- **Cache poisoning vectors** (11211/Memcached UDP amplification).

**AI augmentation opportunities (Lancer differentiator):**

1. **Service-port reasoning.** Given `host:port` list, AI infers tech stack + likely CVEs: "saw `9200`, `5601` → ELK stack — check for unauth `_cluster/state`, CVE-2015-1427 dynamic script RCE on old versions." Output a ranked list of hypotheses + nuclei templates to try.
2. **Smart-scan model retraining.** Continuously refine `prediction::DefaultModel` from your own scan corpus — port correlations differ per industry (FinTech vs SaaS vs E-comm).
3. **Stealthy schedule planner.** AI computes the ideal `-rate`/`-c` for the target tier (small startup vs Cloudflare-fronted FAANG) to minimize block-prob while maximizing yield.
4. **Anomalous-port flagger.** Out of 1000 hosts, 998 have `:443` open and 2 also have `:31337` — surface the outliers, those are usually the bugs.
5. **CVE-aware port prioritization.** "There's a current 0-day on port X service" → bump that port to the front of the queue for all your scans this week.

## Implementation phases (10-week plan)

### Phase 0 — Skeleton & connect scan (Week 1)
- `cargo new lancerscan`. `clap` with 9 groups (input/port/rate/output/scan-type/host-discovery/services/optimization/debug).
- Target parser: single IP, CIDR (`ipnet::Ipv4Net::hosts`), hostname (resolve via `hickory-resolver`).
- Port parser: range, list, top-100 (hardcode NmapTop100 verbatim from naabu).
- TCP CONNECT scan: `tokio::task::JoinSet` of `tokio::net::TcpStream::connect` with `tokio::time::timeout`. `governor::RateLimiter` global rate cap.
- Output: `host:port` per line (stdout default).
- Deliverable: `lancerscan -host scanme.nmap.org -top-ports 100 -silent` returns open ports in ~5 sec.

### Phase 1 — Port spec completeness, exclude, output formats (Week 2)
- All port-spec forms: `1-65535`, `80,443,u:53`, `-tp full|1000`, `-ports-file`, `-exclude-ports`.
- Output formats: txt, JSON, JSONL, CSV. Field control (`-list-output-fields`, `-exclude-output-fields`).
- `-resume`: write `resume.json` checkpoints; resume from last unscanned `(host,port)`.
- Deliverable: feature parity with naabu's CLI surface for CONNECT scan.

### Phase 2 — Rate limiting + retries + verify (Week 3)
- Per-host token bucket + global token bucket (`governor::Keyed`).
- `-retries N`: re-queue closed-result ports up to N times.
- `-verify`: post-scan re-check open ports (catches transient false-positives).
- `-port-threshold N`: stop scanning host after N opens (firewall heuristic).
- Adaptive backoff on `EHOSTUNREACH`, `ETIMEDOUT`, `ECONNRESET` bursts.
- Deliverable: `-rate 50 -retries 3 -verify` reliably finds same ports nmap does.

### Phase 3 — Host discovery (Week 4)
- ICMP echo via `pnet::transport::transport_channel(EchoRequest)` — needs raw socket cap.
- TCP SYN/ACK ping (raw SYN to port 80/443, look for SYN-ACK or RST).
- ARP ping on local subnet via `pnet::datalink::channel`.
- IPv6 ND ping.
- `-sn` mode (host-discovery only, no port scan).
- `-Pn` skip (default in 2026).
- Deliverable: `lancerscan -host 192.168.1.0/24 -sn -arp -pe` lists live hosts.

### Phase 4 — SYN scan (raw socket) (Week 5-6)
- Capability check: `caps::has_cap(CAP_NET_RAW)` on Linux, `IsUserAnAdmin` on Windows, BPF check on macOS. Fall back to CONNECT with clear warning.
- `pcap::Capture` for receive (gated on libpcap install detection).
- `pnet::transport::transport_channel(layer=IPv4 + transport_protocol=TCP)` for send. Pre-built SYN template, rewrite IP+port per send (mirrors naabu's `fastsend.go`).
- `TCPSequencer` for unique seq numbers per (host, port).
- Blackrock Feistel shuffle to randomize (host × port) iteration order (port the ~50 LOC from `projectdiscovery/blackrock`).
- 8 ICMP write workers (matches naabu's #1672 fix).
- Receive loop: pcap BPF filter `tcp[tcpflags] & (tcp-ack|tcp-syn) = (tcp-ack|tcp-syn)` for SYN-ACK; correlate by `(src_ip, src_port, ack=our_seq+1)`.
- Deliverable: `lancerscan -s SYN -host scanme.nmap.org -p 1-65535` completes in <10 sec (vs CONNECT's 60s).

### Phase 5 — UDP + UDP probes (Week 7)
- UDP scan (longer timeout, ICMP-port-unreachable detection = closed; no response = open|filtered).
- Embed nmap-service-probes UDP section; per-port payload provider.
- `-uP` flag.
- Deliverable: `lancerscan -p u:53,u:161,u:123 -uP` reliably detects DNS/SNMP/NTP.

### Phase 6 — Service version (-sV) (Week 8)
- Parse nmap-service-probes (embed via `include_str!`). Build `Vec<Probe { string, ports, rarity, matches: Vec<Regex> }>`.
- For each open port, send probe matching the port number first; on no match, sweep by rarity.
- `-sV-fast` (port-hinted only), `-sV-timeout`, `-sV-workers`.
- TLS detection: on ports 443/8443/etc., do a TLS handshake to get cert details.
- Deliverable: `lancerscan -host acme.com -sV` outputs `1.2.3.4:443 https openssl 1.1.1k`.

### Phase 7 — CDN/WAF integration + cdncheck (Week 9)
- Embed LancerCDN crate (sibling project). On each target IP, check `cdn.match(ip)`.
- `-ec` (exclude CDN): for matched IPs, restrict to 80/443.
- `-cdn` (display): annotate output with provider name.
- `-passive`: query `https://internetdb.shodan.io/{ip}` instead of sending packets.
- Deliverable: `lancerscan -list assets.txt -ec -cdn` skips full-port-scan on Cloudflare IPs.

### Phase 8 — Smart-scan + metrics + PDCP-style upload (Week 9-10)
- Port-prediction model: hardcode the correlations from `pkg/prediction/default_model.go`. Priority queue per-host.
- On open-port discovery, boost correlated ports' priority (re-heapify).
- `-ss` smart-scan, `-pt` threshold.
- Metrics endpoint: `axum` `:63636/metrics` exposing Prometheus stats.
- Optional `-dashboard`: upload JSONL to Lancer cloud dashboard.
- Deliverable: `-ss` finds open ports 1.5-2× faster on real-world targets vs random.

### Phase 9 — Lancer integration + polish (Week 10)
- Library API (`lib.rs`): `Scanner::new(opts).scan(targets, ports).await -> impl Stream<Item=ScanResult>`. Lancer §37 Bulk Probe calls this.
- Cross-platform release: musl Linux, glibc Linux, macOS arm64+x86_64, Windows (with Npcap detection).
- Healthcheck command (`-hc`): permission check, libpcap detection, default-route detection.
- Deliverable: `cargo install lancerscan` works on all platforms.

## CLAUDE.md to seed in the clone repo
```
This project = a naabu clone in Rust ("lancerscan").
- Default scan: TCP CONNECT (no privileges). SYN scan via pnet + libpcap, gated on CAP_NET_RAW / admin / BPF.
- Hardcode NmapTop100, NmapTop1000 verbatim from upstream pkg/runner/ports.go.
- Embed nmap-service-probes via include_str! for -sV.
- Rate-limit via governor (per-host + global). Default -rate is conservative (issue #1685: high rates miss opens).
- Pcap receive in a dedicated thread → tokio mpsc → result fan-out.
- Use Blackrock Feistel shuffle (port the ~50 LOC) for IP×Port permutation order.
- 8 ICMP write workers (naabu #1672 fix).
- Library API in lib.rs (Scanner::scan returns Stream); Lancer §37 imports.
- ENABLE_TLS_DETECTION env-var triggers TLS handshake on opens.
- Output is always sorted host:port, also JSON/CSV with field control.
- NEVER block on a single slow target — per-port timeout + per-host port-threshold + overall ctx cancellation.
```

---

## GUI (Lancer-standard pattern)

`lancer-naabu` ships as a **native GUI application** by default. The CLI surface listed in `## Granular feature catalog` is still available behind a `--cli` flag (or via the `lancer-naabu-cli` companion binary), but the **plain `lancer-naabu` invocation opens a native desktop window**, matching every other tool in the Lancer ecosystem. No terminal-only mode.

### Framework

Pure-Rust GUI stack — no JavaScript, no Node, single static binary:

| Crate | Role |
|-------|------|
| `eframe` | Cross-platform window + event loop wrapper around `egui` |
| `egui` | Immediate-mode UI widgets (panels, tables, forms, menus, drag-and-drop) |
| `egui_extras` | Sortable tables, image loaders, syntax highlighting, date pickers |
| `egui_plot` | Charts, graphs, timelines (histograms, activity meters, progress) |
| `rfd` | Native file/folder pickers (open file, save dialog) |
| `directories` | Per-OS config dir (`~/.config/lancer-naabu/`, `%APPDATA%\lancer-naabu\`, etc.) |
| `image` | Screenshot / preview rendering inside egui |
| `arboard` | Clipboard read/write for "copy result" actions |
| `muda` | Native menu bar (Linux / macOS / Windows) |
| `egui-notify` | Toast notifications |

Optional dark/light theme persisted to `lancer-naabu-config.json` via `serde_json`.

### Window layout

Three-pane layout matching the Lancer mothership GUI:

```
┌─────────────────────────────────────────────────────────────────────┐
│  File   Tools   Settings   Help                              [≡]    │
├──────────┬────────────────────────────────────────┬─────────────────┤
│          │                                        │                 │
│  Inputs  │           Main view                    │  Detail pane    │
│  / jobs  │  (table of results / source tree /     │  (full record / │
│  / scope │   findings list / packet list / etc.)  │   bytes / src / │
│          │                                        │   remediation)  │
│          │                                        │                 │
├──────────┴────────────────────────────────────────┴─────────────────┤
│  Status: idle           Items: 0          [Open]  [Run]  [Export]   │
└─────────────────────────────────────────────────────────────────────┘
```

- **Left sidebar (200-300px)** — inputs / queued jobs / scope / target list. Drag-and-drop accepted.
- **Center pane (flexible)** — primary result view appropriate to the tool (table for findings, tree for hierarchical data, code editor for source).
- **Right pane (300-400px, collapsible)** — full detail of the currently-selected item.
- **Top menu bar** — File (Open / Save / Export / Recent / Quit), Tools (per-tool actions), Settings (theme, fonts, integrations), Help (About / Docs).
- **Bottom status bar** — current activity, item counts, primary action buttons.

### Cross-tool integration with Lancer + the other 29 clones

Every Lancer-clone GUI exposes a small local HTTP server on a port auto-allocated at launch (`127.0.0.1:<port>`, written to `%TEMP%/lancer-naabu.port`):

- The main Lancer GUI discovers running tools by scanning `%TEMP%/lancer-*.port` and lists them in its sidebar.
- Right-clicking any item in any tool can "Send to <other Lancer tool>" — the receiving tool fetches the payload via its own HTTP endpoint.
- A future "Lancer Hub" tray shell can launch / focus any of the 30 GUIs from one menu.
- HTTP endpoints exposed:
  - `GET  /v1/state` — current jobs / progress
  - `POST /v1/import` — accept a target / file / record from another Lancer tool
  - `GET  /v1/export?format=json|csv|sarif|markdown` — pull the current result set in a portable format

### Async work + responsiveness

- Long-running scans run on a Tokio task pool; the GUI thread only renders.
- Progress propagates via `crossbeam::channel` from worker → UI.
- A `Stop` button cancels in-flight work via a `CancellationToken`.
- All file I/O / network I/O / subprocess work goes through async channels — the egui thread never blocks.

### Build output

The existing `build.bat` / `build-windows.bat` / `build-linux.sh` already produce a single binary. With `eframe` linked, the same binary is the GUI app.

- Windows: `build\lancer-naabu.exe` (double-click opens the GUI window).
- Linux: `build/lancer-naabu` (also installable as a `.desktop` entry via `build-linux.sh --install`).
- macOS: `build/lancer-naabu` (bundled into `lancer-naabu.app` via `cargo-bundle` in the `build-mac.sh` companion).

For CI / headless / scripting, pass `--cli` to fall through to the CLI surface from `## Granular feature catalog`.

## Build Setup (Lancer-standard pattern)

This clone follows the same build pattern as the main Lancer project — single `.exe` output via `build.bat` on Windows, `.so/elf` via `build-linux.sh` on Linux.

### Project layout

```
lancer-naabu/
├── Cargo.toml              # single-crate Rust project
├── Cargo.lock              # committed (binary, not library)
├── src/
│   └── main.rs             # entry point (scaffold)
├── build.bat               # Windows build → build/lancer-naabu.exe
├── build-windows.bat       # Windows packaged dist build → dist/lancer-naabu-windows-x86_64/
├── build-linux.sh          # Linux build → build/lancer-naabu
├── .gitignore              # plan.md (local-only) + target/ + build/ + dist/
├── README.md               # public-facing (pushed to GitHub)
└── plan.md                 # this file (gitignored — local blueprint, never pushed)
```

### Build commands

**Windows (double-click `build.bat`):**
```
build.bat
```
Produces `build\lancer-naabu.exe`. Pauses at end so the window stays open.

**Windows (packaged dist):**
```
build-windows.bat
```
Produces `dist\lancer-naabu-windows-x86_64\bin\lancer-naabu.exe` plus LICENSE/README — ready to zip.

**Linux / macOS:**
```bash
./build-linux.sh
```
Produces `build/lancer-naabu`.

### Requirements
- Rust toolchain (https://rustup.rs)
- Windows: Visual C++ Build Tools 2019/2022 (needed by some crates)

### CI

The build pattern is intentionally identical across Lancer and all 19 clones, so a single Jenkins/GitHub Actions matrix can build everything by calling `build-windows.bat` or `build-linux.sh` per repo.
