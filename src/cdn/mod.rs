use ipnet::IpNet;
use std::net::IpAddr;
use std::str::FromStr;

pub struct CdnRange {
    pub provider: &'static str,
    pub cidrs: Vec<IpNet>,
}

pub struct CdnChecker {
    ranges: Vec<CdnRange>,
}

pub struct CdnMatch {
    pub provider: String,
}

/// Parse a static CIDR string slice into a `Vec<IpNet>`, ignoring any that fail.
fn parse_cidrs(raw: &[&'static str]) -> Vec<IpNet> {
    raw.iter()
        .filter_map(|s| IpNet::from_str(s).ok())
        .collect()
}

impl CdnChecker {
    pub fn new() -> Self {
        Self::from_builtin()
    }

    fn from_builtin() -> Self {
        let ranges = vec![
            CdnRange {
                provider: "Cloudflare",
                cidrs: parse_cidrs(&[
                    "103.21.244.0/22",
                    "103.22.200.0/22",
                    "103.31.4.0/22",
                    "104.16.0.0/13",
                    "104.24.0.0/14",
                    "108.162.192.0/18",
                    "131.0.72.0/22",
                    "141.101.64.0/18",
                    "162.158.0.0/15",
                    "172.64.0.0/13",
                    "173.245.48.0/20",
                    "188.114.96.0/20",
                    "190.93.240.0/20",
                    "197.234.240.0/22",
                    "198.41.128.0/17",
                ]),
            },
            CdnRange {
                provider: "Akamai",
                cidrs: parse_cidrs(&[
                    "2.16.0.0/13",
                    "23.0.0.0/12",
                    "23.192.0.0/11",
                    "96.16.0.0/15",
                    "96.6.0.0/15",
                ]),
            },
            CdnRange {
                provider: "Fastly",
                cidrs: parse_cidrs(&[
                    "23.235.32.0/20",
                    "43.249.72.0/22",
                    "103.244.50.0/24",
                    "103.245.222.0/23",
                    "104.156.80.0/20",
                    "151.101.0.0/16",
                    "157.52.64.0/18",
                    "167.82.0.0/17",
                    "185.31.16.0/22",
                ]),
            },
            CdnRange {
                provider: "Amazon CloudFront",
                cidrs: parse_cidrs(&[
                    "13.32.0.0/15",
                    "13.35.0.0/16",
                    "52.84.0.0/15",
                    "52.124.128.0/17",
                    "54.182.0.0/16",
                    "54.192.0.0/16",
                    "204.246.164.0/22",
                    "205.251.192.0/19",
                ]),
            },
        ];

        Self { ranges }
    }

    /// Check if the given IP belongs to a known CDN range.
    /// Returns the first matching provider.
    pub fn check(&self, ip: IpAddr) -> Option<CdnMatch> {
        for range in &self.ranges {
            for cidr in &range.cidrs {
                if cidr.contains(&ip) {
                    return Some(CdnMatch {
                        provider: range.provider.to_string(),
                    });
                }
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cloudflare_range_detected() {
        let checker = CdnChecker::new();
        // 104.16.0.0 is in the Cloudflare 104.16.0.0/13 range
        let ip: IpAddr = "104.16.0.0".parse().unwrap();
        let result = checker.check(ip);
        assert!(result.is_some());
        assert_eq!(result.unwrap().provider, "Cloudflare");
    }

    #[test]
    fn test_non_cdn_ip() {
        let checker = CdnChecker::new();
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        assert!(checker.check(ip).is_none());
    }

    #[test]
    fn test_cloudflare_104_16() {
        let checker = CdnChecker::new();
        let ip: IpAddr = "104.16.0.0".parse().unwrap();
        let m = checker.check(ip).expect("should match Cloudflare");
        assert_eq!(m.provider, "Cloudflare");
    }
}
