use anyhow::Result;
use std::net::IpAddr;

#[allow(dead_code)]
pub struct InternetDbResult {
    pub ip: String,
    pub ports: Vec<u16>,
    pub hostnames: Vec<String>,
}

/// Query Shodan InternetDB for the given IP.
///
/// Returns `Ok(None)` if the IP has no record (404).
/// Returns `Ok(Some(...))` with port/hostname data on success.
pub async fn query_internetdb(ip: IpAddr) -> Result<Option<InternetDbResult>> {
    let url = format!("https://internetdb.shodan.io/{}", ip);
    let resp = reqwest::get(&url).await?;
    if resp.status() == reqwest::StatusCode::NOT_FOUND {
        return Ok(None);
    }
    let body: serde_json::Value = resp.json().await?;
    let ports = body["ports"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_u64().map(|n| n as u16))
                .collect()
        })
        .unwrap_or_default();
    let hostnames = body["hostnames"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default();
    Ok(Some(InternetDbResult {
        ip: ip.to_string(),
        ports,
        hostnames,
    }))
}

/// Build the InternetDB URL for a given IP (used in tests / logging).
#[allow(dead_code)]
pub fn internetdb_url(ip: IpAddr) -> String {
    format!("https://internetdb.shodan.io/{}", ip)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_url_construction() {
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        assert_eq!(internetdb_url(ip), "https://internetdb.shodan.io/1.2.3.4");
    }

    #[test]
    fn test_url_ipv6() {
        let ip: IpAddr = "2001:db8::1".parse().unwrap();
        let url = internetdb_url(ip);
        assert!(url.contains("internetdb.shodan.io"));
    }
}
