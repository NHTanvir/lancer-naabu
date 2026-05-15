/// Return the well-known service name for a port/protocol pair.
///
/// Used by `--service-discovery` (`-sD`) to annotate open ports without
/// performing active probing.
pub fn guess_service(port: u16, protocol: &str) -> Option<&'static str> {
    match (port, protocol) {
        (20, "tcp") => Some("ftp-data"),
        (21, "tcp") => Some("ftp"),
        (22, "tcp") => Some("ssh"),
        (23, "tcp") => Some("telnet"),
        (25, "tcp") => Some("smtp"),
        (53, _) => Some("dns"),
        (67, "udp") => Some("dhcp"),
        (68, "udp") => Some("dhcp"),
        (69, "udp") => Some("tftp"),
        (80, "tcp") => Some("http"),
        (110, "tcp") => Some("pop3"),
        (119, "tcp") => Some("nntp"),
        (123, "udp") => Some("ntp"),
        (143, "tcp") => Some("imap"),
        (161, "udp") => Some("snmp"),
        (389, "tcp") => Some("ldap"),
        (443, "tcp") => Some("https"),
        (445, "tcp") => Some("smb"),
        (465, "tcp") => Some("smtps"),
        (514, "udp") => Some("syslog"),
        (587, "tcp") => Some("submission"),
        (636, "tcp") => Some("ldaps"),
        (993, "tcp") => Some("imaps"),
        (995, "tcp") => Some("pop3s"),
        (1433, "tcp") => Some("mssql"),
        (1521, "tcp") => Some("oracle"),
        (1883, "tcp") => Some("mqtt"),
        (2375, "tcp") => Some("docker"),
        (2376, "tcp") => Some("docker-tls"),
        (3306, "tcp") => Some("mysql"),
        (3389, "tcp") => Some("rdp"),
        (4443, "tcp") => Some("https-alt"),
        (5432, "tcp") => Some("postgresql"),
        (5672, "tcp") => Some("amqp"),
        (5900, "tcp") => Some("vnc"),
        (5985, "tcp") => Some("winrm"),
        (6379, "tcp") => Some("redis"),
        (6443, "tcp") => Some("kubernetes"),
        (7077, "tcp") => Some("spark"),
        (8080, "tcp") => Some("http-proxy"),
        (8443, "tcp") => Some("https-alt"),
        (8888, "tcp") => Some("jupyter"),
        (9000, "tcp") => Some("sonarqube"),
        (9200, "tcp") => Some("elasticsearch"),
        (9300, "tcp") => Some("elasticsearch-cluster"),
        (11211, "tcp") | (11211, "udp") => Some("memcached"),
        (15672, "tcp") => Some("rabbitmq-mgmt"),
        (27017, "tcp") => Some("mongodb"),
        (27018, "tcp") => Some("mongodb-shard"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ssh_port() {
        assert_eq!(guess_service(22, "tcp"), Some("ssh"));
    }

    #[test]
    fn test_http_port() {
        assert_eq!(guess_service(80, "tcp"), Some("http"));
    }

    #[test]
    fn test_https_port() {
        assert_eq!(guess_service(443, "tcp"), Some("https"));
    }

    #[test]
    fn test_dns_any_protocol() {
        assert_eq!(guess_service(53, "tcp"), Some("dns"));
        assert_eq!(guess_service(53, "udp"), Some("dns"));
    }

    #[test]
    fn test_unknown_port() {
        assert_eq!(guess_service(65535, "tcp"), None);
    }

    #[test]
    fn test_mysql_port() {
        assert_eq!(guess_service(3306, "tcp"), Some("mysql"));
    }

    #[test]
    fn test_rdp_port() {
        assert_eq!(guess_service(3389, "tcp"), Some("rdp"));
    }
}
