/// Returns a UDP probe payload for the given port number.
/// Based on common protocol probes (DNS, SNMP, NTP, NetBIOS, IKE, SSDP).
pub fn get_probe_payload(port: u16) -> &'static [u8] {
    match port {
        53   => DNS_QUERY,
        161  => SNMP_REQUEST,
        123  => NTP_REQUEST,
        137  => NETBIOS_NS,
        500  => IKE_INIT,
        1900 => SSDP_SEARCH,
        _    => b"",
    }
}

// DNS query for "version.bind" IN TXT CH
const DNS_QUERY: &[u8] = &[
    0x00, 0x00, // Transaction ID
    0x01, 0x00, // Flags: standard query
    0x00, 0x01, // Questions: 1
    0x00, 0x00, // Answer RRs: 0
    0x00, 0x00, // Authority RRs: 0
    0x00, 0x00, // Additional RRs: 0
    // Query: version.bind IN TXT
    0x07, b'v', b'e', b'r', b's', b'i', b'o', b'n',
    0x04, b'b', b'i', b'n', b'd', 0x00,
    0x00, 0x10, // Type: TXT
    0x00, 0x03, // Class: CH
];

// SNMP v1 GetRequest for sysDescr.0, community "public"
const SNMP_REQUEST: &[u8] = &[
    0x30, 0x26, // SEQUENCE
    0x02, 0x01, 0x01, // version: 1
    0x04, 0x06, b'p', b'u', b'b', b'l', b'i', b'c', // community: "public"
    0xa0, 0x19, // GetRequest-PDU
    0x02, 0x04, 0x00, 0x00, 0x00, 0x01, // request-id: 1
    0x02, 0x01, 0x00, // error-status: 0
    0x02, 0x01, 0x00, // error-index: 0
    0x30, 0x0b, // variable-bindings
    0x30, 0x09, 0x06, 0x05, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x05, 0x00, // sysDescr.0
];

// NTP client request (version 4, mode 3)
const NTP_REQUEST: &[u8] = &[
    0xe3, 0x00, 0x06, 0xec, // LI=3, VN=4, Mode=3 (client), stratum=0, poll=6, precision=-20
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // root delay, dispersion
    0x00, 0x00, 0x00, 0x00, // reference ID
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // reference timestamp
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // originate timestamp
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // receive timestamp
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // transmit timestamp
];

// NetBIOS Name Service query for wildcard "*"
const NETBIOS_NS: &[u8] = &[
    0x82, 0x28, 0x00, 0x00, 0x00, 0x01, // Transaction ID + flags + questions
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x20, 0x43, 0x4b, 0x41, 0x41, 0x41, 0x41, 0x41, // encoded name *
    0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
    0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
    0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
    0x41, 0x41, 0x00, 0x00, 0x21, 0x00, 0x01, // type NB, class IN
];

// IKEv1 SA proposal (simplified 28-byte initiator packet)
const IKE_INIT: &[u8] = &[
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // initiator SPI
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // responder SPI
    0x01, 0x10, 0x02, 0x00, // exchange type SA, version 1.0
    0x00, 0x00, 0x00, 0x00, // flags, message ID
    0x00, 0x00, 0x00, 0x1c, // total length 28
];

// SSDP M-SEARCH discovery
const SSDP_SEARCH: &[u8] =
    b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: ssdp:all\r\n\r\n";

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dns_probe_is_non_empty() {
        let payload = get_probe_payload(53);
        assert!(!payload.is_empty(), "DNS probe should be non-empty");
        // DNS query should start with two-byte transaction ID (0x00, 0x00)
        assert_eq!(payload[0], 0x00);
    }

    #[test]
    fn snmp_probe_is_non_empty() {
        let payload = get_probe_payload(161);
        assert!(!payload.is_empty());
    }

    #[test]
    fn ntp_probe_is_non_empty() {
        let payload = get_probe_payload(123);
        assert!(!payload.is_empty());
    }

    #[test]
    fn unknown_port_returns_empty() {
        let payload = get_probe_payload(999);
        assert!(payload.is_empty(), "unknown port should return empty slice");
    }

    #[test]
    fn unknown_port_12345_returns_empty() {
        assert!(get_probe_payload(12345).is_empty());
    }
}
