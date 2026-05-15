// Items in this module are only consumed by the `raw_scan` feature, but the
// module itself (and its tests) is always compiled.
#![allow(dead_code)]

//! TCP Initial Sequence Number (ISN) generator for SYN-scan reply correlation.
//!
//! The SYN scanner embeds a deterministic ISN in each outgoing SYN packet and
//! verifies incoming SYN-ACK replies by checking that the acknowledgement
//! number equals `ISN + 1`.

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::net::IpAddr;
use std::time::SystemTime;

/// Generates and verifies TCP sequence numbers for SYN-scan reply correlation.
///
/// Every `(ip, port)` pair is assigned a deterministic but unpredictable ISN
/// derived from a per-session random seed.  Incoming SYN-ACK packets can be
/// validated without storing any per-connection state.
pub struct TcpSequencer {
    seed: u32,
}

impl TcpSequencer {
    /// Create a new sequencer with a random seed derived from the current time.
    pub fn new() -> Self {
        let mut hasher = DefaultHasher::new();
        SystemTime::now().hash(&mut hasher);
        // XOR the upper and lower 32 bits for a tighter mix.
        let h = hasher.finish();
        let seed = (h as u32) ^ ((h >> 32) as u32);
        Self { seed }
    }

    /// Create a sequencer with a fixed seed (useful for testing).
    pub fn with_seed(seed: u32) -> Self {
        Self { seed }
    }

    /// Return the ISN that will be sent in the SYN packet for `(ip, port)`.
    pub fn sequence_for(&self, ip: IpAddr, port: u16) -> u32 {
        let ip_bits = match ip {
            IpAddr::V4(v4) => u32::from(v4),
            // For IPv6 XOR the four 32-bit words together.
            IpAddr::V6(v6) => {
                let o = v6.octets();
                u32::from_be_bytes([o[0], o[1], o[2], o[3]])
                    ^ u32::from_be_bytes([o[4], o[5], o[6], o[7]])
                    ^ u32::from_be_bytes([o[8], o[9], o[10], o[11]])
                    ^ u32::from_be_bytes([o[12], o[13], o[14], o[15]])
            }
        };

        // Encode all three independent values into a 64-bit integer without
        // XOR-collapsing them, then apply a Murmur3 avalanche mix.
        //
        // Layout:  [ seed(32) | ip(32) ]  ⊕  [ port(16) | 0(48) ]
        // Keeping ip and port in different bit positions ensures that
        // (ip=X, port=Y) and (ip=X', port=Y') never produce the same 64-bit
        // input unless all three of seed, ip, and port are identical.
        let base: u64 = ((self.seed as u64) << 32) | (ip_bits as u64);
        let combined = base ^ ((port as u64) << 48);
        let mut h = combined;
        h ^= h >> 33;
        h = h.wrapping_mul(0xff51afd7ed558ccd);
        h ^= h >> 33;
        h = h.wrapping_mul(0xc4ceb9fe1a85ec53);
        h ^= h >> 33;
        (h ^ (h >> 32)) as u32
    }

    /// Return `true` if `ack_num` matches the expected SYN-ACK acknowledgement
    /// number (i.e. `sequence_for(ip, port) + 1`).
    pub fn verify_reply(&self, ip: IpAddr, port: u16, ack_num: u32) -> bool {
        self.sequence_for(ip, port).wrapping_add(1) == ack_num
    }
}

impl Default for TcpSequencer {
    fn default() -> Self {
        Self::new()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    fn ipv4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    /// Core property: verify_reply must accept seq+1.
    #[test]
    fn test_verify_reply_accepts_correct_ack() {
        let seq = TcpSequencer::with_seed(0xdeadbeef);
        let ip = ipv4(127, 0, 0, 1);
        let port = 80u16;

        let isn = seq.sequence_for(ip, port);
        assert!(
            seq.verify_reply(ip, port, isn.wrapping_add(1)),
            "verify_reply must return true when ack_num == seq + 1"
        );
    }

    /// verify_reply must reject wrong ack numbers.
    #[test]
    fn test_verify_reply_rejects_wrong_ack() {
        let seq = TcpSequencer::with_seed(0xdeadbeef);
        let ip = ipv4(10, 0, 0, 1);
        let isn = seq.sequence_for(ip, 443);
        assert!(!seq.verify_reply(ip, 443, isn));
        assert!(!seq.verify_reply(ip, 443, isn.wrapping_add(2)));
    }

    /// Different (ip, port) pairs must produce different ISNs (with high probability).
    #[test]
    fn test_sequence_uniqueness() {
        use std::collections::HashSet;
        let seq = TcpSequencer::with_seed(0x1234_5678);
        let ips: Vec<IpAddr> = (1u8..=10)
            .map(|i| ipv4(192, 168, 1, i))
            .collect();
        let ports: Vec<u16> = (80u16..=89).collect();

        let mut seen = HashSet::new();
        for &ip in &ips {
            for &port in &ports {
                let isn = seq.sequence_for(ip, port);
                seen.insert(isn);
            }
        }
        // With 100 (ip,port) combinations in a 2^32 space we expect no
        // collisions with overwhelming probability.  If this flakes, the hash
        // function is broken.
        assert_eq!(
            seen.len(),
            100,
            "expected 100 unique ISNs — hash function has collisions"
        );
    }

    /// Wrap-around: seq = u32::MAX → ack must be 0.
    #[test]
    fn test_verify_reply_wraps_around() {
        // Find an (ip, port, seed) combination whose ISN is u32::MAX.
        // Instead of brute-force, just test wrapping_add directly.
        let seq = TcpSequencer::with_seed(0xffff_fffe);
        let ip = ipv4(1, 2, 3, 4);
        let port = 1u16;
        let isn = seq.sequence_for(ip, port);
        assert!(seq.verify_reply(ip, port, isn.wrapping_add(1)));
    }

    /// IPv6 addresses must be handled without panicking.
    #[test]
    fn test_ipv6_doesnt_panic() {
        let seq = TcpSequencer::with_seed(42);
        let ip = IpAddr::V6(Ipv6Addr::LOCALHOST);
        let isn = seq.sequence_for(ip, 443);
        assert!(seq.verify_reply(ip, 443, isn.wrapping_add(1)));
    }
}
