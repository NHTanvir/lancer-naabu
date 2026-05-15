// Items in this module are only consumed by the `raw_scan` feature, but the
// module itself (and its tests) is always compiled.
#![allow(dead_code)]

/// Blackrock Feistel cipher — same algorithm concept as projectdiscovery/blackrock.
///
/// Uniformly permutes integers `0..n` without repeats using a cycle-walking
/// Feistel network.  The permutation is deterministic given the same `seed`
/// and `n`, but pseudo-random in appearance.
///
/// # Usage
/// ```rust,no_run
/// use lancer_naabu::blackrock::Blackrock;
/// let br = Blackrock::new(1000, 42);
/// for i in 0..1000 {
///     let idx = br.permute(i);
///     // idx is unique in 0..1000
/// }
/// ```

// ── Internal mixing function ──────────────────────────────────────────────────

/// 64-bit finalisation mix (Murmur3/xxHash-style).
fn round_fn(x: u64, key: u64) -> u64 {
    let mut h = x ^ key;
    h ^= h >> 33;
    h = h.wrapping_mul(0xff51afd7ed558ccd);
    h ^= h >> 33;
    h = h.wrapping_mul(0xc4ceb9fe1a85ec53);
    h ^= h >> 33;
    h
}

// ── Core permutation ──────────────────────────────────────────────────────────

/// One Feistel encryption step over the full `2^bits` domain.
///
/// `x` must be in `[0, 2^bits)` where `bits = ceil(log2(n+1))`.
/// The result is also in `[0, 2^bits)`.
fn feistel_step(x: u64, bits: u32, seed: u64, rounds: u32) -> u64 {
    debug_assert!(bits >= 1 && bits <= 64);
    let half = bits / 2;
    let lo_mask = (1u64 << half).wrapping_sub(1);

    let mut lo = x & lo_mask;
    let mut hi = (x >> half) & lo_mask; // symmetric masks — see note below

    for r in 0..rounds {
        let f = round_fn(hi, seed ^ (r as u64));
        let new_lo = hi;
        let new_hi = lo ^ (f & lo_mask);
        lo = new_lo;
        hi = new_hi;
    }

    lo | (hi << half)
}

/// Permute a single value `x` in the range `[0, n)`.
///
/// Uses a cycle-walking Feistel network:
/// * The domain `[0, n)` is embedded in `[0, 2^bits)` where
///   `bits = ceil(log2(n+1))`.
/// * `rounds` Feistel rounds are applied.
/// * If the result falls outside `[0, n)`, the cipher is applied again
///   (cycle-walking) until a valid value is produced.  For `n` close to a
///   power of two this almost never iterates more than once.
pub fn permute_feistel(x: u64, n: u64, seed: u64, rounds: u32) -> u64 {
    assert!(x < n, "x={x} must be less than n={n}");
    assert!(n > 0, "n must be > 0");

    // Number of bits needed to represent n-1 (the largest index in [0,n)).
    // For n=1 we use 1 bit.
    let bits = u64::BITS - (n - 1).max(1).leading_zeros(); // 1..=63
    // Round bits up to an even number so both halves are equal width.
    let bits = bits + (bits & 1); // make even

    let domain = 1u64 << bits; // power-of-two domain >= n
    debug_assert!(domain >= n);

    // Cycle-walk: keep encrypting until the result is in [0, n).
    let mut val = x;
    loop {
        val = feistel_step(val, bits, seed, rounds);
        // val is now in [0, domain); reject if >= n and try again.
        if val < n {
            return val;
        }
        // val is in [n, domain) — still within the Feistel domain,
        // so we can re-encrypt it directly.
    }
}

// ── Blackrock struct ──────────────────────────────────────────────────────────

/// A reusable Blackrock permutation context for a fixed domain `[0, n)`.
pub struct Blackrock {
    pub n: u64,
    pub rounds: u32,
    pub seed: u64,
}

impl Blackrock {
    /// Create a new Blackrock permutation over `[0, n)` with the given `seed`.
    ///
    /// The number of Feistel rounds is chosen automatically as
    /// `max(4, ceil(log2(n)) / 2)`.
    pub fn new(n: u64, seed: u64) -> Self {
        assert!(n > 0, "domain size n must be > 0");
        let bits = (u64::BITS - n.leading_zeros()) as u32;
        let rounds = (bits / 2).max(4);
        Self { n, rounds, seed }
    }

    /// Permute a single index `x` in `[0, n)`.
    pub fn permute(&self, x: u64) -> u64 {
        permute_feistel(x, self.n, self.seed, self.rounds)
    }

    /// Return an iterator that yields every value in `[0, n)` in pseudo-random
    /// order, each exactly once.
    pub fn iter(&self) -> BlackrockIter<'_> {
        BlackrockIter {
            br: self,
            current: 0,
        }
    }
}

// ── Iterator ──────────────────────────────────────────────────────────────────

pub struct BlackrockIter<'a> {
    br: &'a Blackrock,
    current: u64,
}

impl<'a> Iterator for BlackrockIter<'a> {
    type Item = u64;

    fn next(&mut self) -> Option<Self::Item> {
        if self.current >= self.br.n {
            return None;
        }
        let val = self.br.permute(self.current);
        self.current += 1;
        Some(val)
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    /// All values 0..N must appear exactly once (permutation property).
    #[test]
    fn test_permute_feistel_all_values_appear_once_small() {
        let n = 13u64; // non-power-of-two
        let seed = 0xdeadbeef_cafebabe;
        let mut seen = HashSet::new();
        for i in 0..n {
            let v = permute_feistel(i, n, seed, 4);
            assert!(v < n, "out-of-range: {v} >= {n}");
            assert!(seen.insert(v), "duplicate value {v} for i={i}");
        }
        assert_eq!(seen.len(), n as usize);
    }

    #[test]
    fn test_permute_feistel_all_values_appear_once_power_of_two() {
        let n = 64u64;
        let seed = 12345;
        let mut seen = HashSet::new();
        for i in 0..n {
            let v = permute_feistel(i, n, seed, 4);
            assert!(v < n);
            assert!(seen.insert(v));
        }
        assert_eq!(seen.len(), n as usize);
    }

    #[test]
    fn test_blackrock_iter_covers_full_domain() {
        let n = 100u64;
        let br = Blackrock::new(n, 999);
        let values: Vec<u64> = br.iter().collect();
        assert_eq!(values.len(), n as usize);

        let mut sorted = values.clone();
        sorted.sort_unstable();
        let expected: Vec<u64> = (0..n).collect();
        assert_eq!(sorted, expected, "iter must cover exactly 0..n");
    }

    #[test]
    fn test_blackrock_different_seeds_produce_different_orders() {
        let n = 50u64;
        let br1 = Blackrock::new(n, 1);
        let br2 = Blackrock::new(n, 2);
        let v1: Vec<u64> = br1.iter().collect();
        let v2: Vec<u64> = br2.iter().collect();
        // The sorted contents should be the same…
        let mut s1 = v1.clone(); s1.sort_unstable();
        let mut s2 = v2.clone(); s2.sort_unstable();
        assert_eq!(s1, s2);
        // …but the orders should differ (extremely unlikely to be equal).
        assert_ne!(v1, v2, "different seeds should produce different permutation orders");
    }

    #[test]
    fn test_blackrock_single_element() {
        let br = Blackrock::new(1, 42);
        assert_eq!(br.permute(0), 0);
        let vals: Vec<u64> = br.iter().collect();
        assert_eq!(vals, vec![0]);
    }
}
