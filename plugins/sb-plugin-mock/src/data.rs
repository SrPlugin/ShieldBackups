//! Reproducible byte generator.

/// Generates `n` reproducible bytes from a seed.
///
/// Uses xorshift64: it is not cryptographic and does not pretend to be. What is
/// needed is that it be deterministic, fast and that it **not compress
/// trivially**, so that the pipeline tests measure something real instead of
/// passing by accident.
///
/// A prefix of the stream is an exact prefix of the longer stream with the same
/// seed: asking for 1 KiB and asking for 1 MiB yield the same beginning.
pub fn deterministic_data(seed: u64, n: usize) -> impl Iterator<Item = u8> {
    // The `| 1` avoids the single absorbing state of xorshift64: zero, which
    // would repeat itself forever.
    let mut state = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
    (0..n).map(move |_| {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        // `to_le_bytes()[0]` instead of `as u8`: it is the same low byte, but
        // without a truncating cast that clippy pedantic would have to forgive.
        state.to_le_bytes()[0]
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_same_seed_produces_the_same_bytes() {
        // Without this, a core test could not compare what was restored with
        // what the engine produced.
        let a: Vec<u8> = deterministic_data(42, 1000).collect();
        let b: Vec<u8> = deterministic_data(42, 1000).collect();
        assert_eq!(a, b);
    }

    #[test]
    fn different_seeds_produce_different_data() {
        let a: Vec<u8> = deterministic_data(1, 1000).collect();
        let b: Vec<u8> = deterministic_data(2, 1000).collect();
        assert_ne!(a, b);
    }

    #[test]
    fn produces_exactly_the_requested_bytes() {
        assert_eq!(deterministic_data(7, 12_345).count(), 12_345);
        assert_eq!(deterministic_data(7, 0).count(), 0);
        assert_eq!(deterministic_data(7, 1).count(), 1);
    }

    #[test]
    fn the_data_covers_almost_the_whole_byte_range() {
        // A generator that returned zeros would make the pipeline's compression
        // tests pass for the wrong reason.
        let data: Vec<u8> = deterministic_data(3, 10_000).collect();
        let distinct: std::collections::HashSet<_> = data.iter().collect();
        assert!(
            distinct.len() > 200,
            "only {} distinct values",
            distinct.len()
        );
    }

    #[test]
    fn a_prefix_is_a_prefix_of_the_longer_stream() {
        // Lets one test ask for 1 KB and another for 1 MB from the same seed
        // and have the first be the exact beginning of the second.
        let short: Vec<u8> = deterministic_data(9, 100).collect();
        let long: Vec<u8> = deterministic_data(9, 1000).collect();
        assert_eq!(short, long[..100]);
    }
}
