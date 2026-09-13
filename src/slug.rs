pub const SLUG_LEN: usize = 8;
pub const SYMBOLS: &[u8; 36] = b"abcdefghijklmnopqrstuvwxyz0123456789";

/// `len` unbiased base36 characters from the OS CSPRNG, used for paste slugs
/// and encryption tokens. No application-managed seed or RNG state.
pub fn random_base36(len: usize) -> String {
    let mut out = String::with_capacity(len);
    while out.len() < len {
        let mut buf = [0u8; 16];
        getrandom::fill(&mut buf).expect("OS RNG unavailable");
        for b in buf {
            if out.len() == len {
                break;
            }
            if b < 252 {
                // 252 = 7 * 36: rejection sampling kills the modulo bias
                out.push(SYMBOLS[(b % 36) as usize] as char);
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slugs_are_8_chars_from_the_charset() {
        for _ in 0..1000 {
            let s = random_base36(SLUG_LEN);
            assert_eq!(s.len(), SLUG_LEN);
            assert!(s.bytes().all(|b| SYMBOLS.contains(&b)), "bad slug {s}");
        }
    }

    #[test]
    fn consecutive_slugs_differ() {
        assert_ne!(random_base36(SLUG_LEN), random_base36(SLUG_LEN));
    }

    /// Chi-square check over 800k characters, df=35. The expected statistic
    /// is 35; a threshold of 100 catches modulo bias with a low false-failure rate.
    #[test]
    fn char_distribution_is_uniform() {
        let mut counts = [0u64; 36];
        let n = 100_000usize;
        for _ in 0..n {
            for b in random_base36(SLUG_LEN).bytes() {
                let i = SYMBOLS.iter().position(|&s| s == b).unwrap();
                counts[i] += 1;
            }
        }
        let expected = (n * SLUG_LEN) as f64 / 36.0;
        let chi2: f64 = counts
            .iter()
            .map(|&c| {
                let d = c as f64 - expected;
                d * d / expected
            })
            .sum();
        assert!(chi2 < 100.0, "chi2 = {chi2}, distribution is biased");
    }
}
