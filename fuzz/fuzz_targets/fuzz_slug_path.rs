#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|s: &str| {
    let ok = scrip::http::valid_slug(s);
    // Accepted slugs must exclude path separators, dot-segments,
    // percent-encoding triggers, and NUL.
    if ok {
        // 16 = the longest legacy slug; TOKEN_LEN = an encryption token,
        // which is key material in the path and so longer on purpose.
        assert!(!s.is_empty() && (s.len() <= 16 || s.len() == scrip::crypto::TOKEN_LEN));
        assert!(!s.contains('/'));
        assert!(!s.contains('.'));
        assert!(!s.contains('%'));
        assert!(!s.contains('\0'));
    }
});
