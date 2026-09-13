#![no_main]
use libfuzzer_sys::fuzz_target;

use scrip::cli_util::parse_duration_secs;

fuzz_target!(|s: &str| {
    // Invariant: never panics; an Ok result is always positive seconds.
    if let Ok(secs) = parse_duration_secs(s) {
        assert!(secs > 0);
    }
});
