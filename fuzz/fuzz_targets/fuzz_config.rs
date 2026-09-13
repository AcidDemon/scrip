#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else {
        return;
    };
    // Parsing and validation may return errors, but neither should panic.
    if let Ok(cfg) = toml::from_str::<scrip::config::Config>(s) {
        let _ = cfg.validate();
    }
});
