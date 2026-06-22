#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        // Must never panic regardless of input
        let _ = caas_api::validation::is_safe_text(s);
    }
});
