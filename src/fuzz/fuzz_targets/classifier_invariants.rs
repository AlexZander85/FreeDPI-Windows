#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = freedpi_core::classifier::Classifier::classify(data);
    let _ = freedpi_core::packet_invariants::validate_before_send(
        data,
        freedpi_core::packet_invariants::ValidationMode::Fast,
    );
});
