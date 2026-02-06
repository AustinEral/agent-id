//! Fuzz target for DID parsing.
//!
//! Tests that aip_core::Did::from_str handles arbitrary input safely,
//! without panicking or causing undefined behavior.

#![no_main]

use libfuzzer_sys::fuzz_target;
use std::str::FromStr;

fuzz_target!(|data: &[u8]| {
    // Try to interpret the bytes as a UTF-8 string
    if let Ok(input) = std::str::from_utf8(data) {
        // Attempt to parse as a DID - should never panic
        let _ = aip_core::Did::from_str(input);
    }
});
