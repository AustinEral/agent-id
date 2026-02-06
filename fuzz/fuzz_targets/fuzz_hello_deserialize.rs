//! Fuzz target for Hello message deserialization.
//!
//! Tests that aip_handshake::Hello JSON parsing handles arbitrary input
//! safely, without panicking or causing undefined behavior.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Try to interpret the bytes as JSON
    if let Ok(input) = std::str::from_utf8(data) {
        // Attempt to parse as Hello message - should never panic
        let _: Result<aip_handshake::Hello, _> = serde_json::from_str(input);
    }
    
    // Also try parsing directly from bytes
    let _: Result<aip_handshake::Hello, _> = serde_json::from_slice(data);
});
