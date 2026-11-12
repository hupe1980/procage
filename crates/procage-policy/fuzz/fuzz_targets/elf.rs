//! The ELF interpreter reader: any bytes give a value or an error, never a
//! panic, and an interpreter it returns lies within the input, is bounded
//! and contains no NUL.

#![no_main]

use libfuzzer_sys::fuzz_target;
use procage_policy::elf::{MAX_INTERPRETER, interpreter};

fuzz_target!(|data: &[u8]| {
    if let Ok(Some(path)) = interpreter(data) {
        assert!(!path.is_empty() && path.len() <= MAX_INTERPRETER);
        assert!(!path.contains(&0));
        let start = path.as_ptr() as usize - data.as_ptr() as usize;
        assert!(start + path.len() < data.len());
    }
});
