//! The one SBPL quoting function: every accepted value decodes back to the
//! exact input; every refusal has its stated reason.

#![no_main]

use libfuzzer_sys::fuzz_target;
use procage_policy::sbpl::{EscapeError, quote};

/// Reads `"…"` knowing only `\\` and `\"`.
fn decode(text: &str) -> Option<Vec<u8>> {
    let inner = text.strip_prefix('"')?.strip_suffix('"')?;
    let mut out = Vec::new();
    let mut chars = inner.chars();
    while let Some(c) = chars.next() {
        match c {
            '\\' => match chars.next()? {
                '\\' => out.push(b'\\'),
                '"' => out.push(b'"'),
                _ => return None,
            },
            '"' => return None,
            c => out.extend_from_slice(c.encode_utf8(&mut [0; 4]).as_bytes()),
        }
    }
    Some(out)
}

fuzz_target!(|data: &[u8]| {
    match quote(data) {
        Ok(quoted) => assert_eq!(decode(&quoted).as_deref(), Some(data)),
        Err(EscapeError::NotUtf8 { at }) => {
            assert_eq!(std::str::from_utf8(data).unwrap_err().valid_up_to(), at)
        }
        Err(EscapeError::ControlCharacter { at, byte }) => {
            assert!(std::str::from_utf8(data).is_ok());
            assert_eq!(data[at], byte);
            assert!(byte < 0x20 || byte == 0x7f);
        }
    }
});
