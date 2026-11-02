//! The canonical host: whatever bytes a request names, a parsed host is a
//! fixed point (printing and parsing it again gives the same host), a name
//! holds only label bytes, and no name is one that the standard library
//! (and so a resolver) would read as an address.

#![no_main]

use std::net::IpAddr;

use libfuzzer_sys::fuzz_target;
use procage_proxy::Host;

fuzz_target!(|bytes: &[u8]| {
    let Ok(host) = Host::parse(bytes) else {
        return;
    };
    let shown = host.to_string();
    assert_eq!(Host::parse(shown.as_bytes()), Ok(host.clone()), "{shown}");
    if let Host::Name(name) = &host {
        assert!(
            name.bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"-._".contains(&b)),
            "{name}"
        );
        assert!(name.parse::<IpAddr>().is_err(), "{name} reads as an address");
        assert!(!name.ends_with('.') && !name.contains(".."), "{name}");
    }
});
