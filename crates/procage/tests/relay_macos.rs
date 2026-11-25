//! macOS has no TPROXY: `Network::Relay` is refused, never replaced by a
//! direct route or by the proxy.

#![cfg(target_os = "macos")]

use procage::native::{Cage, CageOptions};
use procage::policy::{Network, Policy};

#[test]
fn macos_refuses_the_transparent_relay() {
    let policy = Policy {
        net: Network::Relay,
        ..Policy::default()
    };
    match Cage::with_options(&policy, &CageOptions::default()) {
        Ok(_) => panic!("macOS must refuse Network::Relay: no TPROXY"),
        Err(e) => {
            let text = e.to_string();
            assert!(
                text.contains("net-relay") || text.contains("relay"),
                "{text}"
            );
        }
    }
}
