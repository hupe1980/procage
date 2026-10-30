//! Reading the data format never panics, and every accepted document
//! round-trips to an equal policy.

#![no_main]

use libfuzzer_sys::fuzz_target;
use procage_policy::Policy;

fuzz_target!(|data: &[u8]| {
    let Ok(policy) = serde_json::from_slice::<Policy>(data) else { return };
    let text = serde_json::to_string(&policy).expect("a policy serialises");
    let again: Policy = serde_json::from_str(&text).expect("written documents read back");
    assert_eq!(again, policy);
});
