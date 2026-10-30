//! Glob compilation: an accepted glob becomes an anchored regex in which
//! every literal character is escaped where it has a regex meaning, and the
//! regex can always be quoted.

#![no_main]

use libfuzzer_sys::fuzz_target;
use procage_policy::Glob;
use procage_policy::glob::REGEX_META;
use procage_policy::sbpl::quote;

const WILDCARDS: &[&str] = &["[^/]*", "[^/]", "(.*/)?", "(/.*)?"];

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else { return };
    let Ok(glob) = Glob::new(text) else { return };
    let regex = glob.to_sbpl_regex();
    let body = regex.strip_prefix('^').and_then(|r| r.strip_suffix('$')).expect("anchored");
    let mut rest = body;
    let mut literals = String::new();
    while !rest.is_empty() {
        if let Some(r) = WILDCARDS.iter().find_map(|w| rest.strip_prefix(w)) {
            rest = r;
            continue;
        }
        let mut chars = rest.chars();
        let c = chars.next().unwrap();
        if c == '\\' {
            let escaped = chars.next().expect("dangling escape");
            assert!(REGEX_META.contains(&escaped), "needless escape in {regex}");
            literals.push(escaped);
        } else {
            assert!(!REGEX_META.contains(&c), "unescaped {c:?} in {regex}");
            literals.push(c);
        }
        rest = chars.as_str();
    }
    assert_eq!(literals, glob.literal_chars().collect::<String>());
    quote(regex.as_bytes()).expect("a glob regex can always be quoted");
});
