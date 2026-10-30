//! Absolute paths: exact bytes, lexical checks only, typed refusals.

mod common;

use common::{CASES, Rng};
use procage_policy::{AbsPath, PathError};

#[test]
fn each_refusal_names_its_reason() {
    let cases: &[(&[u8], PathError)] = &[
        (b"", PathError::Empty),
        (b"relative/dir", PathError::Relative),
        (b"~/dir", PathError::Relative),
        (b"/a/../b", PathError::DotDotComponent { at: 3 }),
        (b"/..", PathError::DotDotComponent { at: 1 }),
        (b"/a/./b", PathError::DotComponent { at: 3 }),
        (b"/a//b", PathError::EmptyComponent { at: 3 }),
        (b"//", PathError::TrailingSlash),
        (b"/a/", PathError::TrailingSlash),
        (b"/a\0b", PathError::Nul { at: 2 }),
    ];
    for (input, want) in cases {
        assert_eq!(AbsPath::new(*input), Err(*want), "{input:?}");
    }
    assert!(AbsPath::new("/").unwrap().is_root());
    assert!(AbsPath::new("/a/.hidden/..x/b.").is_ok());
}

#[test]
fn bytes_are_kept_exactly() {
    let raw = b"/tmp/\xff\xfe/caf\xc3\xa9";
    let p = AbsPath::new(&raw[..]).unwrap();
    assert_eq!(p.as_bytes(), raw);
    assert_eq!(p.clone().into_bytes(), raw.to_vec());
}

#[test]
fn ancestry_is_component_wise() {
    let p = AbsPath::new("/a/b/c").unwrap();
    let names: Vec<_> = p.ancestors().into_iter().map(|a| a.to_string()).collect();
    assert_eq!(names, ["/a/b", "/a", "/"]);
    let a = AbsPath::new("/a").unwrap();
    assert!(!AbsPath::new("/ab").unwrap().starts_with_path(&a));
    assert!(AbsPath::new("/a/b").unwrap().starts_with_path(&a));
}

/// An independent statement of the rules.
fn oracle(bytes: &[u8]) -> bool {
    if bytes.first() != Some(&b'/') || bytes.contains(&0) {
        return false;
    }
    if bytes == b"/" {
        return true;
    }
    !bytes.ends_with(b"/")
        && bytes[1..]
            .split(|&b| b == b'/')
            .all(|c| !c.is_empty() && c != b"." && c != b"..")
}

#[test]
fn generated_inputs_match_the_rules() {
    let mut rng = Rng::new(7);
    for _ in 0..CASES {
        let mut bytes = rng.nasty_bytes(12);
        if rng.chance(70) {
            bytes.insert(0, b'/');
        }
        if rng.chance(20) {
            bytes.extend_from_slice(b"/..");
        }
        let accepted = AbsPath::new(bytes.clone());
        assert_eq!(accepted.is_ok(), oracle(&bytes), "{bytes:?}");
        if let Ok(p) = accepted {
            assert_eq!(p.as_bytes(), bytes.as_slice());
        }
    }
}
