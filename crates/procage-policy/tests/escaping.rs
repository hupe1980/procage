//! Untrusted path data never changes what a profile means: every quoted value
//! decodes back to exactly its input, globs are escaped, and no identifier
//! can carry profile syntax.

mod common;

use common::*;
use procage_policy::glob::REGEX_META;
use procage_policy::name::OperationName;
use procage_policy::sbpl::{EscapeError, INLINE_LIMIT, quote};
use procage_policy::*;

#[test]
fn quoting_round_trips_or_refuses() {
    let mut rng = Rng::new(42);
    let (mut accepted, mut refused) = (0, 0);
    for _ in 0..CASES {
        let input = if rng.chance(50) {
            rng.nasty_text(24).into_bytes()
        } else {
            rng.nasty_bytes(24)
        };
        match quote(&input) {
            Ok(quoted) => {
                accepted += 1;
                assert_eq!(
                    decode_sbpl_string(&quoted),
                    Some(input.clone()),
                    "{input:?}"
                );
            }
            Err(EscapeError::NotUtf8 { at }) => {
                refused += 1;
                assert!(std::str::from_utf8(&input).is_err());
                assert_eq!(std::str::from_utf8(&input).unwrap_err().valid_up_to(), at);
            }
            Err(EscapeError::ControlCharacter { at, byte }) => {
                refused += 1;
                assert!(byte < 0x20 || byte == 0x7f);
                assert_eq!(input[at], byte);
            }
        }
    }
    assert!(
        accepted > 1000 && refused > 1000,
        "{accepted} accepted, {refused} refused"
    );
}

/// The line with every quoted string removed.
fn outside_quotes(line: &str) -> String {
    let mut out = String::new();
    let mut chars = line.chars();
    while let Some(c) = chars.next() {
        if c == '"' {
            while let Some(d) = chars.next() {
                match d {
                    '\\' => {
                        chars.next();
                    }
                    '"' => break,
                    _ => {}
                }
            }
            out.push_str("\"\"");
        } else {
            out.push(c);
        }
    }
    out.push('\n');
    out
}

#[test]
fn a_hostile_directory_name_stays_one_subpath() {
    let name = "/tmp/a\"b(c)*?[d]\\e) (allow default) (with no-sandbox";
    let mut p = Policy::default();
    p.fs.push(subpath(Access::Read, name));
    let plan = seatbelt_plan(&p, &LowerOptions::default());
    let line = plan
        .profile
        .lines()
        .find(|l| l.contains("tmp/a"))
        .expect("the rule is emitted");
    assert!(line.starts_with("(allow file-read* (subpath \""));
    assert!(!line.contains("(regex"));
    assert_eq!(quoted_strings(line), Some(vec![name.as_bytes().to_vec()]));
    // Outside quoted strings, the profile holds no syntax from the name.
    let syntax: String = plan.profile.lines().map(outside_quotes).collect();
    assert!(
        !syntax.contains("(allow default") && !syntax.contains("(with no-sandbox"),
        "{syntax}"
    );
}

#[test]
fn every_quoted_string_in_every_reference_profile_is_well_formed() {
    for (name, policy) in reference_policies() {
        let Ok(Plan::Seatbelt(plan)) = lower(&policy, Target::MacOs, &allow_all()) else {
            panic!("{name}");
        };
        for line in plan.profile.lines() {
            assert!(quoted_strings(line).is_some(), "{name}: {line}");
            // The only modifiers: the default's message, and a quiet deny's
            // `(with no-report)` at the end of the line (base V3).
            let with = line.matches("(with").count();
            assert!(
                with == 0
                    || line.starts_with("(deny default (with message ")
                    || (with == 1
                        && line.starts_with("(deny ")
                        && line.ends_with(" (with no-report))")),
                "{name}: {line}"
            );
            assert!(
                !line.contains("no-sandbox") && !line.contains("no-profile"),
                "{name}: {line}"
            );
        }
    }
}

#[test]
fn a_glob_becomes_one_anchored_escaped_pattern() {
    let mut p = Policy::default();
    p.fs.push(FsRule::new(
        Access::Read,
        FsTarget::Glob(glob("/work/**/*.rs")),
    ));
    let plan = seatbelt_plan(&p, &LowerOptions::default());
    assert!(
        plan.profile
            .contains(r#"(allow file-read* (regex "^/work/(.*/)?[^/]*\\.rs$"))"#),
        "{}",
        plan.profile
    );
    // No wildcard: still a pattern, never a literal.
    let mut q = Policy::default();
    q.fs.push(FsRule::new(
        Access::Read,
        FsTarget::Glob(glob("/work/a.txt")),
    ));
    let plan = seatbelt_plan(&q, &LowerOptions::default());
    assert!(plan.profile.contains(r#"(regex "^/work/a\\.txt$")"#));
    assert!(!plan.profile.contains("(literal"));
}

/// Removes the regex syntax the glob compiler adds, leaving the escaped
/// literal characters; checks each literal is escaped where it must be.
fn literals_are_escaped(glob: &Glob) -> Result<(), String> {
    let regex = glob.to_sbpl_regex();
    let body = regex
        .strip_prefix('^')
        .and_then(|r| r.strip_suffix('$'))
        .ok_or("not anchored")?;
    let mut rest = body;
    let mut literals = String::new();
    while !rest.is_empty() {
        if let Some(r) = ["[^/]*", "[^/]", "(.*/)?", "(/.*)?"]
            .iter()
            .find_map(|w| rest.strip_prefix(w))
        {
            rest = r;
            continue;
        }
        let mut chars = rest.chars();
        let c = chars.next().unwrap_or_default();
        if c == '\\' {
            let escaped = chars.next().ok_or("dangling escape")?;
            if !REGEX_META.contains(&escaped) {
                return Err(format!("needless escape of {escaped:?}"));
            }
            literals.push(escaped);
        } else if REGEX_META.contains(&c) {
            return Err(format!("unescaped {c:?} in {regex}"));
        } else {
            literals.push(c);
        }
        rest = chars.as_str();
    }
    let expected: String = glob.literal_chars().collect();
    if literals == expected {
        Ok(())
    } else {
        Err(format!("literals {literals:?} != {expected:?}"))
    }
}

#[test]
fn generated_globs_escape_every_literal() {
    let mut rng = Rng::new(99);
    let mut parsed = 0;
    for _ in 0..CASES {
        let text = rng.nasty_text(16);
        if let Ok(glob) = Glob::new(&text) {
            parsed += 1;
            literals_are_escaped(&glob).unwrap_or_else(|e| panic!("{text:?}: {e}"));
            assert!(quote(glob.to_sbpl_regex().as_bytes()).is_ok());
        }
    }
    assert!(parsed > 500, "only {parsed} globs parsed");
}

#[test]
fn unsupported_glob_syntax_is_refused() {
    assert!(matches!(
        Glob::new("/a/[ab]"),
        Err(GlobError::UnsupportedSyntax { ch: '[', .. })
    ));
    assert!(matches!(
        Glob::new("/a/{b,c}"),
        Err(GlobError::UnsupportedSyntax { ch: '{', .. })
    ));
    assert!(matches!(
        Glob::new("/a**/b"),
        Err(GlobError::MisplacedDoubleStar { .. })
    ));
    assert!(Glob::new(r"/a/\[ab\]").is_ok());
}

#[test]
fn identifiers_cannot_carry_syntax() {
    for bad in ["a(b", "a b", "a\"b", "no-sandbox)", "default"] {
        assert!(OperationName::new(bad).is_err(), "{bad:?}");
    }
    for bad in ["a\"b", "a b", "a/b", "A"] {
        assert!(GrantName::new(bad).is_err(), "{bad:?}");
    }
    assert!(Tag::new("x\") (allow default").is_err());
}

#[test]
fn long_values_go_through_a_parameter() {
    let at_limit = format!("/{}", "a".repeat(INLINE_LIMIT - 3));
    let over = format!("/{}", "a".repeat(INLINE_LIMIT - 2));
    let mut p = Policy::default();
    p.fs.push(subpath(Access::Read, &at_limit));
    let plan = seatbelt_plan(&p, &LowerOptions::default());
    assert!(plan.params.is_empty());
    p.fs.push(subpath(Access::Read, &over));
    let plan = seatbelt_plan(&p, &LowerOptions::default());
    assert_eq!(plan.params, vec![("P0".to_string(), over.clone())]);
    assert!(plan.profile.contains("(subpath (param \"P0\"))"));
}
