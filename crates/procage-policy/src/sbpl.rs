//! SBPL text: the one quoting function, the emitted rule model, the profile
//! writer and the limits guard.
//!
//! [`quote`] is the only function in this crate that writes a `"` into a
//! profile. Every path, name and pattern goes through it, or, when its quoted
//! form is longer than [`INLINE_LIMIT`], through a generated `(param …)`.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::fmt;

use crate::name::Tag;
use crate::seatbelt::Effect;

/// The longest quoted string emitted inline, in bytes.
///
/// libsandbox's reader rejects string literals of 1024 characters (1023 are
/// accepted; measured on macOS 26.6.2). The limit is checked against the
/// quoted form, which is never shorter than the decoded value, leaving a
/// margin. Longer values are passed as parameters.
pub const INLINE_LIMIT: usize = 1016;

/// Why a value cannot be quoted for SBPL.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum EscapeError {
    /// The value is not valid UTF-8 from this byte offset.
    NotUtf8 {
        /// Byte offset of the first invalid byte.
        at: usize,
    },
    /// The value contains a NUL or control character (U+0000–U+001F, U+007F).
    ControlCharacter {
        /// Byte offset.
        at: usize,
        /// The byte.
        byte: u8,
    },
}

impl fmt::Display for EscapeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EscapeError::NotUtf8 { at } => {
                write!(f, "value is not valid UTF-8 at byte offset {at}")
            }
            EscapeError::ControlCharacter { at, byte } => {
                write!(
                    f,
                    "value contains control character 0x{byte:02x} at byte offset {at}"
                )
            }
        }
    }
}

impl core::error::Error for EscapeError {}

/// Quotes `value` as an SBPL string literal.
///
/// `\` becomes `\\` and `"` becomes `\"`; every other accepted byte is copied
/// unchanged. Values that are not valid UTF-8, or that contain a control
/// character, are refused: they are never altered or dropped.
pub fn quote(value: &[u8]) -> Result<String, EscapeError> {
    let text = core::str::from_utf8(value).map_err(|e| EscapeError::NotUtf8 {
        at: e.valid_up_to(),
    })?;
    if let Some(at) = value.iter().position(|&b| b < 0x20 || b == 0x7f) {
        return Err(EscapeError::ControlCharacter {
            at,
            byte: value[at],
        });
    }
    let mut out = String::with_capacity(text.len() + 2);
    out.push('"');
    for ch in text.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            c => out.push(c),
        }
    }
    out.push('"');
    Ok(out)
}

/// A filter of an emitted rule. String-bearing variants hold the raw value;
/// it is quoted only when the rule is rendered.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Filter {
    /// `(literal "…")`.
    Literal(Vec<u8>),
    /// `(subpath "…")`.
    Subpath(Vec<u8>),
    /// `(regex "…")`; the value is regex text.
    Regex(String),
    /// `(path-ancestors "…")`.
    PathAncestors(Vec<u8>),
    /// `(extension "…")`; the value is the extension class.
    Extension(String),
    /// `(global-name "…")`.
    GlobalName(String),
    /// `(global-name-prefix "…")`.
    GlobalNamePrefix(String),
    /// `(xpc-service-name-prefix "…")`.
    XpcServiceNamePrefix(String),
    /// `(target self)`, `(target children)` or `(target others)`.
    Target(&'static str),
    /// `(require-not (target same-sandbox))`.
    OutsideSameSandbox,
    /// `(remote ip "…")`, e.g. `localhost:8080`.
    RemoteIp(String),
    /// `(local ip "…")`.
    LocalIp(String),
    /// `(remote unix-socket (path-literal "…"))`.
    RemoteUnixSocket(Vec<u8>),
    /// `(fcntl-command n …)`.
    FcntlCommand(Vec<u32>),
    /// `(file-mode #o…)`.
    FileMode(u32),
    /// `(ioctl-command #x…)`.
    IoctlCommand(u32),
    /// `(ipc-posix-name "…")`.
    IpcPosixName(String),
}

/// A top-level SBPL rule: `(allow|deny op… filter)`. More than one filter is
/// rendered as `(require-any …)`, so the filters are alternatives; no filter
/// means the rule applies to every request of its operations.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Rule {
    /// Allow or deny.
    pub effect: Effect,
    /// Operation names, in a fixed order.
    pub ops: Vec<String>,
    /// Alternative filters; empty means unfiltered.
    pub filters: Vec<Filter>,
}

impl Rule {
    /// A rule over `ops` with `filters`.
    pub fn new(effect: Effect, ops: &[&str], filters: Vec<Filter>) -> Self {
        Self {
            effect,
            ops: ops.iter().map(|op| op.to_string()).collect(),
            filters,
        }
    }

    /// Every raw value this rule would quote, for checking before rendering.
    pub fn values(&self) -> impl Iterator<Item = &[u8]> {
        self.filters.iter().filter_map(|f| match f {
            Filter::Literal(v)
            | Filter::Subpath(v)
            | Filter::PathAncestors(v)
            | Filter::RemoteUnixSocket(v) => Some(v.as_slice()),
            Filter::Regex(s)
            | Filter::Extension(s)
            | Filter::GlobalName(s)
            | Filter::GlobalNamePrefix(s)
            | Filter::XpcServiceNamePrefix(s)
            | Filter::RemoteIp(s)
            | Filter::LocalIp(s)
            | Filter::IpcPosixName(s) => Some(s.as_bytes()),
            Filter::Target(_)
            | Filter::OutsideSameSandbox
            | Filter::FcntlCommand(_)
            | Filter::FileMode(_)
            | Filter::IoctlCommand(_) => None,
        })
    }

    /// Renders the rule; long values become parameters in `params`.
    pub fn render(&self, params: &mut Params) -> Result<String, EscapeError> {
        let mut out = String::from(match self.effect {
            Effect::Allow => "(allow",
            Effect::Deny => "(deny",
        });
        for op in &self.ops {
            out.push(' ');
            out.push_str(op);
        }
        match self.filters.as_slice() {
            [] => {}
            [only] => {
                out.push(' ');
                out.push_str(&render_filter(only, params)?);
            }
            many => {
                out.push_str(" (require-any");
                for filter in many {
                    out.push(' ');
                    out.push_str(&render_filter(filter, params)?);
                }
                out.push(')');
            }
        }
        out.push(')');
        Ok(out)
    }
}

/// Parameters generated for values longer than [`INLINE_LIMIT`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Params {
    entries: Vec<(String, String)>,
}

impl Params {
    /// The parameter name for `value`, reusing one for an equal value.
    fn name_for(&mut self, value: &str) -> String {
        if let Some((name, _)) = self.entries.iter().find(|(_, v)| v == value) {
            return name.clone();
        }
        let name = format!("P{}", self.entries.len());
        self.entries.push((name.clone(), value.to_string()));
        name
    }

    /// The `(name, value)` pairs, in the order they were generated.
    pub fn into_entries(self) -> Vec<(String, String)> {
        self.entries
    }
}

fn string_value(value: &[u8], params: &mut Params) -> Result<String, EscapeError> {
    let quoted = quote(value)?;
    if quoted.len() <= INLINE_LIMIT {
        return Ok(quoted);
    }
    // `quote` succeeded, so the value is valid UTF-8 without control characters.
    let text = core::str::from_utf8(value).map_err(|e| EscapeError::NotUtf8 {
        at: e.valid_up_to(),
    })?;
    let name = params.name_for(text);
    Ok(format!("(param {})", quote(name.as_bytes())?))
}

fn render_filter(filter: &Filter, params: &mut Params) -> Result<String, EscapeError> {
    Ok(match filter {
        Filter::Literal(v) => format!("(literal {})", string_value(v, params)?),
        Filter::Subpath(v) => format!("(subpath {})", string_value(v, params)?),
        Filter::Regex(s) => format!("(regex {})", string_value(s.as_bytes(), params)?),
        Filter::PathAncestors(v) => format!("(path-ancestors {})", string_value(v, params)?),
        Filter::Extension(s) => format!("(extension {})", string_value(s.as_bytes(), params)?),
        Filter::GlobalName(s) => format!("(global-name {})", string_value(s.as_bytes(), params)?),
        Filter::GlobalNamePrefix(s) => format!(
            "(global-name-prefix {})",
            string_value(s.as_bytes(), params)?
        ),
        Filter::XpcServiceNamePrefix(s) => {
            format!(
                "(xpc-service-name-prefix {})",
                string_value(s.as_bytes(), params)?
            )
        }
        Filter::Target(t) => format!("(target {t})"),
        Filter::OutsideSameSandbox => "(require-not (target same-sandbox))".to_string(),
        Filter::RemoteIp(s) => format!("(remote ip {})", string_value(s.as_bytes(), params)?),
        Filter::LocalIp(s) => format!("(local ip {})", string_value(s.as_bytes(), params)?),
        Filter::RemoteUnixSocket(v) => {
            format!(
                "(remote unix-socket (path-literal {}))",
                string_value(v, params)?
            )
        }
        Filter::FcntlCommand(commands) => {
            let mut out = String::from("(fcntl-command");
            for c in commands {
                out.push_str(&format!(" {c}"));
            }
            out.push(')');
            out
        }
        Filter::FileMode(mode) => format!("(file-mode #o{mode:o})"),
        Filter::IoctlCommand(command) => format!("(ioctl-command #x{command:x})"),
        Filter::IpcPosixName(s) => {
            format!("(ipc-posix-name {})", string_value(s.as_bytes(), params)?)
        }
    })
}

/// The most filters [`merge_adjacent`] puts into one `require-any`.
///
/// A `require-any` of 10,000 literals fails to compile without an error
/// message (macOS 26.6.2); small groups stay far from that.
pub const MAX_MERGED_FILTERS: usize = 64;

/// The limits guard's only rewrite: merges neighbouring rules with the same
/// effect and the same operations into one rule whose filters are the
/// alternatives of both.
///
/// Under last-match-wins this matches exactly the requests the two rules
/// matched, so it never broadens an allow. An unfiltered rule absorbs its
/// neighbour (it already matches everything). At most `max_filters` filters
/// are put into one rule.
pub fn merge_adjacent(rules: Vec<Rule>, max_filters: usize) -> Vec<Rule> {
    let mut out: Vec<Rule> = Vec::with_capacity(rules.len());
    let same = |a: &Rule, b: &Rule| a.effect == b.effect && a.ops == b.ops;
    for rule in rules {
        if rule.filters.is_empty() {
            // An unfiltered rule covers every neighbour like it.
            while out.last().is_some_and(|last| same(last, &rule)) {
                out.pop();
            }
            out.push(rule);
            continue;
        }
        if let Some(last) = out.last_mut()
            && same(last, &rule)
        {
            if last.filters.is_empty() {
                continue;
            }
            if last.filters.len() + rule.filters.len() <= max_filters {
                last.filters.extend(rule.filters);
                continue;
            }
        }
        out.push(rule);
    }
    out
}

/// A rendered profile and its parameters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rendered {
    /// The SBPL text.
    pub text: String,
    /// Generated parameters, `(name, value)`.
    pub params: Vec<(String, String)>,
}

/// Writes `(version 1)`, `(deny default)` (with the run tag, if any) and the
/// rules in order, one per line.
pub fn write_profile(tag: Option<&Tag>, rules: &[Rule]) -> Result<Rendered, EscapeError> {
    let mut params = Params::default();
    let mut text = String::from("(version 1)\n");
    match tag {
        Some(tag) => {
            text.push_str(&format!(
                "(deny default (with message {}))\n",
                quote(tag.as_str().as_bytes())?
            ));
        }
        None => text.push_str("(deny default)\n"),
    }
    for rule in rules {
        text.push_str(&rule.render(&mut params)?);
        text.push('\n');
    }
    Ok(Rendered {
        text,
        params: params.into_entries(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn quote_escapes_and_refuses() {
        assert_eq!(quote(b"/a\"b\\c").unwrap(), r#""/a\"b\\c""#);
        assert_eq!(quote("/é".as_bytes()).unwrap(), "\"/é\"");
        assert_eq!(
            quote(b"/a\nb").unwrap_err(),
            EscapeError::ControlCharacter { at: 2, byte: b'\n' }
        );
        assert_eq!(
            quote(b"/a\x7f").unwrap_err(),
            EscapeError::ControlCharacter { at: 2, byte: 0x7f }
        );
        assert_eq!(
            quote(b"/a\0").unwrap_err(),
            EscapeError::ControlCharacter { at: 2, byte: 0 }
        );
        assert_eq!(
            quote(b"/a\xff").unwrap_err(),
            EscapeError::NotUtf8 { at: 2 }
        );
    }

    #[test]
    fn long_values_become_params() {
        let short = [b'a'; INLINE_LIMIT - 2];
        let long = [b'a'; INLINE_LIMIT - 1];
        let mut params = Params::default();
        let r = Rule::new(
            Effect::Allow,
            &["file-read*"],
            vec![Filter::Literal(short.to_vec())],
        );
        assert!(r.render(&mut params).unwrap().contains("(literal \"aaa"));
        let r = Rule::new(
            Effect::Allow,
            &["file-read*"],
            vec![Filter::Literal(long.to_vec())],
        );
        assert_eq!(
            r.render(&mut params).unwrap(),
            "(allow file-read* (literal (param \"P0\")))"
        );
        assert_eq!(params.into_entries()[0].1.len(), INLINE_LIMIT - 1);
    }

    #[test]
    fn rendering() {
        let mut p = Params::default();
        let r = Rule::new(
            Effect::Deny,
            &["system-fcntl"],
            vec![Filter::FcntlCommand(vec![80, 110])],
        );
        assert_eq!(
            r.render(&mut p).unwrap(),
            "(deny system-fcntl (fcntl-command 80 110))"
        );
        let r = Rule::new(
            Effect::Allow,
            &["signal"],
            vec![Filter::Target("self"), Filter::Target("children")],
        );
        assert_eq!(
            r.render(&mut p).unwrap(),
            "(allow signal (require-any (target self) (target children)))"
        );
        let r = Rule::new(
            Effect::Deny,
            &["process-exec*"],
            vec![Filter::FileMode(0o4000)],
        );
        assert_eq!(
            r.render(&mut p).unwrap(),
            "(deny process-exec* (file-mode #o4000))"
        );
        let r = Rule::new(
            Effect::Deny,
            &["file-ioctl"],
            vec![Filter::IoctlCommand(0x8001_7472)],
        );
        assert_eq!(
            r.render(&mut p).unwrap(),
            "(deny file-ioctl (ioctl-command #x80017472))"
        );
    }

    #[test]
    fn merge_keeps_effects_apart() {
        let lit = |s: &str| Filter::Literal(s.as_bytes().to_vec());
        let rules = vec![
            Rule::new(Effect::Allow, &["file-read*"], vec![lit("/a")]),
            Rule::new(Effect::Allow, &["file-read*"], vec![lit("/b")]),
            Rule::new(Effect::Deny, &["file-read*"], vec![lit("/a")]),
            Rule::new(Effect::Allow, &["file-read*"], vec![lit("/c")]),
        ];
        let merged = merge_adjacent(rules, MAX_MERGED_FILTERS);
        assert_eq!(merged.len(), 3);
        assert_eq!(merged[0].filters, vec![lit("/a"), lit("/b")]);
    }
}
