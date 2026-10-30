//! Globs: patterns that exist only because the author built one.
//!
//! A [`Glob`] is never inferred from a path. A directory whose name contains
//! `*` is a path, and stays one. The supported syntax is deliberately small:
//!
//! | Token | Matches |
//! |---|---|
//! | `*` | any characters within one path component |
//! | `?` | one character within a component |
//! | `**` | any number of whole components; only as a whole component |
//! | `\x` | the character `x` literally |
//!
//! `[`, `]`, `{` and `}` are refused rather than guessed. For Seatbelt a glob
//! becomes one regular expression anchored at both ends in which every
//! literal character is escaped ([`Glob::to_sbpl_regex`]).

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

/// Why text is not a [`Glob`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum GlobError {
    /// The glob is empty.
    Empty,
    /// The glob does not start with `/`.
    Relative,
    /// A control character (U+0000–U+001F, U+007F) at this byte offset.
    ControlCharacter {
        /// Byte offset.
        at: usize,
    },
    /// Wildcard syntax this glob dialect does not support.
    UnsupportedSyntax {
        /// Byte offset.
        at: usize,
        /// The character.
        ch: char,
    },
    /// `**` that is not a whole path component.
    MisplacedDoubleStar {
        /// Byte offset of the first `*`.
        at: usize,
    },
    /// The glob ends with a lone `\`.
    TrailingEscape,
}

impl fmt::Display for GlobError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GlobError::Empty => f.write_str("glob is empty"),
            GlobError::Relative => f.write_str("glob is not absolute (it must start with '/')"),
            GlobError::ControlCharacter { at } => {
                write!(f, "glob contains a control character at offset {at}")
            }
            GlobError::UnsupportedSyntax { at, ch } => {
                write!(
                    f,
                    "glob uses unsupported syntax {ch:?} at offset {at} (escape it with '\\')"
                )
            }
            GlobError::MisplacedDoubleStar { at } => {
                write!(f, "'**' at offset {at} is not a whole path component")
            }
            GlobError::TrailingEscape => f.write_str("glob ends with a lone '\\'"),
        }
    }
}

impl core::error::Error for GlobError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum Token {
    Literal(char),
    Star,
    Question,
    /// `**/`: zero or more whole directories.
    AnyDirs,
    /// A trailing `/**`: the directory itself and everything below it.
    AnyBelow,
}

/// Characters that have a meaning in SBPL (POSIX extended) regular
/// expressions and are escaped when they occur literally.
pub const REGEX_META: &[char] = &[
    '\\', '.', '^', '$', '|', '?', '*', '+', '(', ')', '[', ']', '{', '}',
];

/// An absolute glob pattern.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(try_from = "String", into = "String")
)]
pub struct Glob {
    source: String,
    tokens: Vec<Token>,
}

fn parse(source: &str) -> Result<Vec<Token>, GlobError> {
    if source.is_empty() {
        return Err(GlobError::Empty);
    }
    if !source.starts_with('/') {
        return Err(GlobError::Relative);
    }
    let chars: Vec<(usize, char)> = source.char_indices().collect();
    let mut tokens = Vec::new();
    let mut i = 0;
    while i < chars.len() {
        let (at, ch) = chars[i];
        if ch.is_control() && (ch as u32) < 0x80 {
            return Err(GlobError::ControlCharacter { at });
        }
        match ch {
            '\\' => {
                let Some(&(at, next)) = chars.get(i + 1) else {
                    return Err(GlobError::TrailingEscape);
                };
                if next.is_control() && (next as u32) < 0x80 {
                    return Err(GlobError::ControlCharacter { at });
                }
                tokens.push(Token::Literal(next));
                i += 2;
            }
            '[' | ']' | '{' | '}' => return Err(GlobError::UnsupportedSyntax { at, ch }),
            '?' => {
                tokens.push(Token::Question);
                i += 1;
            }
            '*' => {
                if chars.get(i + 1).map(|c| c.1) != Some('*') {
                    tokens.push(Token::Star);
                    i += 1;
                    continue;
                }
                let starts_component = matches!(tokens.last(), Some(Token::Literal('/')));
                match chars.get(i + 2).map(|c| c.1) {
                    Some('/') if starts_component => {
                        tokens.push(Token::AnyDirs);
                        i += 3;
                    }
                    None if starts_component => {
                        tokens.pop();
                        tokens.push(Token::AnyBelow);
                        i += 2;
                    }
                    _ => return Err(GlobError::MisplacedDoubleStar { at }),
                }
            }
            _ => {
                tokens.push(Token::Literal(ch));
                i += 1;
            }
        }
    }
    Ok(tokens)
}

impl Glob {
    /// Parses `source`.
    pub fn new(source: &str) -> Result<Self, GlobError> {
        let tokens = parse(source)?;
        Ok(Self {
            source: source.into(),
            tokens,
        })
    }

    /// The glob as written.
    pub fn as_str(&self) -> &str {
        &self.source
    }

    /// The characters the glob matches literally, in order (wildcards
    /// removed, escapes resolved).
    pub fn literal_chars(&self) -> impl Iterator<Item = char> + '_ {
        self.tokens.iter().filter_map(|t| match t {
            Token::Literal(c) => Some(*c),
            _ => None,
        })
    }

    /// Whether the glob contains a wildcard at all.
    pub fn has_wildcard(&self) -> bool {
        self.tokens.iter().any(|t| !matches!(t, Token::Literal(_)))
    }

    /// The SBPL regular expression for this glob, anchored with `^` and `$`.
    ///
    /// The result is regex text, not a quoted SBPL string; the profile writer
    /// passes it through the one quoting function like any other value.
    pub fn to_sbpl_regex(&self) -> String {
        let mut out = String::from("^");
        for token in &self.tokens {
            match token {
                Token::Literal(c) => {
                    if REGEX_META.contains(c) {
                        out.push('\\');
                    }
                    out.push(*c);
                }
                Token::Star => out.push_str("[^/]*"),
                Token::Question => out.push_str("[^/]"),
                Token::AnyDirs => out.push_str("(.*/)?"),
                Token::AnyBelow => out.push_str("(/.*)?"),
            }
        }
        out.push('$');
        out
    }
}

impl TryFrom<&str> for Glob {
    type Error = GlobError;

    fn try_from(source: &str) -> Result<Self, GlobError> {
        Self::new(source)
    }
}

impl TryFrom<String> for Glob {
    type Error = GlobError;

    fn try_from(source: String) -> Result<Self, GlobError> {
        let tokens = parse(&source)?;
        Ok(Self { source, tokens })
    }
}

impl From<Glob> for String {
    fn from(glob: Glob) -> String {
        glob.source
    }
}

impl fmt::Display for Glob {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.source)
    }
}

impl fmt::Debug for Glob {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Glob({:?})", self.source)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn regex(source: &str) -> String {
        Glob::new(source).unwrap().to_sbpl_regex()
    }

    #[test]
    fn translation() {
        assert_eq!(regex("/work/**/*.rs"), r"^/work/(.*/)?[^/]*\.rs$");
        assert_eq!(regex("/work/**"), r"^/work(/.*)?$");
        assert_eq!(regex("/a?c"), r"^/a[^/]c$");
        assert_eq!(regex("/a.b+c(d)|e^f$"), r"^/a\.b\+c\(d\)\|e\^f\$$");
        assert_eq!(regex(r"/lit\*\[x\]"), r"^/lit\*\[x\]$");
        assert_eq!(regex("/work/a.txt"), r"^/work/a\.txt$");
    }

    #[test]
    fn refusals() {
        assert_eq!(Glob::new("").unwrap_err(), GlobError::Empty);
        assert_eq!(Glob::new("work/*").unwrap_err(), GlobError::Relative);
        assert_eq!(
            Glob::new("/a[b]").unwrap_err(),
            GlobError::UnsupportedSyntax { at: 2, ch: '[' }
        );
        assert_eq!(
            Glob::new("/a/{b,c}").unwrap_err(),
            GlobError::UnsupportedSyntax { at: 3, ch: '{' }
        );
        assert_eq!(
            Glob::new("/a**").unwrap_err(),
            GlobError::MisplacedDoubleStar { at: 2 }
        );
        assert_eq!(
            Glob::new("/**x").unwrap_err(),
            GlobError::MisplacedDoubleStar { at: 1 }
        );
        assert_eq!(
            Glob::new("/a/***").unwrap_err(),
            GlobError::MisplacedDoubleStar { at: 3 }
        );
        assert_eq!(Glob::new("/a\\").unwrap_err(), GlobError::TrailingEscape);
        assert_eq!(
            Glob::new("/a\nb").unwrap_err(),
            GlobError::ControlCharacter { at: 2 }
        );
    }

    #[test]
    fn literal_chars_resolve_escapes() {
        let g = Glob::new(r"/a\*b/*.c").unwrap();
        assert_eq!(g.literal_chars().collect::<String>(), "/a*b/.c");
        assert!(g.has_wildcard());
        assert!(!Glob::new("/plain").unwrap().has_wildcard());
    }
}
