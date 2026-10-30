//! Absolute paths as exact bytes.
//!
//! [`AbsPath`] checks the *lexical* form only: absolute, no `.` or `..`
//! components, no empty components, no trailing slash, no NUL. It never
//! changes the bytes it is given. Resolving symlinks and firmlinks to the real
//! path needs the filesystem and happens in `procage` before a policy is built.

use alloc::vec::Vec;
use core::fmt;

/// Why a byte string is not an [`AbsPath`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PathError {
    /// The path is empty.
    Empty,
    /// The path does not start with `/` (this includes `~`).
    Relative,
    /// The path contains a NUL byte at this offset.
    Nul {
        /// Byte offset of the NUL.
        at: usize,
    },
    /// The path contains `//`; the empty component starts at this offset.
    EmptyComponent {
        /// Byte offset of the empty component.
        at: usize,
    },
    /// The path contains a `.` component at this offset.
    DotComponent {
        /// Byte offset of the component.
        at: usize,
    },
    /// The path contains a `..` component at this offset.
    DotDotComponent {
        /// Byte offset of the component.
        at: usize,
    },
    /// The path ends with `/` and is not `/` itself.
    TrailingSlash,
}

impl fmt::Display for PathError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PathError::Empty => f.write_str("path is empty"),
            PathError::Relative => {
                f.write_str("path is not absolute (it must start with '/'; '~' is not expanded)")
            }
            PathError::Nul { at } => write!(f, "path contains a NUL byte at offset {at}"),
            PathError::EmptyComponent { at } => {
                write!(f, "path contains an empty component ('//') at offset {at}")
            }
            PathError::DotComponent { at } => {
                write!(f, "path contains a '.' component at offset {at}")
            }
            PathError::DotDotComponent { at } => {
                write!(f, "path contains a '..' component at offset {at}")
            }
            PathError::TrailingSlash => f.write_str("path ends with '/'"),
        }
    }
}

impl core::error::Error for PathError {}

/// An absolute, lexically normal path, stored as exact bytes.
///
/// Bytes that are not valid UTF-8 are kept as they are; whether a backend can
/// express them is decided when the policy is lowered.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(try_from = "crate::format::PathRepr", into = "crate::format::PathRepr")
)]
pub struct AbsPath(Vec<u8>);

fn check(bytes: &[u8]) -> Result<(), PathError> {
    if bytes.is_empty() {
        return Err(PathError::Empty);
    }
    if bytes[0] != b'/' {
        return Err(PathError::Relative);
    }
    if let Some(at) = bytes.iter().position(|&b| b == 0) {
        return Err(PathError::Nul { at });
    }
    if bytes.len() == 1 {
        return Ok(());
    }
    if bytes[bytes.len() - 1] == b'/' {
        return Err(PathError::TrailingSlash);
    }
    let mut at = 1;
    for component in bytes[1..].split(|&b| b == b'/') {
        match component {
            b"" => return Err(PathError::EmptyComponent { at }),
            b"." => return Err(PathError::DotComponent { at }),
            b".." => return Err(PathError::DotDotComponent { at }),
            _ => {}
        }
        at += component.len() + 1;
    }
    Ok(())
}

impl AbsPath {
    /// Checks `bytes` and wraps them unchanged.
    pub fn new(bytes: impl Into<Vec<u8>>) -> Result<Self, PathError> {
        let bytes = bytes.into();
        check(&bytes)?;
        Ok(Self(bytes))
    }

    /// The root directory, `/`.
    pub fn root() -> Self {
        Self(alloc::vec![b'/'])
    }

    /// The exact bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// The exact bytes, by value.
    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }

    /// The path as text, if it is valid UTF-8.
    pub fn to_str(&self) -> Option<&str> {
        core::str::from_utf8(&self.0).ok()
    }

    /// Whether this is `/`.
    pub fn is_root(&self) -> bool {
        self.0.len() == 1
    }

    /// The components after the leading `/`; none for the root.
    pub fn components(&self) -> impl Iterator<Item = &[u8]> {
        let rest = if self.is_root() {
            &[][..]
        } else {
            &self.0[1..]
        };
        rest.split(|&b| b == b'/').filter(|c| !c.is_empty())
    }

    /// The parent directory; `None` for the root.
    pub fn parent(&self) -> Option<AbsPath> {
        if self.is_root() {
            return None;
        }
        let cut = self.0.iter().rposition(|&b| b == b'/').unwrap_or(0);
        Some(if cut == 0 {
            Self::root()
        } else {
            Self(self.0[..cut].to_vec())
        })
    }

    /// Every ancestor, nearest first, ending with `/`.
    pub fn ancestors(&self) -> Vec<AbsPath> {
        let mut out = Vec::new();
        let mut current = self.parent();
        while let Some(path) = current {
            current = path.parent();
            out.push(path);
        }
        out
    }

    /// Whether `self` is `base` or lies below it, compared component by
    /// component (`/ab` does not start with `/a`).
    pub fn starts_with_path(&self, base: &AbsPath) -> bool {
        if base.is_root() {
            return true;
        }
        self.0.starts_with(&base.0)
            && (self.0.len() == base.0.len() || self.0[base.0.len()] == b'/')
    }
}

impl TryFrom<&[u8]> for AbsPath {
    type Error = PathError;

    fn try_from(bytes: &[u8]) -> Result<Self, PathError> {
        Self::new(bytes)
    }
}

impl TryFrom<Vec<u8>> for AbsPath {
    type Error = PathError;

    fn try_from(bytes: Vec<u8>) -> Result<Self, PathError> {
        Self::new(bytes)
    }
}

impl TryFrom<&str> for AbsPath {
    type Error = PathError;

    fn try_from(text: &str) -> Result<Self, PathError> {
        Self::new(text.as_bytes())
    }
}

impl TryFrom<alloc::string::String> for AbsPath {
    type Error = PathError;

    fn try_from(text: alloc::string::String) -> Result<Self, PathError> {
        Self::new(text.into_bytes())
    }
}

impl fmt::Display for AbsPath {
    /// Text for messages: UTF-8 as is, other bytes escaped. Never parse it back.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.to_str() {
            Some(text) => f.write_str(text),
            None => write!(f, "{}", self.0.escape_ascii()),
        }
    }
}

impl fmt::Debug for AbsPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "AbsPath(\"{}\")", self.0.escape_ascii())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn errors_name_their_reason() {
        let cases: &[(&[u8], PathError)] = &[
            (b"", PathError::Empty),
            (b"relative/dir", PathError::Relative),
            (b"~/dir", PathError::Relative),
            (b"/a/../b", PathError::DotDotComponent { at: 3 }),
            (b"/a/./b", PathError::DotComponent { at: 3 }),
            (b"/a//b", PathError::EmptyComponent { at: 3 }),
            (b"/a/", PathError::TrailingSlash),
            (b"/a\0b", PathError::Nul { at: 2 }),
        ];
        for (input, want) in cases {
            assert_eq!(AbsPath::new(*input).unwrap_err(), *want, "{input:?}");
        }
    }

    #[test]
    fn root_parent_and_ancestors() {
        let root = AbsPath::new("/").unwrap();
        assert!(root.is_root());
        assert_eq!(root.parent(), None);
        let p = AbsPath::new("/a/b/c").unwrap();
        let ancestors: Vec<_> = p
            .ancestors()
            .iter()
            .map(|a| a.as_bytes().to_vec())
            .collect();
        assert_eq!(ancestors, [b"/a/b".to_vec(), b"/a".to_vec(), b"/".to_vec()]);
    }

    #[test]
    fn starts_with_is_component_wise() {
        let a = AbsPath::new("/a").unwrap();
        assert!(AbsPath::new("/a/b").unwrap().starts_with_path(&a));
        assert!(AbsPath::new("/a").unwrap().starts_with_path(&a));
        assert!(!AbsPath::new("/ab").unwrap().starts_with_path(&a));
        assert!(
            AbsPath::new("/ab")
                .unwrap()
                .starts_with_path(&AbsPath::root())
        );
    }

    #[test]
    fn non_utf8_is_kept() {
        let p = AbsPath::new(&b"/a\xffb"[..]).unwrap();
        assert_eq!(p.as_bytes(), b"/a\xffb");
        assert_eq!(p.to_str(), None);
    }
}
