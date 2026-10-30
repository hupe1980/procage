//! Validated identifiers.
//!
//! Each of these values ends up inside a profile or plan: a grant name becomes
//! part of a sandbox-extension class, a tag becomes the run tag, a name
//! becomes a Mach service name. They are restricted to short identifiers, so
//! no quote, space or parenthesis can reach the output through them.

use alloc::string::{String, ToString};
use core::fmt;
use core::str::FromStr;

/// The kind of identifier a [`NameError`] is about.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum NameKind {
    /// A [`GrantName`].
    Grant,
    /// A [`Tag`].
    Tag,
    /// A [`Name`].
    Name,
    /// An [`OperationName`].
    Operation,
    /// A [`SyscallName`].
    Syscall,
    /// A [`Port`].
    Port,
}

impl NameKind {
    fn rule(self) -> &'static str {
        match self {
            NameKind::Grant => "1 to 32 of [a-z0-9_-]",
            NameKind::Tag => "1 to 64 of [A-Za-z0-9._-]",
            NameKind::Name => "1 to 128 of [A-Za-z0-9._-]",
            NameKind::Operation => "1 to 64 of [a-z0-9*-], not `default`",
            NameKind::Syscall => "1 to 32 of [a-z0-9_]",
            NameKind::Port => "a port from 1 to 65535",
        }
    }
}

impl fmt::Display for NameKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            NameKind::Grant => "grant name",
            NameKind::Tag => "tag",
            NameKind::Name => "name",
            NameKind::Operation => "operation name",
            NameKind::Syscall => "syscall name",
            NameKind::Port => "port",
        })
    }
}

/// An identifier that does not match its rule.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NameError {
    /// What the value was meant to be.
    pub kind: NameKind,
    /// The refused value.
    pub value: String,
}

impl fmt::Display for NameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "invalid {} {:?}: expected {}",
            self.kind,
            self.value,
            self.kind.rule()
        )
    }
}

impl core::error::Error for NameError {}

fn check(
    kind: NameKind,
    value: &str,
    max: usize,
    allowed: fn(u8) -> bool,
) -> Result<(), NameError> {
    // `default` would let a raw rule allow everything by default.
    let forbidden = kind == NameKind::Operation && value == "default";
    if forbidden || value.is_empty() || value.len() > max || !value.bytes().all(allowed) {
        return Err(NameError {
            kind,
            value: value.to_string(),
        });
    }
    Ok(())
}

macro_rules! name_type {
    ($(#[$meta:meta])* $ty:ident, $kind:expr, $max:expr, $allowed:expr) => {
        $(#[$meta])*
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
        #[cfg_attr(
            feature = "serde",
            derive(serde::Serialize, serde::Deserialize),
            serde(try_from = "String", into = "String")
        )]
        pub struct $ty(String);

        impl $ty {
            /// Checks `value` and wraps it.
            pub fn new(value: &str) -> Result<Self, NameError> {
                check($kind, value, $max, $allowed)?;
                Ok(Self(value.to_string()))
            }

            /// The identifier.
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl TryFrom<&str> for $ty {
            type Error = NameError;

            fn try_from(value: &str) -> Result<Self, NameError> {
                Self::new(value)
            }
        }

        impl TryFrom<String> for $ty {
            type Error = NameError;

            fn try_from(value: String) -> Result<Self, NameError> {
                check($kind, &value, $max, $allowed)?;
                Ok(Self(value))
            }
        }

        impl FromStr for $ty {
            type Err = NameError;

            fn from_str(value: &str) -> Result<Self, NameError> {
                Self::new(value)
            }
        }

        impl From<$ty> for String {
            fn from(value: $ty) -> String {
                value.0
            }
        }

        impl AsRef<str> for $ty {
            fn as_ref(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $ty {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }
    };
}

name_type!(
    /// The name of a per-spawn grant: `[a-z0-9_-]{1,32}`.
    ///
    /// On macOS it becomes the sandbox-extension class `procage.<name>`.
    GrantName,
    NameKind::Grant,
    32,
    |b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-'
);

name_type!(
    /// A run tag for violation correlation: `[A-Za-z0-9._-]{1,64}`.
    Tag,
    NameKind::Tag,
    64,
    |b| b.is_ascii_alphanumeric() || b == b'.' || b == b'_' || b == b'-'
);

name_type!(
    /// A Mach service name or prefix: `[A-Za-z0-9._-]{1,128}`.
    Name,
    NameKind::Name,
    128,
    |b| b.is_ascii_alphanumeric() || b == b'.' || b == b'_' || b == b'-'
);

name_type!(
    /// A Seatbelt operation name outside the closed list: `[a-z0-9*-]{1,64}`.
    ///
    /// Only reachable through `seatbelt::Operation::Other` with the feature
    /// `unstable-operations`. The character set leaves no way to write a
    /// parenthesis, space or quote into a profile, and `default` is refused:
    /// a policy cannot allow by default.
    OperationName,
    NameKind::Operation,
    64,
    |b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'*' || b == b'-'
);

name_type!(
    /// A Linux syscall name outside the named set: `[a-z0-9_]{1,32}`.
    SyscallName,
    NameKind::Syscall,
    32,
    |b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_'
);

/// A TCP or UDP port from 1 to 65535.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(try_from = "u16", into = "u16")
)]
pub struct Port(u16);

impl Port {
    /// Checks that `port` is not 0.
    pub fn new(port: u16) -> Result<Self, NameError> {
        if port == 0 {
            return Err(NameError {
                kind: NameKind::Port,
                value: "0".to_string(),
            });
        }
        Ok(Self(port))
    }

    /// The port number.
    pub fn get(self) -> u16 {
        self.0
    }
}

impl TryFrom<u16> for Port {
    type Error = NameError;

    fn try_from(port: u16) -> Result<Self, NameError> {
        Self::new(port)
    }
}

impl From<Port> for u16 {
    fn from(port: Port) -> u16 {
        port.0
    }
}

impl fmt::Display for Port {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grant_names() {
        assert!(GrantName::new("scratch").is_ok());
        assert!(GrantName::new("work_dir-2").is_ok());
        for bad in ["", "A", "a b", "a\"b", "a/b", "a.b", &"a".repeat(33)] {
            assert_eq!(
                GrantName::new(bad).unwrap_err().kind,
                NameKind::Grant,
                "{bad:?}"
            );
        }
    }

    #[test]
    fn operation_names() {
        assert!(OperationName::new("file-read*").is_ok());
        for bad in ["a(b", "a b", "a\"b", "no-sandbox)", "File", "", "default"] {
            assert!(OperationName::new(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn tags_names_syscalls_ports() {
        assert!(Tag::new("pc-run.1_A").is_ok());
        assert!(Tag::new("a b").is_err());
        assert!(Name::new("com.apple.lsd.mapdb").is_ok());
        assert!(Name::new("com.apple\"x").is_err());
        assert!(SyscallName::new("io_uring_setup").is_ok());
        assert!(SyscallName::new("io-uring").is_err());
        assert!(Port::new(0).is_err());
        assert_eq!(Port::new(8080).unwrap().get(), 8080);
    }

    #[test]
    fn error_message_names_the_rule() {
        let err = GrantName::new("a b").unwrap_err();
        assert_eq!(
            err.to_string(),
            "invalid grant name \"a b\": expected 1 to 32 of [a-z0-9_-]"
        );
    }
}
