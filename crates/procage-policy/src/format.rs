//! The serialised form (feature `serde`).
//!
//! - A policy is written with `"version": 1`; any other version is refused.
//! - Every map refuses unknown fields, because an unknown field may be a
//!   restriction written by a newer writer.
//! - Every value is read through its constructor, so a document cannot hold
//!   a value code could not build.
//! - A path is a string when its bytes are valid UTF-8, otherwise an array of
//!   byte values.

use alloc::collections::BTreeSet;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::path::{AbsPath, PathError};
use crate::policy::{
    Base, EnvPolicy, FsRule, Grant, HardDenyClass, Ipc, Network, Policy, PresetTag, Process,
    Rlimits, Tty,
};
use crate::{linux, seatbelt};

/// How a path is written.
#[derive(Serialize, Deserialize)]
#[serde(untagged)]
pub(crate) enum PathRepr {
    Text(String),
    Bytes(Vec<u8>),
}

impl From<AbsPath> for PathRepr {
    fn from(path: AbsPath) -> Self {
        match String::from_utf8(path.into_bytes()) {
            Ok(text) => PathRepr::Text(text),
            Err(e) => PathRepr::Bytes(e.into_bytes()),
        }
    }
}

impl TryFrom<PathRepr> for AbsPath {
    type Error = PathError;

    fn try_from(repr: PathRepr) -> Result<Self, PathError> {
        match repr {
            PathRepr::Text(text) => AbsPath::new(text.into_bytes()),
            PathRepr::Bytes(bytes) => AbsPath::new(bytes),
        }
    }
}

/// The schema version; only 1 exists.
#[derive(Clone, Copy)]
pub(crate) struct Version;

impl Serialize for Version {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_u32(1)
    }
}

impl<'de> Deserialize<'de> for Version {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let version = u32::deserialize(deserializer)?;
        if version == 1 {
            Ok(Version)
        } else {
            Err(serde::de::Error::custom(UnsupportedVersion(version)))
        }
    }
}

struct UnsupportedVersion(u32);

impl fmt::Display for UnsupportedVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "unsupported policy version {}", self.0)
    }
}

/// How a policy is written.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PolicyRepr {
    version: Version,
    #[serde(default)]
    fs: Vec<FsRule>,
    #[serde(default)]
    net: Network,
    #[serde(default)]
    process: Process,
    #[serde(default)]
    ipc: Ipc,
    #[serde(default)]
    env: EnvPolicy,
    #[serde(default)]
    limits: Rlimits,
    #[serde(default)]
    tty: Tty,
    #[serde(default)]
    base: Base,
    #[serde(default)]
    preset: Option<PresetTag>,
    #[serde(default)]
    waive: BTreeSet<HardDenyClass>,
    #[serde(default)]
    grants: Vec<Grant>,
    #[serde(default)]
    seatbelt: Option<seatbelt::Layer>,
    #[serde(default)]
    linux: Option<linux::Layer>,
}

impl From<Policy> for PolicyRepr {
    fn from(p: Policy) -> Self {
        Self {
            version: Version,
            fs: p.fs,
            net: p.net,
            process: p.process,
            ipc: p.ipc,
            env: p.env,
            limits: p.limits,
            tty: p.tty,
            base: p.base,
            preset: p.preset,
            waive: p.waive,
            grants: p.grants,
            seatbelt: p.seatbelt,
            linux: p.linux,
        }
    }
}

impl From<PolicyRepr> for Policy {
    fn from(r: PolicyRepr) -> Self {
        let _ = r.version;
        Policy {
            fs: r.fs,
            net: r.net,
            process: r.process,
            ipc: r.ipc,
            env: r.env,
            limits: r.limits,
            tty: r.tty,
            base: r.base,
            preset: r.preset,
            waive: r.waive,
            grants: r.grants,
            seatbelt: r.seatbelt,
            linux: r.linux,
        }
    }
}
