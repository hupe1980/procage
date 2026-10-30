//! Data-driven hard-deny classes and frozen presets.
//!
//! **Hard-deny lists** (version 1, macOS; emitted last in every profile,
//! case-folded, waivable only by class name):
//!
//! - [`HardDenyClass::Secrets`] denies reading and writing [`SECRETS_HOME`]
//!   in every home under `/Users`.
//! - [`HardDenyClass::TrustHandoff`] denies writing [`HANDOFF_ANYWHERE`] in
//!   any directory and [`HANDOFF_HOME`] in every home, and removing or
//!   renaming any `.git` directory (so `.git` cannot be moved aside, edited
//!   and moved back). Objects, refs, the index and the working tree stay
//!   writable. `git init` and `git clone` write hooks and config, so they
//!   need the class waived.
//! - [`HardDenyClass::Persistence`] denies writing [`PERSISTENCE_HOME`] in
//!   every home and [`PERSISTENCE_SYSTEM`].
//!
//! On Linux these classes are not expressible yet: Landlock cannot deny
//! inside a granted tree, and masking at spawn belongs to the Linux spawn
//! backend, which must implement them before it ships.
//!
//! **Presets** (version 1, frozen). Each returns an ordinary [`Policy`] with
//! base profile V1, the full hard-deny tier, an environment allowlist of
//! [`PRESET_ENV`], and a [`PresetTag`]:
//!
//! | Preset | Adds |
//! |---|---|
//! | [`minimal::v1`] | nothing |
//! | [`agent_readonly::v1`] | read of the workspace, the `tmpdir` grant, fork, signals to self and children |
//! | [`agent_workspace::v1`] | as `agent_readonly`, plus write and exec on the workspace |
//! | [`build::v1`] | as `agent_workspace`, plus loopback network |

use alloc::format;
use alloc::string::ToString;
use alloc::vec::Vec;

use crate::glob::Glob;
use crate::name::GrantName;
use crate::path::AbsPath;
use crate::policy::{
    Access, Base, EnvPolicy, FsRule, FsTarget, Grant, HardDenyClass, Network, Policy, Ports,
    PresetTag, Signals,
};

/// Secrets, relative to each home.
pub const SECRETS_HOME: &[&str] = &[
    ".aws",
    ".cargo/credentials.toml",
    ".config/gcloud",
    ".config/gh",
    ".docker/config.json",
    ".git-credentials",
    ".gnupg",
    ".kube",
    ".netrc",
    ".pypirc",
    ".ssh",
    "Library/Application Support/BraveSoftware",
    "Library/Application Support/Firefox",
    "Library/Application Support/Google/Chrome",
    "Library/Application Support/Microsoft Edge",
    "Library/Cookies",
    "Library/Keychains",
    "Library/Mail",
    "Library/Messages",
    "Library/Safari",
];

/// Trust-handoff names, in any directory.
pub const HANDOFF_ANYWHERE: &[&str] = &[
    ".bash_profile",
    ".bashrc",
    ".cargo/config",
    ".cargo/config.toml",
    ".claude",
    ".codex",
    ".cursor",
    ".envrc",
    ".git/config",
    ".git/hooks",
    ".gitconfig",
    ".gitmodules",
    ".idea",
    ".mcp.json",
    ".npmrc",
    ".profile",
    ".vscode",
    ".zprofile",
    ".zshenv",
    ".zshrc",
];

/// Trust-handoff paths, relative to each home.
pub const HANDOFF_HOME: &[&str] = &[".cargo/bin", ".local/bin", ".ssh/config"];

/// Persistence locations, relative to each home.
pub const PERSISTENCE_HOME: &[&str] = &[
    "Library/Application Support/com.apple.backgroundtaskmanagementagent",
    "Library/LaunchAgents",
    "Library/LaunchDaemons",
];

/// System-wide persistence locations.
pub const PERSISTENCE_SYSTEM: &[&str] = &["/Library/LaunchAgents", "/Library/LaunchDaemons"];

/// The environment allowlist of every preset.
pub const PRESET_ENV: &[&str] = &["HOME", "LANG", "LC_ALL", "PATH", "TERM", "TMPDIR", "USER"];

fn glob(source: &str) -> Glob {
    // Every pattern below is a valid absolute glob.
    Glob::new(source).unwrap_or_else(|_| unreachable!("invalid built-in pattern {source}"))
}

/// Escapes glob syntax in a literal name.
fn literal(name: &str) -> alloc::string::String {
    let mut out = alloc::string::String::new();
    for c in name.chars() {
        if matches!(c, '\\' | '*' | '?' | '[' | ']' | '{' | '}') {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

fn home(rel: &str) -> Glob {
    glob(&format!("/Users/*/{}/**", literal(rel)))
}

fn anywhere(name: &str) -> Glob {
    glob(&format!("/**/{}/**", literal(name)))
}

/// The patterns of a data-driven class (empty for the other classes).
pub fn patterns(class: HardDenyClass) -> Vec<Glob> {
    match class {
        HardDenyClass::Secrets => SECRETS_HOME.iter().map(|r| home(r)).collect(),
        HardDenyClass::TrustHandoff => HANDOFF_ANYWHERE
            .iter()
            .map(|n| anywhere(n))
            .chain(HANDOFF_HOME.iter().map(|r| home(r)))
            .collect(),
        HardDenyClass::Persistence => PERSISTENCE_HOME
            .iter()
            .map(|r| home(r))
            .chain(
                PERSISTENCE_SYSTEM
                    .iter()
                    .map(|p| glob(&format!("{}/**", literal(p)))),
            )
            .collect(),
        _ => Vec::new(),
    }
}

/// The pattern of a `.git` directory, whose removal or renaming
/// [`HardDenyClass::TrustHandoff`] denies.
pub fn git_dir() -> Glob {
    glob("/**/.git")
}

fn base(name: &str) -> Policy {
    Policy {
        base: Base::V1,
        env: EnvPolicy::Allowlist(PRESET_ENV.iter().map(|v| v.to_string()).collect()),
        preset: Some(PresetTag {
            name: name.into(),
            version: 1,
        }),
        ..Policy::default()
    }
}

fn workspace(p: &mut Policy, root: &AbsPath, access: &[Access]) {
    for &a in access {
        p.fs.push(FsRule::new(a, FsTarget::Subpath(root.clone())));
    }
    p.grants.push(Grant {
        name: GrantName::new("tmpdir").unwrap_or_else(|_| unreachable!("valid name")),
        access: Access::Write,
    });
    p.process.fork = true;
    p.process.signals = Signals::SelfAndChildren;
}

/// `minimal`: base profile V1 and nothing else.
pub mod minimal {
    use super::*;

    /// Version 1.
    pub fn v1() -> Policy {
        base("minimal")
    }
}

/// `agent_readonly`: read a workspace, no network.
pub mod agent_readonly {
    use super::*;

    /// Version 1.
    pub fn v1(root: &AbsPath) -> Policy {
        let mut p = base("agent_readonly");
        workspace(&mut p, root, &[Access::Read]);
        p
    }
}

/// `agent_workspace`: read, write and execute in a workspace, no network.
pub mod agent_workspace {
    use super::*;

    /// Version 1.
    pub fn v1(root: &AbsPath) -> Policy {
        let mut p = base("agent_workspace");
        workspace(&mut p, root, &[Access::Write, Access::Exec]);
        p
    }
}

/// `build`: as `agent_workspace`, plus loopback network for test servers.
pub mod build {
    use super::*;

    /// Version 1.
    pub fn v1(root: &AbsPath) -> Policy {
        let mut p = base("build");
        workspace(&mut p, root, &[Access::Write, Access::Exec]);
        p.net = Network::Loopback(Ports::Any);
        p
    }
}
