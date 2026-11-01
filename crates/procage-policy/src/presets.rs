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
//! **Linux lists** (version 1; see [`linux_class_paths`]): homes are `/root`
//! and every directory under `/home` ([`LINUX_HOMES`]).
//!
//! - `secrets`: [`SECRETS_HOME_LINUX`] in every home.
//! - `trust-handoff`: [`HANDOFF_ANYWHERE`] in any directory, [`HANDOFF_HOME`]
//!   in every home, and no rename or removal of `.git`.
//! - `persistence`: [`PERSISTENCE_HOME_LINUX`] in every home and
//!   [`PERSISTENCE_SYSTEM_LINUX`].
//!
//! Landlock cannot deny inside a tree it allows. Where no rule of a policy
//! can reach a class's paths, Landlock's default deny enforces the class
//! exactly. Where one can, tier T1 masks the paths that exist at spawn (an
//! approximation: paths created later are not covered) and tier T2 cannot
//! enforce the class; the lowering table gives the details.
//!
//! **Presets** (frozen; use version 3). Each returns an ordinary [`Policy`]
//! with the base profile of its version, the full hard-deny tier, an
//! environment allowlist of [`PRESET_ENV`], and a [`PresetTag`]:
//!
//! | Preset | Adds |
//! |---|---|
//! | [`minimal::v1`], [`minimal::v2`], [`minimal::v3`] | nothing |
//! | [`agent_readonly::v1`], [`agent_readonly::v2`], [`agent_readonly::v3`] | read of the workspace, the `tmpdir` grant, fork, signals to self and children |
//! | [`agent_workspace::v1`], [`agent_workspace::v2`], [`agent_workspace::v3`] | as `agent_readonly`, plus write and exec on the workspace |
//! | [`build::v1`] | as `agent_workspace`, plus loopback network |
//! | [`build::v2`], [`build::v3`] | as `build::v1`, plus Unix sockets in the workspace |
//!
//! Every preset keeps the default [`Lifetime::Run`](crate::Lifetime::Run):
//! the processes a forking preset's child starts end with the run. On Linux
//! `setsid` and `setpgid` fail inside them; their macOS profiles end with
//! the run-marker block.
//!
//! On Linux, `build` is a capability gap (Linux cages have no loopback
//! networking), and the write rules of `agent_workspace` and `build` reach
//! trust-handoff names (see above).

use alloc::format;
use alloc::string::ToString;
use alloc::vec::Vec;

use crate::glob::Glob;
use crate::linux::ClassPaths;
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

/// Linux: the home directories (`/root` and every directory under `/home`).
pub const LINUX_HOMES: &[&str] = &["/home/*", "/root"];

/// Linux: secrets, relative to each home.
pub const SECRETS_HOME_LINUX: &[&str] = &[
    ".aws",
    ".cargo/credentials.toml",
    ".config/BraveSoftware",
    ".config/chromium",
    ".config/gcloud",
    ".config/gh",
    ".config/google-chrome",
    ".config/microsoft-edge",
    ".docker/config.json",
    ".git-credentials",
    ".gnupg",
    ".kube",
    ".local/share/keyrings",
    ".mozilla",
    ".netrc",
    ".password-store",
    ".pypirc",
    ".ssh",
];

/// Linux: persistence locations, relative to each home.
pub const PERSISTENCE_HOME_LINUX: &[&str] = &[
    ".config/autostart",
    ".config/systemd/user",
    ".local/share/systemd/user",
];

/// Linux: system-wide persistence locations.
pub const PERSISTENCE_SYSTEM_LINUX: &[&str] = &[
    "/etc/cron.d",
    "/etc/systemd/system",
    "/etc/xdg/autostart",
    "/var/spool/cron",
];

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

fn strings(list: &[&str]) -> Vec<alloc::string::String> {
    list.iter().map(|s| s.to_string()).collect()
}

/// The Linux paths of a data-driven class (`None` for the other classes).
pub fn linux_class_paths(class: HardDenyClass) -> Option<ClassPaths> {
    let system = |list: &[&str]| -> Vec<AbsPath> {
        list.iter()
            .map(|p| AbsPath::new(*p).unwrap_or_else(|_| unreachable!("valid path {p}")))
            .collect()
    };
    Some(match class {
        HardDenyClass::Secrets => ClassPaths {
            class,
            hide: true,
            home: strings(SECRETS_HOME_LINUX),
            anywhere: Vec::new(),
            system: Vec::new(),
            pin_git: false,
        },
        HardDenyClass::TrustHandoff => ClassPaths {
            class,
            hide: false,
            home: strings(HANDOFF_HOME),
            anywhere: strings(HANDOFF_ANYWHERE),
            system: Vec::new(),
            pin_git: true,
        },
        HardDenyClass::Persistence => ClassPaths {
            class,
            hide: false,
            home: strings(PERSISTENCE_HOME_LINUX),
            anywhere: Vec::new(),
            system: system(PERSISTENCE_SYSTEM_LINUX),
            pin_git: false,
        },
        _ => return None,
    })
}

/// The pattern of a `.git` directory, whose removal or renaming
/// [`HardDenyClass::TrustHandoff`] denies.
pub fn git_dir() -> Glob {
    glob("/**/.git")
}

/// The common start of preset `name` at `version` (base V1, V2 or V3).
fn base(name: &str, version: u32) -> Policy {
    Policy {
        base: match version {
            1 => Base::V1,
            2 => Base::V2,
            _ => Base::V3,
        },
        env: EnvPolicy::Allowlist(PRESET_ENV.iter().map(|v| v.to_string()).collect()),
        preset: Some(PresetTag {
            name: name.into(),
            version,
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

/// `minimal`: a base profile and nothing else.
pub mod minimal {
    use super::*;

    /// Version 1.
    pub fn v1() -> Policy {
        base("minimal", 1)
    }

    /// Version 2: base profile V2.
    pub fn v2() -> Policy {
        base("minimal", 2)
    }

    /// Version 3: base profile V3.
    pub fn v3() -> Policy {
        base("minimal", 3)
    }
}

/// `agent_readonly`: read a workspace, no network.
pub mod agent_readonly {
    use super::*;

    /// Version 1.
    pub fn v1(root: &AbsPath) -> Policy {
        let mut p = base("agent_readonly", 1);
        workspace(&mut p, root, &[Access::Read]);
        p
    }

    /// Version 2: as version 1 on base profile V2.
    pub fn v2(root: &AbsPath) -> Policy {
        let mut p = base("agent_readonly", 2);
        workspace(&mut p, root, &[Access::Read]);
        p
    }

    /// Version 3: as version 2 on base profile V3.
    pub fn v3(root: &AbsPath) -> Policy {
        let mut p = base("agent_readonly", 3);
        workspace(&mut p, root, &[Access::Read]);
        p
    }
}

/// `agent_workspace`: read, write and execute in a workspace, no network.
pub mod agent_workspace {
    use super::*;

    /// Version 1.
    pub fn v1(root: &AbsPath) -> Policy {
        let mut p = base("agent_workspace", 1);
        workspace(&mut p, root, &[Access::Write, Access::Exec]);
        p
    }

    /// Version 2: as version 1 on base profile V2.
    pub fn v2(root: &AbsPath) -> Policy {
        let mut p = base("agent_workspace", 2);
        workspace(&mut p, root, &[Access::Write, Access::Exec]);
        p
    }

    /// Version 3: as version 2 on base profile V3.
    pub fn v3(root: &AbsPath) -> Policy {
        let mut p = base("agent_workspace", 3);
        workspace(&mut p, root, &[Access::Write, Access::Exec]);
        p
    }
}

/// `build`: as `agent_workspace`, plus loopback network for test servers.
pub mod build {
    use super::*;

    /// Version 1.
    pub fn v1(root: &AbsPath) -> Policy {
        let mut p = base("build", 1);
        workspace(&mut p, root, &[Access::Write, Access::Exec]);
        p.net = Network::Loopback(Ports::Any);
        p
    }

    /// Version 2: as version 1 on base profile V2, plus Unix sockets in the
    /// workspace (test servers).
    pub fn v2(root: &AbsPath) -> Policy {
        let mut p = base("build", 2);
        workspace(&mut p, root, &[Access::Write, Access::Exec]);
        p.net = Network::Loopback(Ports::Any);
        p.ipc.unix_sockets = alloc::vec![root.clone()];
        p
    }

    /// Version 3: as version 2 on base profile V3.
    pub fn v3(root: &AbsPath) -> Policy {
        let mut p = base("build", 3);
        workspace(&mut p, root, &[Access::Write, Access::Exec]);
        p.net = Network::Loopback(Ports::Any);
        p.ipc.unix_sockets = alloc::vec![root.clone()];
        p
    }
}
