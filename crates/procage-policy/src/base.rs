//! The base profile: what ordinary programs need to start, and nothing the
//! user cares about.
//!
//! A policy opts in with [`Base::V1`](crate::Base::V1). Version 1 is frozen;
//! a loosening needs a new version.
//!
//! **macOS** (measured on macOS 26.6.2, 25G83, on 2026-10-30):
//!
//! | Entry | Why |
//! |---|---|
//! | read `/` (the directory itself) | dyld aborts without it |
//! | read, exec, map `/usr/lib`, `/System`, `/bin`, `/sbin`, `/usr/bin`, `/usr/sbin`, `/usr/libexec` | system code and the dyld shared cache |
//! | read `/usr/share`, `/private/etc`, `/private/var/db/timezone`, `/private/var/select`, `/Library/Preferences/Logging` | locale and terminfo data, `/etc` files, local time, the `sh` selector, logging preferences |
//! | metadata of `/etc`, `/tmp`, `/var`, `/private`, `/private/var`, `/usr`, `/Library` | path lookup through the system symlinks |
//! | read/write `/dev/null`, `/dev/zero`, `/dev/dtracehelper`; read `/dev/random`, `/dev/urandom`; read/write under `/dev/fd` | standard devices |
//! | read sysctls | page size, CPU count, OS version (the Rust runtime and `uname` need them) |
//! | look up `com.apple.system.opendirectoryd.libinfo`, `com.apple.system.notification_center`, `com.apple.SystemConfiguration.configd`, `com.apple.trustd`, `com.apple.trustd.agent`, `com.apple.oahd` | user and group names, notifications, system configuration, certificate trust, Rosetta |
//! | read the shared memory `apple.shm.notification_center` | notifications |
//! | with `Tty::Inherit` only: read, write, ioctl on `/dev/tty` and `/dev/ttys*` | the caller's terminal |
//!
//! It allows nothing under `/Users`, `/private/var/folders`, `/private/tmp`
//! or `/Volumes`, no network, no writes beyond the devices above, and no
//! process creation or signals beyond the policy's.
//!
//! procage's tests run these programs with base V1 on the kernel: `id -un`,
//! `whoami`, `date`, `uname -a`, `sh`, `zsh` and `bash` with a command,
//! `cat`, `sort`, `sed`, `awk`, `xxd` on `/dev/urandom`, `perl -e 1`,
//! `tar --version`, `gzip -V`, and a Rust program. Tools that are Xcode
//! shims (`/usr/bin/git`, `/usr/bin/python3`) need developer-tool paths and
//! are not covered.
//!
//! **Linux**: read and exec for `/usr`, `/bin`, `/sbin`, `/lib`, `/lib64`,
//! `/lib32`; read for `/etc`; read/write `/dev/null`, `/dev/zero`; read
//! `/dev/random`, `/dev/urandom`; with `Tty::Inherit`, read/write `/dev/tty`
//! and `/dev/pts`. Paths a host lacks are skipped. This content is
//! expressed in the plan now and verified with Linux spawning.

use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;

use crate::linux::{AccessFs, LandlockRule, RuleTarget, rights};
use crate::path::AbsPath;
use crate::policy::{Access, Tty};
use crate::sbpl::{Filter, Rule};
use crate::seatbelt::Effect;

/// macOS: system code (read, exec, map).
pub const MACOS_CODE: &[&str] = &[
    "/System",
    "/bin",
    "/sbin",
    "/usr/bin",
    "/usr/lib",
    "/usr/libexec",
    "/usr/sbin",
];
/// macOS: system data (read).
pub const MACOS_DATA: &[&str] = &[
    "/Library/Preferences/Logging",
    "/private/etc",
    "/private/var/db/timezone",
    "/private/var/select",
    "/usr/share",
];
/// macOS: directories and symlinks whose metadata path lookup needs.
pub const MACOS_METADATA: &[&str] = &[
    "/Library",
    "/etc",
    "/private",
    "/private/var",
    "/tmp",
    "/usr",
    "/var",
];
/// macOS: devices read and written.
pub const MACOS_DEVICES_RW: &[&str] = &["/dev/dtracehelper", "/dev/null", "/dev/zero"];
/// macOS: devices read.
pub const MACOS_DEVICES_R: &[&str] = &["/dev/random", "/dev/urandom"];
/// macOS: Mach services looked up.
pub const MACOS_SERVICES: &[&str] = &[
    "com.apple.SystemConfiguration.configd",
    "com.apple.oahd",
    "com.apple.system.notification_center",
    "com.apple.system.opendirectoryd.libinfo",
    "com.apple.trustd",
    "com.apple.trustd.agent",
];
/// macOS: POSIX shared memory read.
pub const MACOS_SHM: &[&str] = &["apple.shm.notification_center"];

/// Linux: system code (read, exec); `/lib64` and `/lib32` may be absent.
pub const LINUX_CODE: &[&str] = &["/bin", "/lib", "/lib32", "/lib64", "/sbin", "/usr"];
/// Linux: system data (read).
pub const LINUX_DATA: &[&str] = &["/etc"];
/// Linux: devices read and written.
pub const LINUX_DEVICES_RW: &[&str] = &["/dev/null", "/dev/zero"];
/// Linux: devices read.
pub const LINUX_DEVICES_R: &[&str] = &["/dev/random", "/dev/urandom"];
/// Linux: terminal devices with `Tty::Inherit`.
pub const LINUX_TTY: &[&str] = &["/dev/pts", "/dev/tty"];

fn bytes(paths: &[&str], filter: fn(Vec<u8>) -> Filter) -> Vec<Filter> {
    paths
        .iter()
        .map(|p| filter(p.as_bytes().to_vec()))
        .collect()
}

fn strings(names: &[&str], filter: fn(String) -> Filter) -> Vec<Filter> {
    names.iter().map(|n| filter(n.to_string())).collect()
}

/// The SBPL allow rules of base V1 for a child with terminal mode `tty`.
pub fn macos_v1(tty: Tty) -> Vec<Rule> {
    let allow = |ops: &[&str], filters: Vec<Filter>| Rule::new(Effect::Allow, ops, filters);
    let mut rules = vec![
        allow(&["file-read*"], vec![Filter::Literal(b"/".to_vec())]),
        allow(
            &["file-read*", "process-exec*", "file-map-executable"],
            bytes(MACOS_CODE, Filter::Subpath),
        ),
        allow(&["file-read*"], bytes(MACOS_DATA, Filter::Subpath)),
        allow(
            &["file-read-metadata"],
            bytes(MACOS_METADATA, Filter::Literal),
        ),
        allow(
            &["file-read*", "file-write-data"],
            bytes(MACOS_DEVICES_RW, Filter::Literal),
        ),
        allow(&["file-read*"], bytes(MACOS_DEVICES_R, Filter::Literal)),
        allow(
            &["file-read*", "file-write-data"],
            vec![Filter::Subpath(b"/dev/fd".to_vec())],
        ),
        allow(&["sysctl-read"], vec![]),
        allow(
            &["mach-lookup"],
            strings(MACOS_SERVICES, Filter::GlobalName),
        ),
        allow(
            &["ipc-posix-shm-read*"],
            strings(MACOS_SHM, Filter::IpcPosixName),
        ),
    ];
    if tty == Tty::Inherit {
        rules.push(allow(
            &["file-read*", "file-write-data", "file-ioctl"],
            vec![
                Filter::Literal(b"/dev/tty".to_vec()),
                Filter::Regex("^/dev/ttys[0-9]+$".into()),
            ],
        ));
    }
    rules
}

fn path(p: &str) -> AbsPath {
    // The constants above are absolute and normal.
    AbsPath::new(p).unwrap_or_else(|_| AbsPath::root())
}

/// The Landlock rules of base V1 for a child with terminal mode `tty`,
/// limited to the rights `handled` covers.
pub fn linux_v1(tty: Tty, handled: AccessFs) -> Vec<LandlockRule> {
    let file = |access: AccessFs| access.intersect(AccessFs::FILE_RIGHTS).intersect(handled);
    let rw = file(AccessFs::READ_FILE.union(AccessFs::WRITE_FILE));
    let mut rules: Vec<LandlockRule> = LINUX_CODE
        .iter()
        .map(|p| LandlockRule {
            target: RuleTarget::PathIfExists(path(p)),
            access: rights(Access::Exec, handled),
        })
        .collect();
    rules.extend(LINUX_DATA.iter().map(|p| LandlockRule {
        target: RuleTarget::Path(path(p)),
        access: rights(Access::Read, handled),
    }));
    rules.extend(LINUX_DEVICES_RW.iter().map(|p| LandlockRule {
        target: RuleTarget::Path(path(p)),
        access: rw,
    }));
    rules.extend(LINUX_DEVICES_R.iter().map(|p| LandlockRule {
        target: RuleTarget::Path(path(p)),
        access: file(AccessFs::READ_FILE),
    }));
    if tty == Tty::Inherit {
        rules.extend(LINUX_TTY.iter().map(|p| {
            LandlockRule {
                target: RuleTarget::PathIfExists(path(p)),
                access: file(
                    AccessFs::READ_FILE
                        .union(AccessFs::WRITE_FILE)
                        .union(AccessFs::IOCTL_DEV),
                ),
            }
        }));
    }
    rules
}
