//! The base profile: what ordinary programs need to start, and nothing the
//! user cares about.
//!
//! A policy opts in with [`Base::V1`](crate::Base::V1) or
//! [`Base::V2`](crate::Base::V2). Each version is frozen; a loosening needs a
//! new version. Use V2 for developer tools (compilers, `git`, interpreters,
//! Homebrew); V1 stays as it was.
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
//! **macOS V2** (measured on macOS 26.6.2 with Xcode 27.2 and Homebrew, on
//! 2026-10-31, by running developer tools in a cage and reading every
//! sandbox denial): V1 plus
//!
//! | Entry | Why |
//! |---|---|
//! | read, exec, map `/Library/Developer/CommandLineTools` and `/Applications/Xcode*.app/Contents` | the developer tools behind Apple's shims (`git`, `clang`, `make`, `python3`, `swift`, `xcrun`) |
//! | read `/private/var/db/xcode_select_link` | `xcode-select`'s choice of developer directory |
//! | read `/Library/Preferences/com.apple.dt.Xcode.plist` | the Xcode license state (without it every shim reports an unaccepted license) |
//! | read `/Library/Ruby`, `/Library/Perl` | the system Ruby's gems and Perl's module paths |
//! | read, exec, map `bin`, `sbin`, `lib`, `libexec`, `opt`, `Cellar`, `Caskroom`, `share`, `include`, `Frameworks` under `/opt/homebrew` and `/usr/local` | Homebrew's programs and libraries (not its `etc` or `var`, which can hold configuration and data) |
//! | read OpenSSL's `openssl.cnf`, `cert.pem` and `certs` and `ca-certificates/cert.pem` under `/opt/homebrew/etc` and `/usr/local/etc` | Homebrew's OpenSSL (used by `node`, `npm`) refuses to start without its configuration; these files are public |
//! | read `/Library/Preferences/.GlobalPreferences.plist`, `/dev/autofs_nowait` | system-wide locale preferences; CoreFoundation's automount guard |
//! | read `.CFUserTextEncoding` in each home | CoreFoundation's text encoding (a few bytes such as `0x1F5:0:0`) |
//! | metadata of `/Users`, each home directory itself, `/Applications`, the Xcode bundles, `/Library/Developer`, `/opt`, `/opt/homebrew`, `/usr/local`, their `etc`, `/private/var/db`, the per-user directories under `/private/var/folders` | path lookup (`stat` of `$HOME` works; listing it does not) |
//! | metadata of every directory on the way to the policy's own paths | resolving a granted path to its real path (`git` refuses a workspace whose parents it cannot examine) |
//!
//! Deliberately left out, although tools look them up:
//!
//! - `com.apple.bsd.dirhelper` and `com.apple.system.opendirectoryd.membership`:
//!   with either, libSystem reports the user's shared per-user temporary
//!   directory, and `mktemp` and `xcrun` write there (xcrun's tool cache
//!   there is read later by unsandboxed tools). Without them it falls back
//!   to `$TMPDIR`, the run's own directory;
//! - logging (`com.apple.logd`, `com.apple.diagnosticd`), analytics, the
//!   DTrace helper ioctl (a kernel parser), other processes' information,
//!   LaunchServices and the Command Line Tools installer (they act outside
//!   the sandbox), the user's preferences and caches under `~/Library`, and
//!   the terminal unless `Tty::Inherit`.
//!
//! **Running developer tools** in a cage:
//!
//! - give the child a `TMPDIR` (the `tmpdir` grant, or a writable
//!   directory of your own). Apple's shims cache tool lookups there: the
//!   first call in a fresh `TMPDIR` takes about a second, later calls run at
//!   native speed, so reuse one writable `TMPDIR` across a session's
//!   commands when speed matters;
//! - `git` stops when it cannot read `~/.gitconfig` (macOS reports
//!   "operation not permitted", which git treats as fatal): set
//!   `GIT_CONFIG_GLOBAL` to a file the policy lets it read (or
//!   `/dev/null`), or point `HOME` somewhere readable;
//! - `git init` and `git clone` write hooks and config, which the
//!   trust-handoff class refuses: create repositories outside the cage, or
//!   waive the class for that run;
//! - accept the Xcode license once outside the cage (`xcodebuild -license`);
//! - Unix socket addresses hold at most 104 bytes, so keep socket paths
//!   short.
//!
//! **Linux**: read and exec for `/usr`, `/bin`, `/sbin`, `/lib`, `/lib64`,
//! `/lib32`; read for `/etc`; read/write `/dev/null`, `/dev/zero`; read
//! `/dev/random`, `/dev/urandom`; with `Tty::Inherit`, read/write `/dev/tty`
//! and `/dev/pts`. Paths a host lacks are skipped. This content is
//! expressed in the plan now and verified with Linux spawning. Version 2 is
//! the same on Linux: `git`, `python3`, `cc`, `make`, `perl`, `curl`,
//! `cargo` and `rustc` run with it when `TMPDIR` (the `tmpdir` grant) and the
//! toolchain's variables (`RUSTUP_HOME`, `CARGO_HOME`) are set.

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

/// macOS V2: developer-tool and package-manager code (read, exec, map),
/// added to V1.
pub const MACOS_V2_CODE: &[&str] = &[
    "/Library/Developer/CommandLineTools",
    "/opt/homebrew/Caskroom",
    "/opt/homebrew/Cellar",
    "/opt/homebrew/Frameworks",
    "/opt/homebrew/bin",
    "/opt/homebrew/include",
    "/opt/homebrew/lib",
    "/opt/homebrew/libexec",
    "/opt/homebrew/opt",
    "/opt/homebrew/sbin",
    "/opt/homebrew/share",
    "/usr/local/Cellar",
    "/usr/local/Frameworks",
    "/usr/local/bin",
    "/usr/local/include",
    "/usr/local/lib",
    "/usr/local/libexec",
    "/usr/local/opt",
    "/usr/local/sbin",
    "/usr/local/share",
];
/// macOS V2: Xcode bundles (any name starting with `Xcode`), code.
pub const MACOS_V2_XCODE: &str = "^/Applications/Xcode[^/]*\\.app/Contents/";
/// macOS V2: data directories read, added to V1.
pub const MACOS_V2_DATA: &[&str] = &["/Library/Perl", "/Library/Ruby"];
/// macOS V2: single files read, added to V1.
pub const MACOS_V2_FILES: &[&str] = &[
    "/Library/Preferences/.GlobalPreferences.plist",
    "/Library/Preferences/com.apple.dt.Xcode.plist",
    "/dev/autofs_nowait",
    "/private/var/db/xcode_select_link",
];
/// macOS V2: OpenSSL's configuration and CA bundle from Homebrew (public
/// data; not its `private` directory).
pub const MACOS_V2_OPENSSL: &str = "^/(opt/homebrew|usr/local)/etc/(openssl@[0-9.]+/(openssl\\.cnf|cert\\.pem|certs(/.*)?)|ca-certificates/cert\\.pem)$";
/// macOS V2: CoreFoundation's text-encoding setting in each home (a few
/// bytes, such as `0x1F5:0:0`).
pub const MACOS_V2_HOME_DATA: &str = "^/Users/[^/]+/\\.CFUserTextEncoding$";
/// macOS V2: metadata for path lookup, added to V1.
pub const MACOS_V2_METADATA: &[&str] = &[
    "/Applications",
    "/Library/Developer",
    "/Users",
    "/opt",
    "/opt/homebrew",
    "/opt/homebrew/etc",
    "/private/var/db",
    "/usr/local",
    "/usr/local/etc",
];
/// macOS V2: each home directory itself (metadata only) and the Xcode
/// bundles' top directories.
pub const MACOS_V2_METADATA_REGEX: &[&str] = &[
    "^/Users/[^/]+$",
    "^/Applications/Xcode[^/]*\\.app(/Contents)?$",
];

/// macOS V2: the per-user directories on the way to private temporary
/// directories (metadata only).
pub const MACOS_V2_FOLDERS: &str = "^/private/var/folders(/[^/]+){0,3}$";

/// The metadata rule of base V2 for the directories on the way to `paths`
/// (the policy's own paths), so that resolving a granted path to its real
/// path works (`git`, `realpath`); `None` when there are none beyond `/`.
pub fn macos_v2_ancestors<'a>(paths: impl IntoIterator<Item = &'a AbsPath>) -> Option<Rule> {
    let mut ancestors: Vec<Vec<u8>> = paths
        .into_iter()
        .flat_map(AbsPath::ancestors)
        .filter(|a| !a.is_root())
        .map(AbsPath::into_bytes)
        .collect();
    ancestors.sort();
    ancestors.dedup();
    if ancestors.is_empty() {
        return None;
    }
    Some(Rule::new(
        Effect::Allow,
        &["file-read-metadata"],
        ancestors.into_iter().map(Filter::Literal).collect(),
    ))
}

/// The SBPL allow rules of base V2: V1 plus developer tools.
pub fn macos_v2(tty: Tty) -> Vec<Rule> {
    let allow = |ops: &[&str], filters: Vec<Filter>| Rule::new(Effect::Allow, ops, filters);
    let mut rules = macos_v1(tty);
    let mut code = bytes(MACOS_V2_CODE, Filter::Subpath);
    code.push(Filter::Regex(MACOS_V2_XCODE.into()));
    rules.push(allow(
        &["file-read*", "process-exec*", "file-map-executable"],
        code,
    ));
    let mut data = bytes(MACOS_V2_DATA, Filter::Subpath);
    data.extend(bytes(MACOS_V2_FILES, Filter::Literal));
    data.push(Filter::Regex(MACOS_V2_HOME_DATA.into()));
    data.push(Filter::Regex(MACOS_V2_OPENSSL.into()));
    rules.push(allow(&["file-read*"], data));
    let mut metadata = bytes(MACOS_V2_METADATA, Filter::Literal);
    metadata.push(Filter::Regex(MACOS_V2_FOLDERS.into()));
    metadata.extend(
        MACOS_V2_METADATA_REGEX
            .iter()
            .map(|r| Filter::Regex((*r).into())),
    );
    rules.push(allow(&["file-read-metadata"], metadata));
    rules
}

/// The Mach services every program asks for that base V3 denies quietly:
/// the logging services, `dirhelper` (left out since V2: each run has its
/// own `TMPDIR`) and group membership lookups. None is needed (measured on
/// macOS 26.6.2 with the developer-tool set of V2).
pub const MACOS_V3_QUIET_SERVICES: &[&str] = &[
    "com.apple.bsd.dirhelper",
    "com.apple.diagnosticd",
    "com.apple.logd",
    "com.apple.system.opendirectoryd.membership",
];

/// The quiet denies of base V3, emitted before every allow so that a policy
/// that grants one of these targets (`Tty::Inherit` and `/dev/tty`) still
/// gets it: the Mach services above, the dyld DTrace helper's ioctl, and
/// `/dev/tty`, which shells probe.
pub fn macos_v3_quiet() -> Vec<Rule> {
    let deny = |ops: &[&str], filters: Vec<Filter>| Rule::new(Effect::Deny, ops, filters).quietly();
    alloc::vec![
        deny(
            &["mach-lookup"],
            MACOS_V3_QUIET_SERVICES
                .iter()
                .map(|n| Filter::GlobalName((*n).into()))
                .collect(),
        ),
        deny(
            &["file-ioctl"],
            alloc::vec![Filter::Literal(b"/dev/dtracehelper".to_vec())]
        ),
        deny(
            &["file-read*", "file-write*"],
            alloc::vec![Filter::Literal(b"/dev/tty".to_vec())],
        ),
    ]
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

/// The Landlock rules of base V2 on Linux: the same as V1.
pub fn linux_v2(tty: Tty, handled: AccessFs) -> Vec<LandlockRule> {
    linux_v1(tty, handled)
}
