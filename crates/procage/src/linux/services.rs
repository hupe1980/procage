//! The socket hard-deny classes (`service-handoff`, `container-engines`) at
//! cage creation and at each spawn.
//!
//! Landlock cannot refuse one Unix socket inside a tree it allows, and
//! seccomp cannot read a `connect` path. So when a policy leaves the child a
//! Unix connect (`Network::All`, or `ipc.unix_sockets`), the parent looks
//! for the classes' sockets: tier T1 covers what it finds (and the classes'
//! directories as a whole), which is an approximation the caller accepts with
//! the spawn snapshot or by name; tier T2 cannot cover and reports a gap per
//! socket. An abstract bus is kept out with Landlock's abstract-socket scope
//! (ABI 6), or is a gap. Each spawn looks again: a socket found later is
//! covered (T1) or refuses the spawn (T2).

use std::collections::BTreeSet;
use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use procage_policy::linux::{AccessFs, RuleTarget, Scopes, SocketPaths};
use procage_policy::{
    AbsPath, CapabilityGap, Construct, Degradation, GapKind, LinuxPlan, Target, Tier,
};

use super::classes::Cover;

/// What the parent found of a socket class.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Found {
    /// An existing listed name (socket, directory, link or any other file)
    /// or the object it resolves to.
    Path(PathBuf),
    /// An existing class directory, and whether it holds a socket now. Tier
    /// T1 covers it either way, so a socket bound in it later is out of
    /// reach too; tier T2 reports it only when it holds one.
    Dir(PathBuf, bool),
    /// A listening abstract socket with a listed prefix (without the `@`).
    Abstract(String),
    /// The socket listing could not be read, so abstract buses are unknown.
    Unlisted,
}

/// One finding of one class.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct Finding {
    pub(crate) construct: Construct,
    pub(crate) found: Found,
}

/// The runtime directories: every readable directory under `/run/user`, the
/// caller's `XDG_RUNTIME_DIR` and `extra`, resolved, without duplicates.
pub(crate) fn runtime_dirs(extra: &[PathBuf]) -> Vec<PathBuf> {
    let mut out = Vec::new();
    if let Ok(entries) = std::fs::read_dir("/run/user") {
        out.extend(
            entries
                .flatten()
                .map(|e| e.path())
                .filter(|p| std::fs::read_dir(p).is_ok()),
        );
    }
    if let Some(dir) = std::env::var_os("XDG_RUNTIME_DIR").map(PathBuf::from)
        && dir.is_absolute()
    {
        out.push(dir);
    }
    out.extend(extra.iter().cloned());
    let mut out: Vec<PathBuf> = out
        .into_iter()
        .map(|p| std::fs::canonicalize(&p).unwrap_or(p))
        .filter(|p| p != Path::new("/"))
        .collect();
    out.sort();
    out.dedup();
    out
}

fn to_path(p: &AbsPath) -> PathBuf {
    PathBuf::from(OsStr::from_bytes(p.as_bytes()))
}

/// The name and, when it differs, the object it resolves to, if the name
/// exists in any form. A name that cannot be inspected (other than for not
/// existing) counts as existing: it may hide a socket.
fn existing(path: &Path) -> Vec<PathBuf> {
    if let Err(e) = std::fs::symlink_metadata(path)
        && e.kind() == std::io::ErrorKind::NotFound
    {
        return Vec::new();
    }
    let mut out = vec![path.to_path_buf()];
    if let Ok(real) = std::fs::canonicalize(path)
        && real != path
    {
        out.push(real);
    }
    out
}

/// Whether `dir` holds a socket. A directory that cannot be listed may hide
/// one, so it counts as holding one.
fn holds_a_socket(dir: &Path) -> bool {
    use std::os::unix::fs::FileTypeExt;
    match std::fs::read_dir(dir) {
        Ok(entries) => entries
            .flatten()
            .any(|e| e.file_type().map_or(true, |t| t.is_socket())),
        Err(_) => true,
    }
}

/// The listening abstract sockets in this network namespace, from
/// `/proc/net/unix` (names without the leading `@`).
fn abstract_names(listing: &str) -> Vec<String> {
    listing
        .lines()
        .skip(1)
        .filter_map(|line| {
            // `Num RefCount Protocol Flags Type St Inode Path`. A name holding
            // a newline continues on the next line, which has no seven fields
            // before it and is skipped; the start of the name is kept.
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() < 8
                || !fields[1..7]
                    .iter()
                    .all(|f| f.chars().all(|c| c.is_ascii_hexdigit()))
            {
                return None;
            }
            let name = fields[7..].join(" ");
            name.strip_prefix('@')
                .filter(|n| !n.is_empty())
                .map(str::to_string)
        })
        .collect()
}

/// Everything of `sockets` that exists now. `abstract_visible`: the child
/// shares the caller's network namespace, so the caller's abstract sockets
/// are its own.
pub(crate) fn find(
    sockets: &[SocketPaths],
    runtime: &[PathBuf],
    abstract_visible: bool,
) -> Vec<Finding> {
    let listing = abstract_visible.then(|| std::fs::read_to_string("/proc/net/unix"));
    let mut out = BTreeSet::new();
    for class in sockets {
        let construct = Construct::of_class(class.class);
        let mut push = |found| {
            out.insert(Finding { construct, found });
        };
        let files = class.system.iter().map(to_path).chain(
            runtime
                .iter()
                .flat_map(|dir| class.runtime.iter().map(move |rel| dir.join(rel))),
        );
        for name in files {
            for p in existing(&name) {
                push(Found::Path(p));
            }
        }
        let dirs = class.system_dirs.iter().map(to_path).chain(
            runtime
                .iter()
                .flat_map(|dir| class.runtime_dirs.iter().map(move |rel| dir.join(rel))),
        );
        for name in dirs {
            for p in existing(&name) {
                if p.is_dir() {
                    let socket = holds_a_socket(&p);
                    push(Found::Dir(p, socket));
                } else {
                    // Something else at a directory's name: cover it too.
                    push(Found::Path(p));
                }
            }
        }
        if class.abstract_prefixes.is_empty() {
            continue;
        }
        match &listing {
            None => {}
            Some(Err(_)) => push(Found::Unlisted),
            Some(Ok(text)) => {
                for name in abstract_names(text) {
                    if class
                        .abstract_prefixes
                        .iter()
                        .any(|prefix| name.starts_with(prefix.as_str()))
                    {
                        push(Found::Abstract(name));
                    }
                }
            }
        }
    }
    out.into_iter().collect()
}

/// What a cage does with `findings`.
#[derive(Debug, Default)]
pub(crate) struct Outcome {
    /// Covers for tier T1.
    pub(crate) covers: Vec<(PathBuf, Cover)>,
    /// Approximations the caller accepted (T1).
    pub(crate) degradations: Vec<Degradation>,
    /// The abstract-socket scope is needed.
    pub(crate) scope: bool,
    /// What cannot be enforced, or was not accepted.
    pub(crate) gaps: Vec<CapabilityGap>,
}

/// The note of the T1 approximation.
const SNAPSHOT: &str = "bus, service-manager and engine sockets that exist at spawn are covered, and \
    the classes' directories as a whole; a socket bound later elsewhere is not";

/// Decides `findings` for `plan`: covers and accepted approximations on T1,
/// gaps on T2, the abstract scope where the ABI has it. `allowed`: the
/// constructs the caller accepts as approximations.
pub(crate) fn decide(
    plan: &LinuxPlan,
    findings: &[Finding],
    allowed: &BTreeSet<Construct>,
) -> Outcome {
    let target = Target::Linux {
        tier: plan.tier,
        landlock_abi: plan.landlock_abi,
    };
    let mut out = Outcome::default();
    let gap = |construct, kind, subject: String| CapabilityGap {
        construct,
        target,
        kind,
        subject: Some(subject),
    };
    // From Landlock ABI 9 without `Network::All`, a pathname socket no
    // Unix-socket rule reaches cannot be connected to; abstract ones are
    // scoped. Only a socket under an allowed path needs a cover.
    let resolve = plan.landlock.handled_fs.contains(AccessFs::RESOLVE_UNIX);
    let reached = |p: &Path| {
        plan.landlock.rules.iter().any(|r| {
            r.access.contains(AccessFs::RESOLVE_UNIX)
                && matches!(&r.target, RuleTarget::Path(a) | RuleTarget::PathIfExists(a) if p.starts_with(to_path(a)))
        })
    };
    for f in findings {
        match &f.found {
            Found::Path(p) | Found::Dir(p, _) if resolve && !reached(p) => {}
            Found::Unlisted if resolve => {}
            Found::Dir(_, false) if plan.tier == Tier::T2 => {}
            Found::Path(p) | Found::Dir(p, _) => match plan.tier {
                Tier::T1 if allowed.contains(&f.construct) => {
                    out.covers.push((p.clone(), Cover::Hide));
                    if !out.degradations.iter().any(|d| d.construct == f.construct) {
                        out.degradations.push(Degradation {
                            construct: f.construct,
                            target,
                            note: SNAPSHOT,
                        });
                    }
                }
                Tier::T1 => out.gaps.push(gap(
                    f.construct,
                    GapKind::Approximation,
                    p.display().to_string(),
                )),
                Tier::T2 => out.gaps.push(gap(
                    f.construct,
                    GapKind::Unsupported,
                    p.display().to_string(),
                )),
            },
            Found::Abstract(name) if plan.landlock_abi >= 6 => {
                let _ = name;
                out.scope = true;
            }
            Found::Abstract(name) => {
                out.gaps
                    .push(gap(f.construct, GapKind::Unsupported, format!("@{name}")))
            }
            Found::Unlisted => out.gaps.push(gap(
                f.construct,
                GapKind::Unsupported,
                "/proc/net/unix (unreadable)".into(),
            )),
        }
    }
    out.gaps.sort();
    out.gaps.dedup();
    out.degradations.sort();
    out
}

/// Whether `plan` scopes abstract sockets.
pub(crate) fn scoped(plan: &LinuxPlan) -> bool {
    plan.landlock.scopes.0 & Scopes::ABSTRACT_UNIX_SOCKET.0 != 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn abstract_names_are_parsed_field_by_field() {
        let listing = "Num       RefCount Protocol Flags    Type St Inode Path\n\
            0000000000000000: 00000002 00000000 00010000 0001 01 12345 @/tmp/dbus-AbCd\n\
            0000000000000000: 00000002 00000000 00010000 0001 01 12346 /run/user/1000/bus\n\
            0000000000000000: 00000002 00000000 00010000 0001 01 12347 @/tmp/dbus-with\n\
            newline @/tmp/dbus-forged\n\
            0000000000000000: 00000002 00000000 00010000 0001 01 12348 @/tmp/.X11-unix/X0\n";
        assert_eq!(
            abstract_names(listing),
            ["/tmp/dbus-AbCd", "/tmp/dbus-with", "/tmp/.X11-unix/X0"]
        );
    }

    /// Directories passed in are added to the ones found, never replace them.
    #[test]
    fn extra_runtime_dirs_add() {
        let dir = std::env::temp_dir().join(format!("procage-rt-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let found = runtime_dirs(&[]);
        let with = runtime_dirs(std::slice::from_ref(&dir));
        assert!(
            with.contains(&std::fs::canonicalize(&dir).unwrap()),
            "{with:?}"
        );
        assert!(found.iter().all(|d| with.contains(d)), "{found:?} {with:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The system lists are found where they exist: the same code reads a
    /// system path and a runtime path.
    #[test]
    fn system_paths_are_found() {
        use std::os::unix::net::UnixListener;
        let dir = std::env::temp_dir().join(format!("procage-sys-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let real = std::fs::canonicalize(&dir).unwrap();
        let _bus = UnixListener::bind(real.join("system_bus_socket")).unwrap();
        let mut sockets = procage_policy::presets::linux_socket_paths(
            procage_policy::HardDenyClass::ServiceHandoff,
        )
        .unwrap();
        sockets.system =
            vec![AbsPath::new(real.join("system_bus_socket").to_str().unwrap()).unwrap()];
        let found = find(&[sockets], &[], false);
        assert!(
            found
                .iter()
                .any(|f| f.found == Found::Path(real.join("system_bus_socket"))),
            "{found:?}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// What cannot be inspected is never taken as absent: an unreadable
    /// class directory holds a socket, an unreadable listing is a gap.
    #[test]
    fn what_cannot_be_inspected_counts() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("procage-closed-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o000)).unwrap();
        let unreadable = std::fs::read_dir(&dir).is_err();
        if unreadable {
            assert!(holds_a_socket(&dir));
        }
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
        let mut plan = procage_policy::lower(
            &{
                let mut p = procage_policy::Policy::default();
                p.net = procage_policy::Network::All;
                p
            },
            Target::Linux {
                tier: Tier::T2,
                landlock_abi: 8,
            },
            &procage_policy::LowerOptions::default(),
        )
        .map(|plan| match plan {
            procage_policy::Plan::Linux(p) => p,
            _ => unreachable!(),
        })
        .unwrap();
        plan.tier = Tier::T2;
        let unlisted = [Finding {
            construct: Construct::HdServiceHandoff,
            found: Found::Unlisted,
        }];
        let outcome = decide(&plan, &unlisted, &BTreeSet::new());
        assert_eq!(outcome.gaps.len(), 1, "{:?}", outcome.gaps);
        assert_eq!(outcome.gaps[0].kind, GapKind::Unsupported);
    }

    /// From Landlock ABI 9 without `Network::All`, only a socket under an
    /// allowed Unix-socket path needs a cover; at ABI 8 every one does.
    #[test]
    fn landlock_keeps_other_sockets_out_from_abi_9() {
        let mut policy = procage_policy::Policy::default();
        policy.ipc.unix_sockets = vec![AbsPath::new("/work").unwrap()];
        let plan = |tier, abi| match procage_policy::lower(
            &policy,
            Target::Linux {
                tier,
                landlock_abi: abi,
            },
            &procage_policy::LowerOptions::default().accept_spawn_snapshot(),
        ) {
            Ok(procage_policy::Plan::Linux(p)) => p,
            other => panic!("{other:?}"),
        };
        let bus = Finding {
            construct: Construct::HdServiceHandoff,
            found: Found::Path(PathBuf::from("/run/dbus/system_bus_socket")),
        };
        let inside = Finding {
            construct: Construct::HdContainerEngines,
            found: Found::Path(PathBuf::from("/work/docker.sock")),
        };
        let unlisted = Finding {
            construct: Construct::HdServiceHandoff,
            found: Found::Unlisted,
        };
        let findings = [bus, inside, unlisted];
        for tier in [Tier::T1, Tier::T2] {
            let at9 = decide(&plan(tier, 9), &findings, &BTreeSet::new());
            let subjects: Vec<_> = at9.gaps.iter().map(|g| g.subject.clone()).collect();
            assert_eq!(subjects, [Some("/work/docker.sock".into())], "{tier}");
        }
        let at8 = decide(&plan(Tier::T1, 8), &findings, &BTreeSet::new());
        assert_eq!(at8.gaps.len(), 3, "{:?}", at8.gaps);
    }

    #[test]
    fn listed_names_are_found_in_any_form() {
        use std::os::unix::net::UnixListener;
        let dir = std::env::temp_dir().join(format!("procage-services-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("systemd")).unwrap();
        let _bus = UnixListener::bind(dir.join("elsewhere.sock")).unwrap();
        std::os::unix::fs::symlink(dir.join("elsewhere.sock"), dir.join("bus")).unwrap();
        let _private = UnixListener::bind(dir.join("systemd/private")).unwrap();
        let sockets = [procage_policy::presets::linux_socket_paths(
            procage_policy::HardDenyClass::ServiceHandoff,
        )
        .unwrap()];
        let real = std::fs::canonicalize(&dir).unwrap();
        let found = find(&sockets, std::slice::from_ref(&real), false);
        let paths: Vec<&Found> = found.iter().map(|f| &f.found).collect();
        assert!(paths.contains(&&Found::Path(real.join("bus"))), "{found:?}");
        assert!(
            paths.contains(&&Found::Path(real.join("elsewhere.sock"))),
            "{found:?}"
        );
        assert!(
            paths.contains(&&Found::Path(real.join("systemd/private"))),
            "{found:?}"
        );
        assert!(
            paths.contains(&&Found::Dir(real.join("systemd"), true)),
            "{found:?}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
