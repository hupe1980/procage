//! Preparing a spawn in the parent: the Landlock ruleset with its rule
//! descriptors, the T1 mounts and id maps, and decoding a failed step.

use std::collections::BTreeMap;
use std::ffi::CString;
use std::io;
use std::os::fd::OwnedFd;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use procage_policy::LinuxPlan;
use procage_policy::linux::{AccessFs, Mount, RuleTarget};

use super::classes::Cover;
use super::sys::{self, ChildMount};
use super::{SpawnError, Step, Unsupported};

fn c_path(path: &Path) -> Result<CString, SpawnError> {
    CString::new(path.as_os_str().as_bytes()).map_err(|_| SpawnError::Path {
        path: path.to_string_lossy().into_owned(),
        error: io::Error::from_raw_os_error(libc::EINVAL),
    })
}

fn path_error(path: &Path, errno: i32) -> SpawnError {
    SpawnError::Path {
        path: path.to_string_lossy().into_owned(),
        error: io::Error::from_raw_os_error(errno),
    }
}

/// The path a rule applies to and whether it may be missing; `None` for a
/// grant without a binding in this spawn (it gives nothing).
fn rule_path(
    target: &RuleTarget,
    grants: &BTreeMap<String, PathBuf>,
) -> Result<Option<(PathBuf, bool)>, SpawnError> {
    let from_bytes = |b: &[u8]| PathBuf::from(std::ffi::OsStr::from_bytes(b));
    match target {
        RuleTarget::Path(p) => Ok(Some((from_bytes(p.as_bytes()), false))),
        RuleTarget::PathIfExists(p) => Ok(Some((from_bytes(p.as_bytes()), true))),
        RuleTarget::Grant(name) => Ok(grants.get(name.as_str()).map(|p| (p.clone(), false))),
        // Resolved per spawn by `ruleset` (the program allowance).
        RuleTarget::Program => Ok(None),
        // The lowering reports glob rules as gaps on Linux.
        RuleTarget::ExpandGlob(_) => Err(SpawnError::Unsupported(Unsupported::Setting {
            setting: "glob rules on Linux",
        })),
    }
}

/// The paths the plan's rules (and the bound grants) let the child write.
pub(super) fn writable(
    plan: &LinuxPlan,
    grants: &BTreeMap<String, PathBuf>,
) -> Result<Vec<PathBuf>, SpawnError> {
    let writes = AccessFs::WRITE_FILE.union(AccessFs::MAKE_REG);
    let mut out = Vec::new();
    for rule in &plan.landlock.rules {
        if rule.access.intersect(writes) == AccessFs::NONE {
            continue;
        }
        let Some((path, _)) = rule_path(&rule.target, grants)? else {
            continue;
        };
        if path.is_dir() {
            out.push(path);
        }
    }
    out.sort();
    out.dedup();
    Ok(out)
}

/// Every path a rule gives access to, and whether that access writes.
pub(super) fn rule_paths(plan: &LinuxPlan) -> Vec<(PathBuf, bool)> {
    let writes = AccessFs::WRITE_FILE.union(AccessFs::MAKE_REG);
    plan.landlock
        .rules
        .iter()
        .filter_map(|rule| match &rule.target {
            RuleTarget::Path(p) | RuleTarget::PathIfExists(p) => Some((
                PathBuf::from(std::ffi::OsStr::from_bytes(p.as_bytes())),
                rule.access.intersect(writes) != AccessFs::NONE,
            )),
            _ => None,
        })
        .collect()
}

/// The Landlock ruleset for `plan`, on descriptors opened for this spawn,
/// with `grants` bound and, with `Tty::NewPty`, the run's `terminal` device.
///
/// `hidden` (tier T2) are paths kept out piecewise: a rule at or under one
/// is dropped, and a rule above one is replaced by rules for every entry on
/// the way except the hidden path, as listed now (symbolic links are
/// skipped: they could lead into the hidden path). At most `limit` entries
/// are visited.
///
/// `program` is the spawn's program allowance (`Exec::Never`,
/// `Exec::Program`): the program and its ELF interpreter, each opened now,
/// so the rule stays with the file that was resolved.
pub(super) fn ruleset(
    plan: &LinuxPlan,
    grants: &BTreeMap<String, PathBuf>,
    terminal: Option<&Path>,
    hidden: &[PathBuf],
    limit: usize,
    program: Option<&crate::unix::Allowance>,
) -> Result<OwnedFd, SpawnError> {
    let ll = &plan.landlock;
    let ruleset = sys::landlock_ruleset(ll.handled_fs.0, ll.handled_net.0, ll.scopes.0)
        .map_err(|e| SpawnError::Io(io::Error::from_raw_os_error(e)))?;
    let reading = AccessFs::READ_FILE
        .union(AccessFs::READ_DIR)
        .union(AccessFs::EXECUTE)
        .union(AccessFs::RESOLVE_UNIX);
    let mut budget = limit;
    for rule in &ll.rules {
        if rule.target == RuleTarget::Program {
            let Some(allowance) = program else { continue };
            let files = [Some(&allowance.program), allowance.interpreter.as_ref()];
            for file in files.into_iter().flatten() {
                if !hidden.iter().any(|h| file.starts_with(h)) {
                    allow_path(&ruleset, file, rule.access, false)?;
                }
            }
            continue;
        }
        let Some((path, optional)) = rule_path(&rule.target, grants)? else {
            continue;
        };
        if hidden.iter().any(|h| path.starts_with(h)) {
            continue;
        }
        let around: Vec<&PathBuf> = hidden.iter().filter(|h| h.starts_with(&path)).collect();
        if around.is_empty() {
            allow_path(&ruleset, &path, rule.access, optional)?;
            continue;
        }
        if rule.access.without(reading) != AccessFs::NONE {
            // The lowering refuses write rules around a hidden path; a grant
            // is bound only now.
            return Err(match &rule.target {
                RuleTarget::Grant(name) => SpawnError::Grant(super::GrantError::Covers {
                    name: name.as_str().to_owned(),
                    hidden: around[0].clone(),
                }),
                _ => path_error(&path, libc::EPERM),
            });
        }
        let mut pieces = Vec::new();
        piecewise(&path, &around, &mut pieces, &mut budget, limit)?;
        for piece in pieces {
            allow_path(&ruleset, &piece, rule.access, true)?;
        }
    }
    // The run's own terminal device (`Tty::NewPty`), and no other.
    if let Some(device) = terminal {
        let access = procage_policy::linux::TERMINAL_ACCESS
            .intersect(AccessFs::FILE_RIGHTS)
            .intersect(ll.handled_fs);
        allow_path(&ruleset, device, access, false)?;
    }
    for rule in &ll.net_rules {
        sys::landlock_allow_port(&ruleset, rule.port.get(), rule.access.0)
            .map_err(|e| SpawnError::Io(io::Error::from_raw_os_error(e)))?;
    }
    Ok(ruleset)
}

/// Adds a rule for `path` with `access` (file rights only on a file).
fn allow_path(
    ruleset: &OwnedFd,
    path: &Path,
    access: AccessFs,
    optional: bool,
) -> Result<(), SpawnError> {
    let (fd, dir) = match sys::open_path(&c_path(path)?) {
        Ok(opened) => opened,
        Err(libc::ENOENT) if optional => return Ok(()),
        Err(e) => return Err(path_error(path, e)),
    };
    // Rights that only apply to directories are refused on a file.
    let access = if dir {
        access
    } else {
        access.intersect(AccessFs::FILE_RIGHTS)
    };
    if access == AccessFs::NONE {
        return Ok(());
    }
    sys::landlock_allow_path(ruleset, &fd, access.0).map_err(|e| path_error(path, e))
}

/// The pieces of `dir` that hold no hidden path: `dir` itself when none is
/// below it, else the pieces of each entry, skipping the hidden paths and
/// symbolic links.
fn piecewise(
    dir: &Path,
    hidden: &[&PathBuf],
    out: &mut Vec<PathBuf>,
    budget: &mut usize,
    limit: usize,
) -> Result<(), SpawnError> {
    if hidden.iter().any(|h| h.as_path() == dir) {
        return Ok(());
    }
    if !hidden.iter().any(|h| h.starts_with(dir)) {
        out.push(dir.to_path_buf());
        return Ok(());
    }
    // A directory that cannot be listed gives nothing below it.
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Ok(());
    };
    for entry in entries.flatten() {
        if *budget == 0 {
            return Err(SpawnError::Walk {
                root: dir.to_path_buf(),
                limit,
            });
        }
        *budget -= 1;
        if entry.file_type().is_ok_and(|t| !t.is_symlink()) {
            piecewise(&entry.path(), hidden, out, budget, limit)?;
        }
    }
    Ok(())
}

/// The pathname sockets bound in this network namespace (from
/// `/proc/net/unix`) that exist outside `allowed` and outside `masked`:
/// masked at spawn on tier T1, so the child cannot reach them.
pub(super) fn foreign_sockets(
    allowed: &[PathBuf],
    masked: &[PathBuf],
) -> Result<Vec<PathBuf>, SpawnError> {
    use std::os::unix::fs::FileTypeExt;
    let listing = Path::new("/proc/net/unix");
    let text = std::fs::read_to_string(listing)
        .map_err(|e| path_error(listing, e.raw_os_error().unwrap_or(libc::EIO)))?;
    let mut out: Vec<PathBuf> = text
        .lines()
        .skip(1)
        .filter_map(|line| {
            // `Num RefCount Protocol Flags Type St Inode Path`; abstract
            // names start with `@`, unbound sockets have no path.
            let path = line
                .split_whitespace()
                .skip(7)
                .collect::<Vec<_>>()
                .join(" ");
            path.starts_with('/').then(|| PathBuf::from(path))
        })
        .filter_map(|p| {
            // The listing shows the path as bound, which may pass through a
            // symbolic link; `allowed` is resolved, and so is the cover.
            let real = std::fs::canonicalize(&p).ok()?;
            (std::fs::symlink_metadata(&real).is_ok_and(|m| m.file_type().is_socket())
                && !allowed.iter().any(|a| real.starts_with(a))
                && !masked
                    .iter()
                    .any(|m| p.starts_with(m) || real.starts_with(m)))
            .then_some(real)
        })
        .collect();
    out.sort();
    out.dedup();
    Ok(out)
}

fn depth(path: &Path) -> usize {
    path.components().count()
}

/// A planned mount path and the identity of the object it names.
struct Planned {
    path: PathBuf,
    c: CString,
    id: sys::Identity,
}

/// The first symbolic link on the way to `path`, if any.
fn link_on(path: &Path) -> Option<PathBuf> {
    let mut at = PathBuf::from("/");
    for component in path.components().skip(1) {
        at.push(component);
        match std::fs::symlink_metadata(&at) {
            Ok(meta) if meta.file_type().is_symlink() => return Some(at),
            Ok(_) => {}
            Err(_) => return None,
        }
    }
    None
}

/// A mount path, canonical as the parent resolves it now (its own links
/// followed), with the identity of the object it names. The child opens
/// this canonical path without following links, so a link or rename that
/// appears after this point refuses the spawn.
fn planned(path: &Path) -> Result<Planned, SpawnError> {
    let real = std::fs::canonicalize(path)
        .map_err(|e| path_error(path, e.raw_os_error().unwrap_or(libc::EIO)))?;
    let c = c_path(&real)?;
    let id = sys::identity(&c).map_err(|e| path_error(&real, e))?;
    Ok(Planned { path: real, c, id })
}

const SEALED: u64 = sys::MOUNT_ATTR_RDONLY
    | sys::MOUNT_ATTR_NOSUID
    | sys::MOUNT_ATTR_NODEV
    | sys::MOUNT_ATTR_NOEXEC;

/// A bind of `p` over itself with `attrs`.
fn self_bind(p: &Planned, attrs: u64) -> ChildMount {
    ChildMount::Bind {
        source: p.c.clone(),
        source_id: p.id,
        target: p.c.clone(),
        target_id: p.id,
        attrs,
        optional: None,
    }
}

fn read_only(p: &Planned) -> ChildMount {
    self_bind(p, sys::MOUNT_ATTR_RDONLY)
}

fn pin(p: &Planned) -> ChildMount {
    self_bind(p, 0)
}

fn hide(p: &Planned) -> Result<ChildMount, SpawnError> {
    let meta = std::fs::metadata(&p.path).map_err(|_| path_error(&p.path, libc::ENOENT))?;
    if meta.is_dir() {
        return Ok(ChildMount::Tmpfs {
            target: p.c.clone(),
            target_id: p.id,
            attrs: SEALED,
            mode: c"000".into(),
            optional: None,
        });
    }
    let null = planned(Path::new("/dev/null"))?;
    Ok(ChildMount::Bind {
        source: null.c,
        source_id: null.id,
        target: p.c.clone(),
        target_id: p.id,
        attrs: SEALED,
        optional: None,
    })
}

/// The objects a cage's declared mounts name, found when the cage is made:
/// canonical paths and their identities. Spawns mount only these objects,
/// so a link or rename made later, even while the parent plans a spawn,
/// refuses it.
pub(super) type Declared = BTreeMap<PathBuf, sys::Identity>;

/// Rewrites the plan's declared mount paths to their canonical form and
/// records the object each names. A path that does not exist yet keeps its
/// spelling and has no identity: its spawns fail as before.
pub(super) fn declare(plan: &mut LinuxPlan) -> Declared {
    let mut declared = Declared::new();
    for m in &mut plan.mounts {
        let (Mount::ReadOnlyBind(p) | Mount::Mask(p) | Mount::Pin(p)) = m else {
            continue;
        };
        let path = PathBuf::from(std::ffi::OsStr::from_bytes(p.as_bytes()));
        let Ok(real) = std::fs::canonicalize(&path) else {
            continue;
        };
        let Ok(c) = c_path(&real) else {
            continue;
        };
        let Ok(id) = sys::identity(&c) else {
            continue;
        };
        if let Ok(canonical) = procage_policy::AbsPath::new(real.as_os_str().as_bytes()) {
            *p = canonical;
            declared.insert(real, id);
        }
    }
    declared
}

/// A declared mount path at spawn, with the object the cage was made with.
/// The child checks that the path still names it: a link or rename made
/// since refuses the spawn there, after the link check has had its say.
fn declared_at(path: &Path, declared: &Declared) -> Result<Planned, SpawnError> {
    let id = *declared
        .get(path)
        .ok_or_else(|| path_error(path, libc::ENOENT))?;
    Ok(Planned {
        path: path.to_path_buf(),
        c: c_path(path)?,
        id,
    })
}

/// The T1 mounts: the plan's, then the class covers, shallowest first.
pub(super) fn mounts(
    plan: &LinuxPlan,
    declared: &Declared,
    covers: &[(PathBuf, Cover)],
) -> Result<Vec<ChildMount>, SpawnError> {
    let to_path =
        |p: &procage_policy::AbsPath| PathBuf::from(std::ffi::OsStr::from_bytes(p.as_bytes()));
    let mut out: Vec<(usize, ChildMount)> = Vec::new();
    for m in &plan.mounts {
        let (p, mount) = match m {
            Mount::ReadOnlyBind(path) => {
                let p = declared_at(&to_path(path), declared)?;
                let m = read_only(&p);
                (p, m)
            }
            Mount::Mask(path) => {
                let p = declared_at(&to_path(path), declared)?;
                let m = hide(&p)?;
                (p, m)
            }
            Mount::Pin(path) => {
                let p = declared_at(&to_path(path), declared)?;
                let m = pin(&p);
                (p, m)
            }
            Mount::PrivateDevShm => {
                let Ok(p) = planned(Path::new("/dev/shm")) else {
                    continue;
                };
                if !p.path.is_dir() {
                    continue;
                }
                let m = ChildMount::Tmpfs {
                    target: p.c.clone(),
                    target_id: p.id,
                    attrs: sys::MOUNT_ATTR_NOSUID | sys::MOUNT_ATTR_NODEV | sys::MOUNT_ATTR_NOEXEC,
                    mode: c"1777".into(),
                    optional: None,
                };
                (p, m)
            }
        };
        out.push((depth(&p.path), mount));
    }
    // Covers come from the file system at spawn (class names, foreign
    // sockets): one whose file is removed before it is mounted, here or in
    // the child, has nothing left to cover and is skipped, as a file created
    // after the spawn is never covered. A name the caller cannot reach (a
    // root-only `/run/podman`) is skipped too: the child runs as the same
    // user and holds no capability over the host's files, so it cannot
    // reach it either. Each holds its object, so the child tells a removed
    // file from a moved one.
    for (path, cover) in covers {
        let gone = |e: &SpawnError| matches!(e, SpawnError::Path { error, .. } if matches!(error.raw_os_error(), Some(libc::ENOENT | libc::EACCES)));
        let mut p = match planned(path) {
            Ok(p) => p,
            Err(e) if gone(&e) => continue,
            Err(e) => return Err(e),
        };
        let held = match sys::hold(&p.c) {
            Ok(fd) => fd,
            Err(libc::ENOENT | libc::EACCES) => continue,
            Err(e) => return Err(path_error(&p.path, e)),
        };
        // The object held is the one planned: the name may have passed to
        // another file since `planned` looked.
        p.id = sys::identity_of(&held).map_err(|e| path_error(&p.path, e))?;
        let mount = match cover {
            Cover::Pin => Ok(pin(&p)),
            Cover::ReadOnly => Ok(read_only(&p)),
            Cover::Hide => hide(&p),
        };
        let mut mount = match mount {
            Ok(m) => m,
            Err(e) if gone(&e) => continue,
            Err(e) => return Err(e),
        };
        match &mut mount {
            ChildMount::Bind { optional, .. } | ChildMount::Tmpfs { optional, .. } => {
                *optional = Some(held);
            }
        }
        out.push((depth(&p.path), mount));
    }
    out.sort_by_key(|(d, _)| *d);
    // A hidden directory (an empty tmpfs) shadows everything beneath it, so
    // a deeper cover under one is redundant: drop it, or the child would
    // find its path gone and could not tell the shadow from an attacker's
    // rename.
    let mut hidden: Vec<PathBuf> = Vec::new();
    let mut kept = Vec::new();
    for (_, mount) in out {
        let target = match &mount {
            ChildMount::Bind { target, .. } | ChildMount::Tmpfs { target, .. } => target,
        };
        let path = PathBuf::from(std::ffi::OsStr::from_bytes(target.to_bytes()));
        if hidden.iter().any(|h| path.starts_with(h) && path != *h) {
            continue;
        }
        if matches!(&mount, ChildMount::Tmpfs { mode, .. } if mode.to_bytes() == b"000") {
            hidden.push(path.clone());
        }
        kept.push(mount);
    }
    Ok(kept)
}

/// After the child refused a mount (`ELOOP`, `ESTALE`): the first planned
/// path that now passes a link or names another object.
pub(super) fn moved(mounts: &[ChildMount]) -> Option<SpawnError> {
    // A removed cover was skipped, whatever its name leads to now.
    for m in mounts.iter().filter(|m| !m.removed()) {
        for (c, id) in m.planned() {
            let path = Path::new(std::ffi::OsStr::from_bytes(c.to_bytes()));
            if let Some(link) = link_on(path) {
                return Some(SpawnError::MountMoved {
                    path: path.to_path_buf(),
                    link: Some(link),
                });
            }
            let now = sys::identity(c);
            if now != Ok(id) {
                return Some(SpawnError::MountMoved {
                    path: path.to_path_buf(),
                    link: None,
                });
            }
        }
    }
    None
}

/// The id map that keeps `id` as itself.
pub(super) fn id_map(id: u32) -> Vec<u8> {
    format!("{id} {id} 1\n").into_bytes()
}

/// Turns a spawn error carrying a step code into [`SpawnError::Apply`].
pub(super) fn decode(error: io::Error) -> SpawnError {
    if let Some((step, errno)) = error.raw_os_error().and_then(sys::decode_step)
        && let Some(step) = Step::from_code(step)
    {
        return SpawnError::Apply { step, errno };
    }
    SpawnError::Io(error)
}
