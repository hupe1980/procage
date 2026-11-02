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
/// with `grants` bound.
///
/// `hidden` (tier T2) are paths kept out piecewise: a rule at or under one
/// is dropped, and a rule above one is replaced by rules for every entry on
/// the way except the hidden path, as listed now (symbolic links are
/// skipped: they could lead into the hidden path). At most `limit` entries
/// are visited.
pub(super) fn ruleset(
    plan: &LinuxPlan,
    grants: &BTreeMap<String, PathBuf>,
    hidden: &[PathBuf],
    limit: usize,
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
        .filter(|p| {
            // The listing shows the path as bound, which may pass through a
            // symbolic link; `allowed` is resolved.
            let real = std::fs::canonicalize(p).unwrap_or_else(|_| p.clone());
            std::fs::symlink_metadata(p).is_ok_and(|m| m.file_type().is_socket())
                && !allowed.iter().any(|a| real.starts_with(a))
                && !masked
                    .iter()
                    .any(|m| p.starts_with(m) || real.starts_with(m))
        })
        .collect();
    out.sort();
    out.dedup();
    Ok(out)
}

fn depth(path: &Path) -> usize {
    path.components().count()
}

fn read_only(path: &Path) -> Result<Vec<ChildMount>, SpawnError> {
    if std::fs::metadata(path).is_err() {
        return Err(path_error(path, libc::ENOENT));
    }
    let target = c_path(path)?;
    let locked = sys::locked_flags(&target).map_err(|e| path_error(path, e))?;
    Ok(vec![
        ChildMount::Bind {
            source: target.clone(),
            target: target.clone(),
            recursive: true,
            optional: false,
        },
        ChildMount::Remount {
            target,
            flags: locked | libc::MS_RDONLY,
            optional: false,
        },
    ])
}

fn hide(path: &Path) -> Result<Vec<ChildMount>, SpawnError> {
    let meta = std::fs::metadata(path).map_err(|_| path_error(path, libc::ENOENT))?;
    let target = c_path(path)?;
    let sealed = libc::MS_RDONLY | libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC;
    if meta.is_dir() {
        return Ok(vec![ChildMount::Tmpfs {
            target,
            flags: sealed,
            data: c"mode=000".into(),
            optional: false,
        }]);
    }
    let null = c"/dev/null";
    let locked = sys::locked_flags(null).map_err(|e| path_error(Path::new("/dev/null"), e))?;
    Ok(vec![
        ChildMount::Bind {
            source: null.into(),
            target: target.clone(),
            recursive: false,
            optional: false,
        },
        ChildMount::Remount {
            target,
            flags: locked | sealed,
            optional: false,
        },
    ])
}

fn pin(path: &Path) -> Result<Vec<ChildMount>, SpawnError> {
    let target = c_path(path)?;
    Ok(vec![ChildMount::Bind {
        source: target.clone(),
        target,
        recursive: true,
        optional: false,
    }])
}

/// The T1 mounts: the plan's, then the class covers, shallowest first.
pub(super) fn mounts(
    plan: &LinuxPlan,
    covers: &[(PathBuf, Cover)],
) -> Result<Vec<ChildMount>, SpawnError> {
    let to_path =
        |p: &procage_policy::AbsPath| PathBuf::from(std::ffi::OsStr::from_bytes(p.as_bytes()));
    let mut groups: Vec<(usize, Vec<ChildMount>)> = Vec::new();
    for m in &plan.mounts {
        let (path, group) = match m {
            Mount::ReadOnlyBind(p) => (to_path(p), read_only(&to_path(p))?),
            Mount::Mask(p) => (to_path(p), hide(&to_path(p))?),
            Mount::Pin(p) => (to_path(p), pin(&to_path(p))?),
            Mount::PrivateDevShm => {
                let shm = PathBuf::from("/dev/shm");
                if !shm.is_dir() {
                    continue;
                }
                let group = vec![ChildMount::Tmpfs {
                    target: c"/dev/shm".into(),
                    flags: libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
                    data: c"mode=1777".into(),
                    optional: false,
                }];
                (shm, group)
            }
        };
        groups.push((depth(&path), group));
    }
    // Covers come from the file system at spawn (class names, foreign
    // sockets): one whose file is removed before it is mounted, here or in
    // the child, has nothing left to cover and is skipped, as a file created
    // after the spawn is never covered.
    for (path, cover) in covers {
        let group = match cover {
            Cover::Pin => pin(path),
            Cover::ReadOnly => read_only(path),
            Cover::Hide => hide(path),
        };
        let group = match group {
            Ok(g) => g,
            Err(SpawnError::Path { error, .. }) if error.raw_os_error() == Some(libc::ENOENT) => {
                continue;
            }
            Err(e) => return Err(e),
        };
        groups.push((depth(path), optional(group)));
    }
    groups.sort_by_key(|(d, _)| *d);
    Ok(groups.into_iter().flat_map(|(_, g)| g).collect())
}

/// `group` with its mounts marked optional (see [`ChildMount::Tmpfs`]).
fn optional(group: Vec<ChildMount>) -> Vec<ChildMount> {
    group
        .into_iter()
        .map(|m| match m {
            ChildMount::Bind {
                source,
                target,
                recursive,
                ..
            } => ChildMount::Bind {
                source,
                target,
                recursive,
                optional: true,
            },
            ChildMount::Tmpfs {
                target,
                flags,
                data,
                ..
            } => ChildMount::Tmpfs {
                target,
                flags,
                data,
                optional: true,
            },
            ChildMount::Remount { target, flags, .. } => ChildMount::Remount {
                target,
                flags,
                optional: true,
            },
        })
        .collect()
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
