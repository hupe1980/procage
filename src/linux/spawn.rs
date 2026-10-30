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

/// The Landlock ruleset for one spawn: the plan's rules on descriptors
/// opened now, with grants bound to their paths.
pub(super) fn ruleset(
    plan: &LinuxPlan,
    grants: &BTreeMap<String, PathBuf>,
) -> Result<OwnedFd, SpawnError> {
    let ll = &plan.landlock;
    let ruleset = sys::landlock_ruleset(ll.handled_fs.0, ll.handled_net.0, ll.scopes.0)
        .map_err(|e| SpawnError::Io(io::Error::from_raw_os_error(e)))?;
    for rule in &ll.rules {
        let Some((path, optional)) = rule_path(&rule.target, grants)? else {
            continue;
        };
        let (fd, dir) = match sys::open_path(&c_path(&path)?) {
            Ok(opened) => opened,
            Err(libc::ENOENT) if optional => continue,
            Err(e) => return Err(path_error(&path, e)),
        };
        // Rights that only apply to directories are refused on a file.
        let access = if dir {
            rule.access
        } else {
            rule.access.intersect(AccessFs::FILE_RIGHTS)
        };
        if access == AccessFs::NONE {
            continue;
        }
        sys::landlock_allow_path(&ruleset, &fd, access.0).map_err(|e| path_error(&path, e))?;
    }
    for rule in &ll.net_rules {
        sys::landlock_allow_port(&ruleset, rule.port.get(), rule.access.0)
            .map_err(|e| SpawnError::Io(io::Error::from_raw_os_error(e)))?;
    }
    Ok(ruleset)
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
        },
        ChildMount::Remount {
            target,
            flags: locked | libc::MS_RDONLY,
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
        }]);
    }
    let null = c"/dev/null";
    let locked = sys::locked_flags(null).map_err(|e| path_error(Path::new("/dev/null"), e))?;
    Ok(vec![
        ChildMount::Bind {
            source: null.into(),
            target: target.clone(),
            recursive: false,
        },
        ChildMount::Remount {
            target,
            flags: locked | sealed,
        },
    ])
}

fn pin(path: &Path) -> Result<Vec<ChildMount>, SpawnError> {
    let target = c_path(path)?;
    Ok(vec![ChildMount::Bind {
        source: target.clone(),
        target,
        recursive: true,
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
                }];
                (shm, group)
            }
        };
        groups.push((depth(&path), group));
    }
    for (path, cover) in covers {
        let group = match cover {
            Cover::Pin => pin(path)?,
            Cover::ReadOnly => read_only(path)?,
            Cover::Hide => hide(path)?,
        };
        groups.push((depth(path), group));
    }
    groups.sort_by_key(|(d, _)| *d);
    Ok(groups.into_iter().flat_map(|(_, g)| g).collect())
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
