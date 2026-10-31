//! The data-driven hard-deny classes at spawn.
//!
//! Landlock cannot deny inside a tree it allows. On tier T1 the paths of the
//! classes in force that exist at spawn are covered by mounts: secrets are
//! hidden, trust-handoff and persistence paths become read-only, and every
//! `.git` directory under a writable tree is pinned (a mountpoint cannot be
//! renamed or removed). On tier T2 nothing can be masked, so a grant whose
//! path reaches a class path is refused.
//!
//! The lowering knows homes as `/home/*` and `/root`. Homes elsewhere (the
//! caller's `$HOME`, or homes added through the cage options) are checked
//! here.

use std::path::{Path, PathBuf};

use procage_policy::linux::{ClassPaths, may_overlap};
use procage_policy::{
    CapabilityGap, Construct, Degradation, GapKind, HardDenyClass, LinuxPlan, LowerOptions, Target,
    Tier,
};

use super::SpawnError;

/// How a class path is covered on T1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Cover {
    /// Bind the path over itself (`.git`), so it cannot be renamed.
    Pin,
    /// Bind the path over itself read-only.
    ReadOnly,
    /// An empty, inaccessible mount over the path.
    Hide,
}

/// The homes: `/root`, every directory under `/home`, the caller's `$HOME`
/// and `extra`, canonicalised, without duplicates.
pub(crate) fn homes(extra: &[PathBuf]) -> Vec<PathBuf> {
    let mut out = vec![PathBuf::from("/root")];
    if let Ok(entries) = std::fs::read_dir("/home") {
        out.extend(
            entries
                .flatten()
                .filter(|e| e.file_type().is_ok_and(|t| t.is_dir()))
                .map(|e| e.path()),
        );
    }
    if let Some(home) = std::env::var_os("HOME").map(PathBuf::from)
        && home.is_absolute()
    {
        out.push(home);
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

/// Whether the lowering already knows `home` (`/root` or `/home/<name>`).
fn known(home: &Path) -> bool {
    home == Path::new("/root") || home.parent() == Some(Path::new("/home"))
}

/// The patterns of `class` in homes the lowering does not know.
fn extra_patterns(class: &ClassPaths, homes: &[PathBuf]) -> Vec<String> {
    homes
        .iter()
        .filter(|h| !known(h))
        .flat_map(|h| {
            class
                .home
                .iter()
                .map(move |rel| format!("{}/{rel}", h.to_string_lossy()))
        })
        .collect()
}

/// The note for hiding by piecewise grants on tier T2 (as the lowering's).
const PIECEWISE: &str = "the trees around the hidden path are granted entry by entry as listed \
    at spawn: entries added later on the way are denied, the directories on the way cannot be \
    listed, and the hidden path's metadata stays visible";

/// Whether access with write rights (`writes`) or any access reaches a path
/// of `class` matching `patterns`.
fn reaches(class: &ClassPaths, patterns: &[String], path: &Path, writes: bool) -> bool {
    (class.hide || writes)
        && patterns
            .iter()
            .any(|p| may_overlap(p, path.as_os_str().as_encoded_bytes()))
}

/// The capability gaps (or, when allowed, degradations) for rules of `plan`
/// that reach class paths in homes the lowering does not know.
pub(crate) fn home_gaps(
    plan: &mut LinuxPlan,
    rules: &[(PathBuf, bool)],
    homes: &[PathBuf],
    options: &LowerOptions,
    target: Target,
) -> Result<(), SpawnError> {
    let mut gaps = Vec::new();
    for class in &plan.classes {
        let patterns = extra_patterns(class, homes);
        if !rules.iter().any(|(p, w)| reaches(class, &patterns, p, *w)) {
            continue;
        }
        let construct = Construct::of_class(class.class);
        // T1 masks; T2 hides piecewise, which a write rule defeats.
        let written = rules
            .iter()
            .any(|(p, w)| *w && reaches(class, &patterns, p, true));
        let note = match plan.tier {
            Tier::T1 => {
                Some("paths that exist at spawn are masked; paths created later are not covered")
            }
            Tier::T2 if class.hide && !written => Some(PIECEWISE),
            Tier::T2 => None,
        };
        if let Some(note) = note
            && options.allow_degrade.contains(&construct)
        {
            if !plan.degradations.iter().any(|d| d.construct == construct) {
                plan.degradations.push(Degradation {
                    construct,
                    target,
                    note,
                });
            }
            continue;
        }
        gaps.push(CapabilityGap {
            construct,
            target,
            kind: if note.is_some() {
                GapKind::Approximation
            } else {
                GapKind::Unsupported
            },
            subject: Some(class.class.to_string()),
        });
    }
    plan.degradations.sort();
    if gaps.is_empty() {
        Ok(())
    } else {
        gaps.sort();
        Err(SpawnError::Lower(procage_policy::LowerError::Gaps(gaps)))
    }
}

/// The class a grant bound to `path` would reach (tier T2).
pub(crate) fn grant_reaches(
    classes: &[ClassPaths],
    homes: &[PathBuf],
    path: &Path,
    writes: bool,
) -> Option<HardDenyClass> {
    classes.iter().find_map(|class| {
        let mut patterns = class.patterns();
        patterns.extend(extra_patterns(class, homes));
        reaches(class, &patterns, path, writes).then_some(class.class)
    })
}

/// Whether `path` exists, following links (a dangling link is skipped: no
/// mount can cover it, and its target does not exist yet).
fn exists(path: &Path) -> bool {
    std::fs::metadata(path).is_ok()
}

/// The T1 mounts for `classes`: home paths in every home, system paths, and
/// the names and `.git` directories found under the `writable` trees.
///
/// The walk never follows symbolic links and visits at most `limit`
/// entries in all; a matched entry that is a link is mounted through,
/// which protects its target.
pub(crate) fn t1_covers(
    classes: &[ClassPaths],
    homes: &[PathBuf],
    writable: &[PathBuf],
    limit: usize,
) -> Result<Vec<(PathBuf, Cover)>, SpawnError> {
    let mut out = Vec::new();
    let mut names: Vec<(&str, Cover)> = Vec::new();
    let mut pin_git = false;
    for class in classes {
        let cover = if class.hide {
            Cover::Hide
        } else {
            Cover::ReadOnly
        };
        for home in homes {
            for rel in &class.home {
                let p = home.join(rel);
                if exists(&p) {
                    out.push((p, cover));
                }
            }
        }
        for p in &class.system {
            let p = PathBuf::from(p.to_str().unwrap_or("/"));
            if exists(&p) {
                out.push((p, cover));
            }
        }
        names.extend(class.anywhere.iter().map(|n| (n.as_str(), cover)));
        pin_git |= class.pin_git;
    }
    if !names.is_empty() || pin_git {
        let mut visited = 0usize;
        for root in writable {
            walk(root, &names, pin_git, limit, &mut visited, &mut out)?;
        }
    }
    out.sort();
    out.dedup();
    Ok(out)
}

fn walk(
    root: &Path,
    names: &[(&str, Cover)],
    pin_git: bool,
    limit: usize,
    visited: &mut usize,
    out: &mut Vec<(PathBuf, Cover)>,
) -> Result<(), SpawnError> {
    let too_big = || SpawnError::Walk {
        root: root.to_path_buf(),
        limit,
    };
    // (directory, inside a `.git` directory)
    let mut stack = vec![(root.to_path_buf(), false)];
    while let Some((dir, in_git)) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            *visited += 1;
            if *visited > limit {
                return Err(too_big());
            }
            let name = entry.file_name();
            let Some(name) = name.to_str() else { continue };
            let path = entry.path();
            for &(n, cover) in names {
                let first = n.split('/').next().unwrap_or(n);
                if first == name {
                    let candidate = dir.join(n);
                    if exists(&candidate) {
                        out.push((candidate, cover));
                    }
                }
            }
            let Ok(kind) = entry.file_type() else {
                continue;
            };
            if pin_git && name == ".git" {
                if kind.is_dir() {
                    out.push((path.clone(), Cover::Pin));
                } else if kind.is_file() {
                    // A `gitdir:` file points git elsewhere; keep it.
                    out.push((path.clone(), Cover::ReadOnly));
                }
            }
            // Object stores can be huge and hold nothing a tool runs.
            if kind.is_dir() && !(in_git && name == "objects") {
                stack.push((path, in_git || name == ".git"));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use procage_policy::presets::linux_class_paths;

    fn scratch(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("procage-classes-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::canonicalize(dir).unwrap()
    }

    #[test]
    fn covers_homes_names_and_git() {
        let home = scratch("home");
        std::fs::create_dir_all(home.join(".ssh")).unwrap();
        std::fs::create_dir_all(home.join(".config/systemd/user")).unwrap();
        let ws = scratch("ws");
        std::fs::create_dir_all(ws.join(".git/hooks")).unwrap();
        std::fs::create_dir_all(ws.join(".git/objects/aa")).unwrap();
        std::fs::create_dir_all(ws.join("sub/.vscode")).unwrap();
        std::fs::write(ws.join("sub/.bashrc"), "").unwrap();
        std::fs::write(ws.join("src.rs"), "").unwrap();
        let classes: Vec<_> = [
            HardDenyClass::Secrets,
            HardDenyClass::TrustHandoff,
            HardDenyClass::Persistence,
        ]
        .into_iter()
        .filter_map(linux_class_paths)
        .collect();
        let covers = t1_covers(
            &classes,
            std::slice::from_ref(&home),
            std::slice::from_ref(&ws),
            1000,
        )
        .unwrap();
        for (path, cover) in [
            (home.join(".ssh"), Cover::Hide),
            (home.join(".config/systemd/user"), Cover::ReadOnly),
            (ws.join(".git"), Cover::Pin),
            (ws.join(".git/hooks"), Cover::ReadOnly),
            (ws.join("sub/.vscode"), Cover::ReadOnly),
            (ws.join("sub/.bashrc"), Cover::ReadOnly),
        ] {
            assert!(
                covers.contains(&(path.clone(), cover)),
                "{path:?} {covers:?}"
            );
        }
        assert!(!covers.iter().any(|(p, _)| p.ends_with("src.rs")));
        assert!(matches!(
            t1_covers(&classes, &[], std::slice::from_ref(&ws), 3),
            Err(SpawnError::Walk { limit: 3, .. })
        ));
        let _ = std::fs::remove_dir_all(home);
        let _ = std::fs::remove_dir_all(ws);
    }

    #[test]
    fn the_walk_does_not_follow_links() {
        let outside = scratch("outside");
        std::fs::create_dir_all(outside.join(".vscode")).unwrap();
        let ws = scratch("links");
        std::os::unix::fs::symlink(&outside, ws.join("link")).unwrap();
        let classes: Vec<_> = linux_class_paths(HardDenyClass::TrustHandoff)
            .into_iter()
            .collect();
        let covers = t1_covers(&classes, &[], std::slice::from_ref(&ws), 1000).unwrap();
        assert!(covers.is_empty(), "{covers:?}");
        let _ = std::fs::remove_dir_all(outside);
        let _ = std::fs::remove_dir_all(ws);
    }

    #[test]
    fn grants_reaching_a_class_are_found() {
        let secrets: Vec<_> = linux_class_paths(HardDenyClass::Secrets)
            .into_iter()
            .collect();
        let homes = [PathBuf::from("/srv/me")];
        assert_eq!(
            grant_reaches(&secrets, &homes, Path::new("/srv/me"), false),
            Some(HardDenyClass::Secrets)
        );
        assert_eq!(
            grant_reaches(&secrets, &homes, Path::new("/home/u"), false),
            Some(HardDenyClass::Secrets)
        );
        assert_eq!(
            grant_reaches(&secrets, &homes, Path::new("/srv/me/ws"), true),
            None
        );
    }
}
