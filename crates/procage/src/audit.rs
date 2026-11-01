//! Audits of what path rules cannot stop.
//!
//! **Link check (before every spawn, on by default).** A hard link gives a
//! file a second name, and path rules see names: a protected or hidden file
//! with another name in a writable or readable tree can be written or read
//! through it (escape class R-08). The other name may lie anywhere, but the
//! file itself shows it: its link count is above one. So before each spawn
//! procage examines the protected and hidden targets of the policy and the
//! existing files of the secrets, trust-handoff and persistence classes, and
//! with [`LinkAudit::Refuse`] (the default) refuses the spawn when one has
//! more than one name, or a literal target has become a symbolic link.
//! [`LinkAudit::Report`] lists them instead; [`LinkAudit::Off`] skips the
//! check. Hard links cannot be made during a run: Seatbelt refuses to link a
//! file the child cannot write, and Landlock never grants linking across
//! directories.
//!
//! **Handoff audit (after the run, opt-in).** Trust handoff is a program
//! outside the sandbox later running or following what the child wrote (R-07).
//! Where a path rule cannot hold (a file that did not exist at spawn on Linux,
//! a symbolic link the host follows), detection can: with the handoff audit,
//! procage notes the trust-handoff files, symbolic links and repository
//! directories of the writable trees before the run and lists, after it, what
//! was created or changed. The harness decides what to do with them.
//!
//! Both walks stay on the device they start on, never follow a symbolic link
//! and stop at the cage's walk limit; a result past the limit, or with an
//! entry that could not be read, is incomplete, never clean.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use procage_policy::linux::may_overlap;

/// What the link check does with a protected file that has another name.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum LinkAudit {
    /// Refuse the spawn (the default).
    #[default]
    Refuse,
    /// Spawn, and list the findings in [`Audit::links`].
    Report,
    /// Do not check.
    Off,
}

/// A protected, hidden or class file with another name.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LinkFinding {
    /// The file, as the policy or the class names it.
    pub path: PathBuf,
    /// Its link count.
    pub links: u64,
    /// The literal target is a symbolic link (not followed).
    pub symbolic: bool,
}

impl fmt::Display for LinkFinding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.symbolic {
            write!(f, "{} is a symbolic link", Escaped(&self.path))
        } else {
            write!(f, "{} has {} names", Escaped(&self.path), self.links)
        }
    }
}

/// What a run changed that an unsandboxed program may later trust.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum HandoffKind {
    /// A trust-handoff file that did not exist before the run.
    Created,
    /// A trust-handoff file the run changed.
    Modified,
    /// A symbolic link created (or retargeted) by the run, with its target
    /// as written (not resolved).
    Link {
        /// The link's target.
        target: PathBuf,
    },
    /// A repository metadata directory (`.git`) created by the run.
    Repository,
}

/// One thing the run left behind.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct HandoffFinding {
    /// Where.
    pub path: PathBuf,
    /// What.
    pub kind: HandoffKind,
}

impl fmt::Display for HandoffFinding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let path = Escaped(&self.path);
        match &self.kind {
            HandoffKind::Created => write!(f, "{path} created"),
            HandoffKind::Modified => write!(f, "{path} modified"),
            HandoffKind::Link { target } => write!(f, "{path} -> {}", Escaped(target)),
            HandoffKind::Repository => write!(f, "{path}: repository created"),
        }
    }
}

/// A run's audits.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Audit {
    /// The link check's mode.
    pub mode: LinkAudit,
    /// Link findings (with [`LinkAudit::Report`]; a refused spawn has none).
    pub links: Vec<LinkFinding>,
    /// Whether the link check examined everything.
    pub links_complete: bool,
    /// Entries the link check examined.
    pub links_visited: usize,
    /// What the run left behind, with the handoff audit.
    pub handoff: Option<Vec<HandoffFinding>>,
    /// Whether both handoff walks examined everything, and the run had
    /// ended before the second.
    pub handoff_complete: bool,
    /// Entries the handoff walks examined.
    pub handoff_visited: usize,
}

/// A path with control characters escaped, for messages.
struct Escaped<'a>(&'a Path);

impl fmt::Display for Escaped<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for c in self.0.to_string_lossy().chars() {
            if c.is_control() {
                write!(f, "{}", c.escape_default())?;
            } else {
                write!(f, "{c}")?;
            }
        }
        Ok(())
    }
}

/// Class entries the link check leaves out: large application data
/// (browser profiles) and folders macOS guards with privacy consent (Mail,
/// Messages, Safari, Cookies), which a walk on every spawn would slow down or
/// prompt for. The credential files of the classes are always examined.
const SKIPPED: &[&str] = &[
    ".config/BraveSoftware",
    ".config/chromium",
    ".config/google-chrome",
    ".config/microsoft-edge",
    ".mozilla",
    "Library/Application Support",
    "Library/Cookies",
    "Library/Mail",
    "Library/Messages",
    "Library/Safari",
];

/// The class paths to examine: each entry of `rels` in every home, except
/// [`SKIPPED`], and `system`; only those that exist.
pub(crate) fn class_paths(
    homes: &[PathBuf],
    rels: &[&str],
    system: &[PathBuf],
    hidden: bool,
) -> Vec<(PathBuf, bool)> {
    let mut out: Vec<PathBuf> = homes
        .iter()
        .flat_map(|h| {
            rels.iter()
                .filter(|r| !SKIPPED.iter().any(|s| r.starts_with(s)))
                .map(move |r| h.join(r))
        })
        .chain(system.iter().cloned())
        .filter(|p| std::fs::symlink_metadata(p).is_ok())
        .collect();
    out.sort();
    out.dedup();
    out.into_iter().map(|p| (p, hidden)).collect()
}

/// What the link check examines, built once per cage.
#[derive(Debug, Clone, Default)]
pub(crate) struct Targets {
    /// Literal protect and hide targets, and whether each is hidden.
    literal: Vec<(PathBuf, bool)>,
    /// Protect and hide subpaths: every file below.
    trees: Vec<(PathBuf, bool)>,
    /// The class paths: every file below, except in cache directories.
    classes: Vec<(PathBuf, bool)>,
    /// Protect and hide globs: the fixed prefix to walk and the pattern.
    /// Matching is conservative: a file that may match counts.
    globs: Vec<(PathBuf, String, bool)>,
}

impl Targets {
    /// The targets of `policy` (resolved), plus `class_paths` (the class
    /// files and directories that exist in the homes, and the system ones).
    pub(crate) fn new(
        policy: &procage_policy::Policy,
        class_paths: Vec<(PathBuf, bool)>,
    ) -> Targets {
        use procage_policy::{Access, FsTarget};
        use std::os::unix::ffi::OsStrExt;
        let to_path = |b: &[u8]| PathBuf::from(std::ffi::OsStr::from_bytes(b));
        let mut t = Targets {
            classes: class_paths,
            ..Targets::default()
        };
        for rule in &policy.fs {
            if !matches!(rule.access, Access::Protect | Access::Hide) {
                continue;
            }
            let hidden = rule.access == Access::Hide;
            match &rule.target {
                FsTarget::Literal(p) => t.literal.push((to_path(p.as_bytes()), hidden)),
                FsTarget::Subpath(p) => t.trees.push((to_path(p.as_bytes()), hidden)),
                FsTarget::Glob(g) => {
                    let source = g.as_str();
                    let prefix: Vec<&str> = source
                        .split('/')
                        .take_while(|c| !c.contains(['*', '?', '[', '{', '\\']))
                        .collect();
                    let prefix = prefix.join("/");
                    let prefix = if prefix.is_empty() {
                        "/".into()
                    } else {
                        prefix
                    };
                    t.globs
                        .push((PathBuf::from(prefix), source.to_string(), hidden));
                }
            }
        }
        t.literal.sort();
        t.literal.dedup();
        t.trees.sort();
        t.trees.dedup();
        t
    }
}

/// The result of a link check.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct LinkResult {
    pub(crate) findings: Vec<LinkFinding>,
    pub(crate) complete: bool,
    pub(crate) visited: usize,
}

/// Runs the link check over `targets`, examining at most `limit` entries.
/// A file is a finding when it has more names than the check found among the
/// targets: names that all lie inside the protected set (a lock file and its
/// link in the same directory) give nothing away.
pub(crate) fn links(targets: &Targets, limit: usize) -> LinkResult {
    let mut r = LinkResult {
        complete: true,
        ..LinkResult::default()
    };
    let mut seen = Names::new();
    for (path, hidden) in &targets.literal {
        r.visited += 1;
        match std::fs::symlink_metadata(path) {
            Ok(m) if m.file_type().is_symlink() => r.findings.push(LinkFinding {
                path: path.clone(),
                links: m.nlink(),
                symbolic: true,
            }),
            Ok(m) => note(&mut seen, path, &m, *hidden),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => r.complete = false,
        }
    }
    for (root, hidden) in &targets.trees {
        walk(root, limit, &mut r, &mut |path, m, _| {
            note(&mut seen, path, m, *hidden)
        });
    }
    for (root, hidden) in &targets.classes {
        walk_skipping(
            root,
            limit,
            &mut r,
            &mut |path, m, _| note(&mut seen, path, m, *hidden),
            &cache,
        );
    }
    for (prefix, pattern, hidden) in &targets.globs {
        walk(prefix, limit, &mut r, &mut |path, m, _| {
            match glob_match(pattern, path) {
                Some(true) => note(&mut seen, path, m, *hidden),
                // Classes and alternatives are matched conservatively: the
                // file is examined, but its name never counts as accounted
                // for, so an over-matched alias cannot hide a finding.
                None if may_overlap(pattern, path.as_os_str().as_encoded_bytes()) => {
                    note_unaccounted(&mut seen, path, m)
                }
                _ => {}
            }
        });
    }
    for (path, links, names) in seen.into_values() {
        // Every name must be among the targets, and a hidden file's names
        // must all be hidden: a second name in a protected (readable) tree
        // would let the child read it.
        let hidden = names.values().any(|h| *h);
        let accounted = names.len() as u64 >= links && (!hidden || names.values().all(|h| *h));
        if !accounted {
            r.findings.push(LinkFinding {
                path,
                links,
                symbolic: false,
            });
        }
    }
    r.findings.sort();
    r.findings.dedup();
    r
}

/// Multi-link files by device and inode: the first name seen, the link
/// count, and every name seen among the targets with whether its target is
/// hidden (a hidden name wins over a protected one for the same path).
type Names = BTreeMap<(u64, u64), (PathBuf, u64, BTreeMap<PathBuf, bool>)>;

/// Whether `path` matches the glob `pattern` (`*` and `?` within a
/// component, `**` across components, `\` escapes); `None` when the
/// pattern uses classes or alternatives (`[…]`, `{…}`), which this does not
/// decide.
fn glob_match(pattern: &str, path: &Path) -> Option<bool> {
    if pattern.contains(['[', '{']) {
        return None;
    }
    fn component(p: &[u8], s: &[u8]) -> bool {
        match (p.first(), s.first()) {
            (None, None) => true,
            (Some(b'*'), _) => component(&p[1..], s) || (!s.is_empty() && component(p, &s[1..])),
            (Some(b'?'), Some(_)) => component(&p[1..], &s[1..]),
            (Some(b'\\'), Some(c)) if p.get(1) == Some(c) => component(&p[2..], &s[1..]),
            (Some(a), Some(b)) if a == b && *a != b'\\' => component(&p[1..], &s[1..]),
            _ => false,
        }
    }
    fn go(p: &[&[u8]], s: &[&[u8]]) -> bool {
        match p.first() {
            None => s.is_empty(),
            Some(&b"**") => go(&p[1..], s) || (!s.is_empty() && go(p, &s[1..])),
            Some(c) => !s.is_empty() && component(c, s[0]) && go(&p[1..], &s[1..]),
        }
    }
    let p: Vec<&[u8]> = pattern
        .as_bytes()
        .split(|b| *b == b'/')
        .filter(|c| !c.is_empty())
        .collect();
    let s: Vec<&[u8]> = path
        .as_os_str()
        .as_encoded_bytes()
        .split(|b| *b == b'/')
        .filter(|c| !c.is_empty())
        .collect();
    Some(go(&p, &s))
}

fn note_unaccounted(seen: &mut Names, path: &Path, m: &std::fs::Metadata) {
    if m.file_type().is_file() && m.nlink() > 1 {
        seen.entry((m.dev(), m.ino()))
            .or_insert_with(|| (path.to_path_buf(), m.nlink(), BTreeMap::new()));
    }
}

fn note(seen: &mut Names, path: &Path, m: &std::fs::Metadata, hidden: bool) {
    if m.file_type().is_file() && m.nlink() > 1 {
        *seen
            .entry((m.dev(), m.ino()))
            .or_insert_with(|| (path.to_path_buf(), m.nlink(), BTreeMap::new()))
            .2
            .entry(path.to_path_buf())
            .or_insert(false) |= hidden;
    }
}

/// Whether a directory inside a class path is a tool's cache (kubectl keeps
/// thousands of entries under `~/.kube/cache`): credentials are not kept in
/// caches, and walking them would slow every spawn.
fn cache(dir: &Path) -> bool {
    dir.file_name()
        .is_some_and(|n| n.to_string_lossy().to_ascii_lowercase().contains("cache"))
}

/// Walks `root` (not following links, not leaving its device), calling
/// `each` for every entry; marks `r` incomplete past `limit` or on an
/// unreadable entry. A missing root is nothing to walk.
fn walk(
    root: &Path,
    limit: usize,
    r: &mut LinkResult,
    each: &mut dyn FnMut(&Path, &std::fs::Metadata, &mut LinkResult),
) {
    walk_skipping(root, limit, r, each, &|_| false);
}

/// [`walk`], not descending into directories below `root` that `skip`
/// names.
fn walk_skipping(
    root: &Path,
    limit: usize,
    r: &mut LinkResult,
    each: &mut dyn FnMut(&Path, &std::fs::Metadata, &mut LinkResult),
    skip: &dyn Fn(&Path) -> bool,
) {
    let Ok(meta) = std::fs::symlink_metadata(root) else {
        return;
    };
    let dev = meta.dev();
    let mut stack = vec![(root.to_path_buf(), meta)];
    while let Some((path, meta)) = stack.pop() {
        if r.visited >= limit {
            r.complete = false;
            return;
        }
        r.visited += 1;
        each(&path, &meta, r);
        if !meta.file_type().is_dir() || meta.dev() != dev || (path != root && skip(&path)) {
            continue;
        }
        let Ok(entries) = std::fs::read_dir(&path) else {
            r.complete = false;
            continue;
        };
        for entry in entries {
            let Ok(entry) = entry else {
                r.complete = false;
                continue;
            };
            match std::fs::symlink_metadata(entry.path()) {
                Ok(m) => stack.push((entry.path(), m)),
                Err(_) => r.complete = false,
            }
        }
    }
}

/// The handoff-relevant state of the writable trees at one moment.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Snapshot {
    files: BTreeMap<PathBuf, (u64, u64, i64, i64, i64, i64)>,
    links: BTreeMap<PathBuf, PathBuf>,
    repositories: BTreeSet<PathBuf>,
    complete: bool,
    visited: usize,
}

/// Whether `path` is a trust-handoff path: it is, or lies inside, an entry
/// of `anywhere` (names in any directory, such as `.git/hooks`) or of
/// `home` (absolute).
fn handoff_path(path: &Path, anywhere: &[String], home: &[PathBuf]) -> bool {
    let components: Vec<&std::ffi::OsStr> = path.iter().collect();
    anywhere.iter().any(|name| {
        let want: Vec<&str> = name.split('/').collect();
        components.windows(want.len()).any(|w| {
            w.iter()
                .zip(&want)
                .all(|(got, want)| *got == std::ffi::OsStr::new(want))
        })
    }) || home.iter().any(|h| path.starts_with(h))
}

impl Snapshot {
    /// The handoff files (`anywhere` names under the trees, and the `home`
    /// paths), symbolic links and `.git` directories under `trees`.
    pub(crate) fn take(
        trees: &[PathBuf],
        anywhere: &[String],
        home: &[PathBuf],
        limit: usize,
    ) -> Snapshot {
        let mut s = Snapshot {
            complete: true,
            ..Snapshot::default()
        };
        let mut r = LinkResult {
            complete: true,
            ..LinkResult::default()
        };
        for root in trees.iter().chain(home) {
            walk(root, limit, &mut r, &mut |path, m, _| {
                let t = m.file_type();
                if t.is_symlink() {
                    if let Ok(target) = std::fs::read_link(path) {
                        s.links.insert(path.to_path_buf(), target);
                    }
                    return;
                }
                if t.is_dir() && path.file_name().is_some_and(|n| n == ".git") {
                    s.repositories.insert(path.to_path_buf());
                }
                if handoff_path(path, anywhere, home) {
                    s.files.insert(
                        path.to_path_buf(),
                        (
                            m.ino(),
                            m.size(),
                            m.ctime(),
                            m.ctime_nsec(),
                            m.mtime(),
                            m.mtime_nsec(),
                        ),
                    );
                }
            });
        }
        s.complete = r.complete;
        s.visited = r.visited;
        s
    }
}

/// What changed from `before` to `after`, and whether both were complete.
pub(crate) fn handoff(before: &Snapshot, after: &Snapshot) -> (Vec<HandoffFinding>, bool) {
    let mut out = Vec::new();
    for (path, meta) in &after.files {
        match before.files.get(path) {
            None => out.push(HandoffFinding {
                path: path.clone(),
                kind: HandoffKind::Created,
            }),
            Some(old) if old != meta => out.push(HandoffFinding {
                path: path.clone(),
                kind: HandoffKind::Modified,
            }),
            Some(_) => {}
        }
    }
    for (path, target) in &after.links {
        if before.links.get(path) != Some(target) {
            out.push(HandoffFinding {
                path: path.clone(),
                kind: HandoffKind::Link {
                    target: target.clone(),
                },
            });
        }
    }
    for path in after.repositories.difference(&before.repositories) {
        out.push(HandoffFinding {
            path: path.clone(),
            kind: HandoffKind::Repository,
        });
    }
    out.sort();
    out.dedup();
    (out, before.complete && after.complete)
}

/// A cage's audits: built once, run for every spawn.
#[derive(Debug)]
pub(crate) struct CageAudit {
    mode: LinkAudit,
    targets: Targets,
    /// With the handoff audit: the writable trees, the handoff names in any
    /// directory, and the handoff paths in the homes.
    handoff: Option<(Vec<PathBuf>, Vec<String>, Vec<PathBuf>)>,
    limit: usize,
}

impl CageAudit {
    pub(crate) fn new(
        mode: LinkAudit,
        targets: Targets,
        handoff: Option<(Vec<PathBuf>, Vec<String>, Vec<PathBuf>)>,
        limit: usize,
    ) -> CageAudit {
        CageAudit {
            mode,
            targets,
            handoff,
            limit,
        }
    }

    /// The link check of one spawn, the last thing before the fork: `Err`
    /// with the findings when the mode refuses them.
    pub(crate) fn before_spawn(self: &std::sync::Arc<Self>) -> Result<RunAudit, Vec<LinkFinding>> {
        let links = match self.mode {
            // Nothing was examined, so nothing is known to be clean.
            LinkAudit::Off => LinkResult::default(),
            _ => links(&self.targets, self.limit),
        };
        if self.mode == LinkAudit::Refuse && !links.findings.is_empty() {
            return Err(links.findings);
        }
        let before = self
            .handoff
            .as_ref()
            .map(|(trees, anywhere, home)| Snapshot::take(trees, anywhere, home, self.limit));
        Ok(RunAudit {
            cage: self.clone(),
            links,
            before,
        })
    }
}

/// One run's audits.
#[derive(Debug)]
pub(crate) struct RunAudit {
    cage: std::sync::Arc<CageAudit>,
    links: LinkResult,
    before: Option<Snapshot>,
}

impl RunAudit {
    /// The audit of the run (the handoff audit walks again now). `ended`:
    /// every process of the run is gone; otherwise the handoff result is
    /// incomplete, since a survivor may still write.
    pub(crate) fn finish(&self, ended: bool) -> Audit {
        let (handoff, handoff_complete, handoff_visited) = match (&self.before, &self.cage.handoff)
        {
            (Some(before), Some((trees, anywhere, home))) => {
                let after = Snapshot::take(trees, anywhere, home, self.cage.limit);
                let (found, complete) = handoff(before, &after);
                (
                    Some(found),
                    complete && ended,
                    before.visited + after.visited,
                )
            }
            _ => (None, true, 0),
        };
        Audit {
            mode: self.cage.mode,
            links: self.links.findings.clone(),
            links_complete: self.links.complete,
            links_visited: self.links.visited,
            handoff,
            handoff_complete,
            handoff_visited,
        }
    }
}

/// The message of a refused spawn.
pub(crate) fn refusal(findings: &[LinkFinding]) -> String {
    let list: Vec<String> = findings.iter().map(ToString::to_string).collect();
    format!(
        "a protected, hidden or class file has another name, which path rules do not cover: {}; \
         remove the extra name, or choose LinkAudit::Report or LinkAudit::Off by name",
        list.join(", ")
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("procage-audit-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        std::fs::canonicalize(&d).unwrap()
    }

    #[test]
    fn a_second_name_is_found_from_the_protected_side() {
        let d = scratch("links");
        std::fs::create_dir_all(d.join("secret")).unwrap();
        std::fs::write(d.join("secret/key"), "k").unwrap();
        std::fs::write(d.join("secret/alone"), "a").unwrap();
        std::fs::hard_link(d.join("secret/key"), d.join("alias")).unwrap();
        let targets = Targets {
            trees: vec![(d.join("secret"), true)],
            ..Targets::default()
        };
        let r = links(&targets, 100);
        assert!(r.complete);
        assert_eq!(r.findings.len(), 1, "{:?}", r.findings);
        assert_eq!(r.findings[0].path, d.join("secret/key"));
        assert_eq!(r.findings[0].links, 2);
        let r = links(&targets, 1);
        assert!(!r.complete, "past the limit");
        // Both names inside the protected set (a lock file and its link)
        // give nothing away.
        std::fs::hard_link(d.join("secret/alone"), d.join("secret/.lock")).unwrap();
        let r = links(&targets, 100);
        assert_eq!(r.findings.len(), 1, "{:?}", r.findings);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn a_literal_target_that_became_a_link_is_a_finding() {
        let d = scratch("symlink");
        std::fs::write(d.join("real"), "r").unwrap();
        std::os::unix::fs::symlink(d.join("real"), d.join("env")).unwrap();
        let targets = Targets {
            literal: vec![(d.join("env"), true), (d.join("missing"), true)],
            ..Targets::default()
        };
        let r = links(&targets, 100);
        assert_eq!(r.findings.len(), 1);
        assert!(r.findings[0].symbolic);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn what_a_run_left_behind_is_listed_once() {
        let d = scratch("handoff");
        std::fs::create_dir_all(d.join(".vscode")).unwrap();
        std::fs::write(d.join(".vscode/settings.json"), "{}").unwrap();
        let anywhere = vec![".vscode".to_string(), ".git/hooks".to_string()];
        let before = Snapshot::take(std::slice::from_ref(&d), &anywhere, &[], 1000);
        std::thread::sleep(std::time::Duration::from_millis(20));
        std::fs::write(d.join(".vscode/settings.json"), "{\"x\":1}").unwrap();
        std::fs::write(d.join(".vscode/tasks.json"), "{}").unwrap();
        std::fs::create_dir_all(d.join("sub/.git/hooks")).unwrap();
        std::fs::write(d.join("sub/.git/hooks/pre-commit"), "#!/bin/sh").unwrap();
        std::os::unix::fs::symlink("/etc/passwd", d.join("build")).unwrap();
        std::fs::write(d.join("plain.txt"), "x").unwrap();
        let after = Snapshot::take(std::slice::from_ref(&d), &anywhere, &[], 1000);
        let (found, complete) = handoff(&before, &after);
        assert!(complete);
        let has =
            |p: &str, k: &HandoffKind| found.iter().any(|f| f.path == d.join(p) && &f.kind == k);
        assert!(
            has(".vscode/settings.json", &HandoffKind::Modified),
            "{found:?}"
        );
        assert!(
            has(".vscode/tasks.json", &HandoffKind::Created),
            "{found:?}"
        );
        assert!(
            has("sub/.git/hooks/pre-commit", &HandoffKind::Created),
            "{found:?}"
        );
        assert!(has("sub/.git", &HandoffKind::Repository), "{found:?}");
        assert!(
            has(
                "build",
                &HandoffKind::Link {
                    target: PathBuf::from("/etc/passwd")
                }
            ),
            "{found:?}"
        );
        assert!(
            !found.iter().any(|f| f.path == d.join("plain.txt")),
            "{found:?}"
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    /// A hidden file whose second name lies in a protected (readable) tree is
    /// a finding; both names in hidden trees are not.
    #[test]
    fn a_hidden_file_needs_every_name_hidden() {
        let d = scratch("strict");
        for dir in ["hidden", "protected", "hidden2"] {
            std::fs::create_dir_all(d.join(dir)).unwrap();
        }
        std::fs::write(d.join("hidden/key"), "k").unwrap();
        std::fs::hard_link(d.join("hidden/key"), d.join("protected/key")).unwrap();
        let targets = Targets {
            trees: vec![(d.join("hidden"), true), (d.join("protected"), false)],
            ..Targets::default()
        };
        assert_eq!(links(&targets, 100).findings.len(), 1);
        std::fs::remove_file(d.join("protected/key")).unwrap();
        std::fs::hard_link(d.join("hidden/key"), d.join("hidden2/key")).unwrap();
        let targets = Targets {
            trees: vec![(d.join("hidden"), true), (d.join("hidden2"), true)],
            ..Targets::default()
        };
        assert!(links(&targets, 100).findings.is_empty());
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Walks never follow a link (a loop, or one out of the tree) and mark
    /// an unreadable directory incomplete.
    #[test]
    fn walks_stay_put_and_say_what_they_could_not_read() {
        use std::os::unix::fs::PermissionsExt;
        let d = scratch("walk");
        std::fs::create_dir_all(d.join("t/sub")).unwrap();
        std::os::unix::fs::symlink(d.join("t"), d.join("t/sub/loop")).unwrap();
        std::os::unix::fs::symlink("/", d.join("t/out")).unwrap();
        let targets = Targets {
            trees: vec![(d.join("t"), false)],
            ..Targets::default()
        };
        let r = links(&targets, 1000);
        assert!(r.complete);
        assert!(r.visited < 10, "followed a link: {}", r.visited);
        std::fs::create_dir_all(d.join("t/closed")).unwrap();
        std::fs::set_permissions(d.join("t/closed"), std::fs::Permissions::from_mode(0o0)).unwrap();
        let unreadable = std::fs::read_dir(d.join("t/closed")).is_err();
        let r = links(&targets, 1000);
        std::fs::set_permissions(d.join("t/closed"), std::fs::Permissions::from_mode(0o755))
            .unwrap();
        if unreadable {
            assert!(!r.complete, "an unreadable directory is incomplete");
        }
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Refuse fails only on findings: an incomplete check with none lets the
    /// spawn run and says it was incomplete; Off says nothing is known.
    #[test]
    fn incomplete_is_never_clean_and_never_a_refusal() {
        let d = scratch("incomplete");
        std::fs::create_dir_all(d.join("t")).unwrap();
        for i in 0..5 {
            std::fs::write(d.join(format!("t/{i}")), "x").unwrap();
        }
        let targets = Targets {
            trees: vec![(d.join("t"), true)],
            ..Targets::default()
        };
        let cage = std::sync::Arc::new(CageAudit::new(LinkAudit::Refuse, targets.clone(), None, 2));
        let run = cage.before_spawn().expect("no finding, no refusal");
        assert!(!run.finish(true).links_complete);
        let off = std::sync::Arc::new(CageAudit::new(LinkAudit::Off, targets, None, 2));
        assert!(!off.before_spawn().unwrap().finish(true).links_complete);
        let _ = std::fs::remove_dir_all(&d);
    }

    /// A rewrite of the same size with the modification time set back is
    /// still a change: the change time cannot be set back.
    #[test]
    fn a_disguised_rewrite_is_modified() {
        let d = scratch("disguise");
        std::fs::create_dir_all(d.join(".vscode")).unwrap();
        let file = d.join(".vscode/settings.json");
        std::fs::write(&file, "aaaa").unwrap();
        let mtime = std::fs::metadata(&file).unwrap().modified().unwrap();
        let anywhere = vec![".vscode".to_string()];
        let before = Snapshot::take(std::slice::from_ref(&d), &anywhere, &[], 100);
        std::thread::sleep(std::time::Duration::from_millis(20));
        std::fs::write(&file, "bbbb").unwrap();
        std::fs::File::options()
            .write(true)
            .open(&file)
            .unwrap()
            .set_modified(mtime)
            .unwrap();
        let after = Snapshot::take(std::slice::from_ref(&d), &anywhere, &[], 100);
        let (found, _) = handoff(&before, &after);
        assert!(
            found
                .iter()
                .any(|f| f.path == file && f.kind == HandoffKind::Modified),
            "{found:?}"
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    /// The refusal names every file with its link count and the remedies.
    #[test]
    fn the_refusal_names_every_file_and_the_way_out() {
        let found = [
            LinkFinding {
                path: PathBuf::from("/w/.env"),
                links: 2,
                symbolic: false,
            },
            LinkFinding {
                path: PathBuf::from("/home/u/.ssh/id"),
                links: 3,
                symbolic: false,
            },
        ];
        let text = refusal(&found);
        assert!(text.contains("/w/.env has 2 names"), "{text}");
        assert!(text.contains("/home/u/.ssh/id has 3 names"), "{text}");
        assert!(
            text.contains("LinkAudit::Report") && text.contains("LinkAudit::Off"),
            "{text}"
        );
    }

    /// A credential file of a class (hidden) with a name outside, and a file
    /// under a glob target with one, are findings; multi-link files that are
    /// no target are none of the check's business.
    #[test]
    fn class_files_and_globs_are_examined_and_nothing_else() {
        let d = scratch("classes");
        std::fs::create_dir_all(d.join("home/.ssh")).unwrap();
        std::fs::create_dir_all(d.join("ws/conf")).unwrap();
        std::fs::write(d.join("home/.ssh/id"), "k").unwrap();
        std::fs::hard_link(d.join("home/.ssh/id"), d.join("ws/id")).unwrap();
        std::fs::write(d.join("ws/conf/app.toml"), "x").unwrap();
        std::fs::hard_link(d.join("ws/conf/app.toml"), d.join("ws/app-alias")).unwrap();
        std::fs::write(d.join("ws/plain"), "x").unwrap();
        std::fs::hard_link(d.join("ws/plain"), d.join("ws/plain2")).unwrap();
        let classes = class_paths(&[d.join("home")], &[".ssh"], &[], true);
        let pattern = format!("{}/ws/**/*.toml", d.display());
        let targets = Targets {
            classes,
            globs: vec![(d.join("ws"), pattern, false)],
            ..Targets::default()
        };
        assert_eq!(
            glob_match("/a/**/*.toml", Path::new("/a/b/c.toml")),
            Some(true)
        );
        assert_eq!(
            glob_match("/a/**/*.toml", Path::new("/a/c.toml")),
            Some(true)
        );
        assert_eq!(
            glob_match("/a/**/*.toml", Path::new("/a/app-alias")),
            Some(false)
        );
        assert_eq!(glob_match("/a/?.rs", Path::new("/a/x.rs")), Some(true));
        assert_eq!(glob_match("/a/\\*", Path::new("/a/x")), Some(false));
        assert_eq!(glob_match("/a/[ab]", Path::new("/a/a")), None);
        let r = links(&targets, 1000);
        let paths: Vec<&PathBuf> = r.findings.iter().map(|f| &f.path).collect();
        assert!(paths.contains(&&d.join("home/.ssh/id")), "{paths:?}");
        assert!(paths.contains(&&d.join("ws/conf/app.toml")), "{paths:?}");
        assert!(
            !paths
                .iter()
                .any(|p| p.ends_with("plain") || p.ends_with("plain2")),
            "{paths:?}"
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn control_characters_are_escaped_in_messages() {
        let f = LinkFinding {
            path: PathBuf::from("/w/a\nb"),
            links: 2,
            symbolic: false,
        };
        assert_eq!(f.to_string(), "/w/a\\nb has 2 names");
    }
}
