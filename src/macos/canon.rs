//! Path resolution: every policy path to the spelling the kernel matches.
//!
//! macOS reaches `/tmp`, `/etc` and `/var` through symlinks into `/private`,
//! and the data volume through firmlinks. The Sandbox kernel extension
//! matches the resolved path, so a rule written with another spelling never
//! matches. Each path is resolved here before lowering, and every rewrite is
//! recorded.
//!
//! The child still opens paths in the spelling its caller uses, and looking
//! up `/tmp/x` needs permission to read the symlink `/tmp` itself. So every
//! symlink a policy path passes through, and the root symlinks `/tmp`, `/var`
//! and `/etc` (for grants bound later), get `file-read-metadata`: the link,
//! not what it points to.

use std::ffi::OsStr;
use std::io;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use procage_policy::seatbelt::{Effect, Filter, Layer, Operation, Rule};
use procage_policy::{AbsPath, FsTarget, Glob, Policy};

use super::{PathRewrite, SpawnError};

const DATA_VOLUME: &[u8] = b"/System/Volumes/Data";

/// The symlinks at the root of a macOS system volume.
const ROOT_LINKS: &[&str] = &["/etc", "/tmp", "/var"];

/// The symlinks a lookup of `path` passes through, in the spelling the
/// kernel sees each of them (with the components before it resolved).
fn links_on(path: &Path) -> Vec<PathBuf> {
    let mut links = Vec::new();
    let mut current = PathBuf::from("/");
    for component in path.components().skip(1) {
        let next = current.join(component);
        match std::fs::symlink_metadata(&next) {
            Ok(meta) if meta.file_type().is_symlink() => {
                links.push(next.clone());
                match std::fs::canonicalize(&next) {
                    Ok(resolved) => current = resolved,
                    Err(_) => break,
                }
            }
            Ok(_) => current = next,
            Err(_) => break,
        }
    }
    links
}

fn as_path(p: &AbsPath) -> &Path {
    Path::new(OsStr::from_bytes(p.as_bytes()))
}

fn same_file(a: &Path, b: &Path) -> bool {
    match (std::fs::metadata(a), std::fs::metadata(b)) {
        (Ok(a), Ok(b)) => a.dev() == b.dev() && a.ino() == b.ino(),
        _ => false,
    }
}

/// The firmlink-visible spelling of a resolved path under the data volume.
fn visible(resolved: PathBuf) -> PathBuf {
    let bytes = resolved.as_os_str().as_bytes();
    if let Some(rest) = bytes.strip_prefix(DATA_VOLUME)
        && rest.first() == Some(&b'/')
    {
        let candidate = PathBuf::from(OsStr::from_bytes(rest));
        if same_file(&candidate, &resolved) {
            return candidate;
        }
    }
    resolved
}

/// Resolves the longest existing leading part of `path` and keeps the rest
/// byte-exact.
pub(crate) fn resolve(path: &AbsPath) -> io::Result<AbsPath> {
    let mut existing = as_path(path).to_path_buf();
    let mut rest: Vec<Vec<u8>> = Vec::new();
    let resolved = loop {
        match std::fs::canonicalize(&existing) {
            Ok(resolved) => break resolved,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                let name = existing
                    .file_name()
                    .map(|n| n.as_bytes().to_vec())
                    .ok_or(e)?;
                rest.push(name);
                existing.pop();
            }
            Err(e) => return Err(e),
        }
    };
    let mut out = visible(resolved).into_os_string().into_vec();
    for name in rest.iter().rev() {
        if out != b"/" {
            out.push(b'/');
        }
        out.extend_from_slice(name);
    }
    AbsPath::new(out).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

/// Resolves an existing path completely (for grants).
pub(crate) fn resolve_existing(path: &Path) -> io::Result<AbsPath> {
    let resolved = visible(std::fs::canonicalize(path)?);
    AbsPath::new(resolved.into_os_string().into_vec())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

fn escape_glob(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        if matches!(c, '\\' | '*' | '?' | '[' | ']' | '{' | '}') {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

/// Whether a glob component contains an unescaped wildcard.
fn has_wildcard(component: &str) -> bool {
    let mut chars = component.chars();
    while let Some(c) = chars.next() {
        match c {
            '\\' => {
                chars.next();
            }
            '*' | '?' => return true,
            _ => {}
        }
    }
    false
}

fn unescape(component: &str) -> String {
    let mut out = String::new();
    let mut chars = component.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            if let Some(next) = chars.next() {
                out.push(next);
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// Resolves the fixed leading part of a glob, before its first wildcard
/// component, and escapes any glob character in the resolved spelling.
pub(crate) fn resolve_glob(glob: &Glob) -> Result<Glob, SpawnError> {
    let source = glob.as_str();
    let components: Vec<&str> = source[1..].split('/').collect();
    let split = components
        .iter()
        .position(|c| has_wildcard(c))
        .unwrap_or(components.len().saturating_sub(1));
    if split == 0 {
        return Ok(glob.clone());
    }
    let prefix: String = components[..split]
        .iter()
        .map(|c| format!("/{}", unescape(c)))
        .collect();
    let prefix_path = AbsPath::new(prefix.as_bytes()).map_err(|e| SpawnError::Path {
        path: prefix.clone(),
        error: io::Error::new(io::ErrorKind::InvalidInput, e),
    })?;
    let resolved = resolve(&prefix_path).map_err(|error| SpawnError::Path {
        path: prefix,
        error,
    })?;
    let Some(text) = resolved.to_str() else {
        // A non-UTF-8 resolved prefix cannot be part of a glob; keep the
        // glob as written so lowering reports it, rather than guessing.
        return Ok(glob.clone());
    };
    let mut out = if text == "/" {
        String::new()
    } else {
        escape_glob(text)
    };
    for c in &components[split..] {
        out.push('/');
        out.push_str(c);
    }
    Glob::new(&out).map_err(|e| SpawnError::Path {
        path: out.clone(),
        error: io::Error::new(io::ErrorKind::InvalidData, e),
    })
}

struct Resolver {
    rewrites: Vec<PathRewrite>,
    links: Vec<AbsPath>,
}

impl Resolver {
    fn path(&mut self, p: &AbsPath) -> Result<AbsPath, SpawnError> {
        let resolved = resolve(p).map_err(|error| SpawnError::Path {
            path: p.to_string(),
            error,
        })?;
        if resolved != *p {
            self.record(p.to_string(), resolved.to_string());
            self.links_of(as_path(p));
        }
        Ok(resolved)
    }

    fn links_of(&mut self, path: &Path) {
        for link in links_on(path) {
            if let Ok(link) = AbsPath::new(link.into_os_string().into_vec())
                && !self.links.contains(&link)
            {
                self.links.push(link);
            }
        }
    }

    fn glob(&mut self, g: &Glob) -> Result<Glob, SpawnError> {
        let resolved = resolve_glob(g)?;
        if resolved != *g {
            self.record(g.as_str().into(), resolved.as_str().into());
            let prefix: String = g.as_str()[1..]
                .split('/')
                .take_while(|c| !has_wildcard(c))
                .map(|c| format!("/{}", unescape(c)))
                .collect();
            self.links_of(Path::new(&prefix));
        }
        Ok(resolved)
    }

    fn record(&mut self, from: String, to: String) {
        let rewrite = PathRewrite { from, to };
        if !self.rewrites.contains(&rewrite) {
            self.rewrites.push(rewrite);
        }
    }
}

/// The policy with every macOS-relevant path resolved, and the rewrites.
pub(crate) fn resolve_policy(policy: &Policy) -> Result<(Policy, Vec<PathRewrite>), SpawnError> {
    let mut r = Resolver {
        rewrites: Vec::new(),
        links: Vec::new(),
    };
    let mut out = policy.clone();
    for rule in &mut out.fs {
        rule.target = match &rule.target {
            FsTarget::Literal(p) => FsTarget::Literal(r.path(p)?),
            FsTarget::Subpath(p) => FsTarget::Subpath(r.path(p)?),
            FsTarget::Glob(g) => FsTarget::Glob(r.glob(g)?),
        };
    }
    for p in &mut out.ipc.unix_sockets {
        *p = r.path(p)?;
    }
    if let Some(layer) = &mut out.seatbelt {
        for rule in &mut layer.rules {
            for filter in &mut rule.filters {
                *filter = match &*filter {
                    Filter::Literal(p) => Filter::Literal(r.path(p)?),
                    Filter::Subpath(p) => Filter::Subpath(r.path(p)?),
                    Filter::UnixSocket(p) => Filter::UnixSocket(r.path(p)?),
                    Filter::Glob(g) => Filter::Glob(r.glob(g)?),
                    other => other.clone(),
                };
            }
        }
    }
    for link in ROOT_LINKS {
        let link = AbsPath::new(*link).map_err(|e| SpawnError::Path {
            path: (*link).into(),
            error: io::Error::new(io::ErrorKind::InvalidInput, e),
        })?;
        if std::fs::symlink_metadata(as_path(&link)).is_ok_and(|m| m.file_type().is_symlink())
            && !r.links.contains(&link)
        {
            r.links.push(link);
        }
    }
    r.links.sort();
    let rule = Rule {
        effect: Effect::Allow,
        ops: vec![Operation::FileReadMetadata],
        filters: r.links.into_iter().map(Filter::Literal).collect(),
    };
    if !rule.filters.is_empty() {
        out.seatbelt
            .get_or_insert_with(Layer::default)
            .rules
            .push(rule);
    }
    Ok((out, r.rewrites))
}
