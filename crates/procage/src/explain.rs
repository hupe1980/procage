//! What both backends share for `Cage::explain`: the lazily built explainer
//! and resolving a question's path on the host.

use std::io;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use procage_policy::explain::{Context, Explainer, Op, Question};
use procage_policy::{AbsPath, GrantName, LowerError, LowerOptions, Policy, Target};

/// The explainer of a cage, built on the first question.
#[derive(Debug)]
pub(crate) struct Lazy {
    policy: Policy,
    target: Target,
    options: LowerOptions,
    cell: OnceLock<Result<Explainer, LowerError>>,
}

impl Lazy {
    pub(crate) fn new(policy: Policy, target: Target, options: LowerOptions) -> Self {
        Self {
            policy,
            target,
            options,
            cell: OnceLock::new(),
        }
    }

    pub(crate) fn get(&self) -> Result<&Explainer, LowerError> {
        self.cell
            .get_or_init(|| Explainer::new(&self.policy, self.target, &self.options))
            .as_ref()
            .map_err(Clone::clone)
    }
}

fn abs(path: &Path) -> io::Result<AbsPath> {
    AbsPath::new(path.as_os_str().as_bytes())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))
}

/// The question about `op` on `path`: every symbolic link resolved (the
/// path itself if it exists, else its resolved parent and its name), and
/// the file's mode if it exists.
pub(crate) fn question(op: Op, path: &Path) -> io::Result<Question> {
    use std::os::unix::fs::PermissionsExt;
    let resolved = match std::fs::canonicalize(path) {
        Ok(p) => p,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            let (Some(parent), Some(name)) = (path.parent(), path.file_name()) else {
                return Err(e);
            };
            std::fs::canonicalize(parent)?.join(name)
        }
        Err(e) => return Err(e),
    };
    let mode = std::fs::metadata(&resolved)
        .ok()
        .map(|m| m.permissions().mode());
    let question = Question::new(op, resolved.as_os_str().as_bytes());
    Ok(match mode {
        Some(mode) => question.with_mode(mode),
        None => question,
    })
}

/// The context of a spawn with `grants` already resolved, and `homes`.
pub(crate) fn context(
    grants: impl IntoIterator<Item = (String, PathBuf)>,
    homes: &[PathBuf],
) -> io::Result<Context> {
    let mut context = Context::default();
    for (name, path) in grants {
        let name = GrantName::new(&name)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;
        context.grants.push((name, abs(&path)?));
    }
    for home in homes {
        context.homes.push(abs(home)?);
    }
    Ok(context)
}
