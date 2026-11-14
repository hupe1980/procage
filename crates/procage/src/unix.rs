//! Spawn preparation shared by the macOS and Linux backends: the
//! environment, the private temporary directory and resource limits.

use std::ffi::OsString;
use std::io;
use std::os::fd::OwnedFd;
use std::path::PathBuf;
use std::process::{Command, Stdio};

use procage_policy::{EnvPolicy, Rlimits};

/// Sets the command's environment to what the policy yields (see
/// [`crate::hygiene::environment`]); returns the names the passthrough
/// denylist dropped.
///
/// When the command called `env_clear`, no variable of the caller is
/// passed, whatever the policy. `Err` when that cannot be observed and the
/// policy passes the caller's environment through.
pub(crate) fn environment(
    command: &mut Command,
    policy: &EnvPolicy,
) -> Result<Vec<String>, EnvClearUnobservable> {
    let cleared = decide(observer_works(), cleared(command), policy)?;
    let explicit: Vec<(OsString, Option<OsString>)> = command
        .get_envs()
        .map(|(k, v)| (k.to_owned(), v.map(|v| v.to_owned())))
        .collect();
    let caller: Vec<(OsString, OsString)> = if cleared {
        Vec::new()
    } else {
        std::env::vars_os().collect()
    };
    let decision = crate::hygiene::environment(caller, policy, &explicit);
    command.env_clear();
    command.envs(decision.set);
    Ok(decision.dropped)
}

/// Passthrough was asked for, but whether the command called `env_clear`
/// cannot be observed with this standard library.
#[derive(Debug)]
pub(crate) struct EnvClearUnobservable;

/// Whether to drop the caller's environment, given whether the observer
/// passed its check and what it saw.
fn decide(
    works: bool,
    seen: Option<bool>,
    policy: &EnvPolicy,
) -> Result<bool, EnvClearUnobservable> {
    match (works, seen) {
        (true, Some(cleared)) => Ok(cleared),
        // An allowlist passes only variables the policy names.
        _ if matches!(policy, EnvPolicy::Allowlist(_)) => Ok(false),
        _ => Err(EnvClearUnobservable),
    }
}

/// Whether `command` had `env_clear` called, read from std's alternate
/// `Debug` output (std has no getter): the line after `env: CommandEnv {`
/// is `clear: true,` or `clear: false,`, and the `env` field is absent when
/// the environment was not changed. Strings print quoted and escaped on one
/// line, so arguments and values cannot fake those lines. `None` when the
/// output does not have that shape.
fn cleared(command: &Command) -> Option<bool> {
    observe(&format!("{command:#?}"))
}

fn observe(text: &str) -> Option<bool> {
    let mut lines = text.lines().map(str::trim);
    while let Some(line) = lines.next() {
        if line == "env: CommandEnv {" {
            return match lines.next() {
                Some("clear: true,") => Some(true),
                Some("clear: false,") => Some(false),
                _ => None,
            };
        }
    }
    Some(false)
}

/// Whether the observer reads std's formatting correctly, checked once per
/// process on a cleared, a changed and an unchanged command.
fn observer_works() -> bool {
    static WORKS: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *WORKS.get_or_init(|| {
        let mut cleared_cmd = Command::new("procage-probe");
        cleared_cmd.env_clear().env("A", "1");
        let mut changed = Command::new("procage-probe");
        changed.env("A", "1");
        let unchanged = Command::new("procage-probe");
        cleared(&cleared_cmd) == Some(true)
            && cleared(&changed) == Some(false)
            && cleared(&unchanged) == Some(false)
    })
}

/// Checks, as `execvp` will search, that `command`'s program exists as an
/// executable file, so `Cage::exec` can refuse before confining the
/// calling process. Call it after the environment is final: the search uses
/// the command's `PATH` (else `/usr/bin:/bin`, the default of `execvp`).
pub(crate) fn find_program(command: &Command) -> io::Result<PathBuf> {
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::PermissionsExt;
    let program = command.get_program();
    let executable = |p: &std::path::Path| {
        std::fs::metadata(p).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
    };
    let not_found = |searched: &str| {
        io::Error::new(
            io::ErrorKind::NotFound,
            format!(
                "program {} not found{searched}",
                std::path::Path::new(program).display()
            ),
        )
    };
    if program.as_bytes().contains(&b'/') {
        let path = match command.get_current_dir() {
            Some(dir) => dir.join(program),
            None => PathBuf::from(program),
        };
        return if executable(&path) {
            Ok(path)
        } else {
            Err(not_found(""))
        };
    }
    let set = command
        .get_envs()
        .find(|(k, _)| *k == "PATH")
        .and_then(|(_, v)| v.map(OsString::from));
    let searched = match &set {
        Some(path) => format!(" in PATH {}", path.to_string_lossy()),
        None => " in /usr/bin:/bin (the command's environment has no PATH: set one on the \
                  command, or name the program by its path)"
            .to_owned(),
    };
    let path = set.unwrap_or_else(|| OsString::from("/usr/bin:/bin"));
    std::env::split_paths(&path)
        .map(|dir| dir.join(program))
        .find(|p| executable(p))
        .ok_or_else(|| not_found(&searched))
}

/// The bytes read from the start of a program to find out what it is.
const PROGRAM_HEAD: u64 = 64 * 1024;

/// What a spawn under `Exec::Never` or `Exec::Program` may execute: the
/// program, as `execvp` finds it, and on Linux the ELF interpreter the
/// kernel loads for it.
#[derive(Debug, Clone)]
pub(crate) struct Allowance {
    /// The program, canonical.
    pub(crate) program: PathBuf,
    /// Its ELF interpreter, canonical (Linux; `None` for a static program).
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub(crate) interpreter: Option<PathBuf>,
}

/// Why a program cannot be the one a run may execute.
#[derive(Debug)]
pub(crate) enum AllowanceError {
    /// Not found, or not readable.
    Io(io::Error),
    /// A script (`#!`): allowing its interpreter would allow every script.
    Script(PathBuf),
    /// Its ELF interpreter cannot be used.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    Interpreter(PathBuf, String),
}

/// The allowance for `command`'s program. Call it after the environment is
/// final: the search uses the command's `PATH`, as [`find_program`] does.
pub(crate) fn program_allowance(command: &Command) -> Result<Allowance, AllowanceError> {
    use std::io::Read;
    let program = std::fs::canonicalize(find_program(command).map_err(AllowanceError::Io)?)
        .map_err(AllowanceError::Io)?;
    let mut head = Vec::new();
    std::fs::File::open(&program)
        .and_then(|f| f.take(PROGRAM_HEAD).read_to_end(&mut head))
        .map_err(AllowanceError::Io)?;
    if head.starts_with(b"#!") {
        return Err(AllowanceError::Script(program));
    }
    #[cfg(target_os = "linux")]
    let interpreter = linux_interpreter(&program, &head)?;
    #[cfg(not(target_os = "linux"))]
    let interpreter = None;
    Ok(Allowance {
        program,
        interpreter,
    })
}

/// The canonical ELF interpreter of `program`, whose first bytes are `head`.
#[cfg(target_os = "linux")]
fn linux_interpreter(
    program: &std::path::Path,
    head: &[u8],
) -> Result<Option<PathBuf>, AllowanceError> {
    use std::os::unix::ffi::OsStrExt;
    let bad = |reason: String| AllowanceError::Interpreter(program.to_owned(), reason);
    let Some(raw) = procage_policy::elf::interpreter(head).map_err(|e| bad(e.to_string()))? else {
        return Ok(None);
    };
    let named = std::path::Path::new(std::ffi::OsStr::from_bytes(raw));
    if !named.is_absolute() {
        return Err(bad(format!(
            "interpreter {} is not absolute",
            named.display()
        )));
    }
    let path = std::fs::canonicalize(named)
        .map_err(|e| bad(format!("interpreter {}: {e}", named.display())))?;
    if !std::fs::metadata(&path).is_ok_and(|m| m.is_file()) {
        return Err(bad(format!("interpreter {} is not a file", path.display())));
    }
    Ok(Some(path))
}

/// A fresh directory, accessible only to the user, under the caller's
/// temporary directory.
pub(crate) fn private_tmpdir() -> io::Result<PathBuf> {
    use std::os::unix::fs::DirBuilderExt;
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let base = std::fs::canonicalize(std::env::temp_dir())?;
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.subsec_nanos());
    let dir = base.join(format!(
        "procage-{}-{}-{nanos}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::DirBuilder::new().mode(0o700).create(&dir)?;
    Ok(dir)
}

/// The `setrlimit` calls for the policy's limits. The core size is always
/// set (0 by default).
pub(crate) fn limits(limits: &Rlimits) -> Vec<(libc::c_int, u64, u64)> {
    let mut out = Vec::new();
    for (resource, value) in [
        (libc::RLIMIT_NPROC, limits.nproc),
        (libc::RLIMIT_CPU, limits.cpu_seconds),
        (libc::RLIMIT_FSIZE, limits.fsize_bytes),
        (libc::RLIMIT_NOFILE, limits.nofile),
        (libc::RLIMIT_CORE, Some(limits.core_bytes)),
    ] {
        if let Some(value) = value {
            // The resource constants are `u32` on glibc and `i32` elsewhere.
            #[allow(clippy::unnecessary_cast)]
            out.push((resource as libc::c_int, value, value));
        }
    }
    out
}

/// Makes `device` (a new terminal's other end) the command's standard
/// input, output and error, each a close-on-exec duplicate.
pub(crate) fn terminal_stdio(command: &mut Command, device: &OwnedFd) -> io::Result<()> {
    command
        .stdin(Stdio::from(device.try_clone()?))
        .stdout(Stdio::from(device.try_clone()?))
        .stderr(Stdio::from(device.try_clone()?));
    Ok(())
}

/// Drops the command's standard streams (closing the parent's copies of a
/// terminal set by [`terminal_stdio`]).
pub(crate) fn release_stdio(command: &mut Command) {
    command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
}

/// One spawn's child sequence on a `Command`. std keeps every `pre_exec`
/// closure a command was given, so spawning it again would run the
/// sequences of its earlier spawns first (and fail at the second `setsid`).
/// Dropped once the spawn (or exec) returned, this marks its sequence
/// spent: later children skip it. It must live until then.
pub(crate) struct Installed(std::sync::Arc<std::sync::atomic::AtomicBool>);

impl Installed {
    /// The guard, and the check its sequence makes first: `true` when spent.
    pub(crate) fn new() -> (Installed, impl Fn() -> bool + Send + Sync + 'static) {
        let spent = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let check = spent.clone();
        (Installed(spent), move || {
            check.load(std::sync::atomic::Ordering::Acquire)
        })
    }
}

impl Drop for Installed {
    fn drop(&mut self) {
        self.0.store(true, std::sync::atomic::Ordering::Release);
    }
}

/// The grant name procage binds to a private temporary directory.
pub const TMPDIR_GRANT: &str = "tmpdir";

/// Removes a private temporary directory unless the spawn succeeded.
pub(crate) struct TmpdirGuard(pub(crate) Option<PathBuf>);

impl TmpdirGuard {
    pub(crate) fn disarm(mut self) -> Option<PathBuf> {
        self.0.take()
    }
}

impl Drop for TmpdirGuard {
    fn drop(&mut self) {
        if let Some(dir) = self.0.take() {
            let _ = std::fs::remove_dir_all(dir);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn programs_are_found_as_execvp_finds_them() {
        let mut c = Command::new("sh");
        c.env("PATH", "/nonexistent:/bin");
        assert_eq!(find_program(&c).unwrap(), PathBuf::from("/bin/sh"));
        let mut c = Command::new("procage-no-such-program");
        c.env("PATH", "/bin:/usr/bin");
        let err = find_program(&c).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
        assert!(err.to_string().contains("procage-no-such-program"), "{err}");
        assert!(find_program(&Command::new("/bin/sh")).is_ok());
        assert!(find_program(&Command::new("/etc/hosts")).is_err());
        let mut c = Command::new("./sh");
        c.current_dir("/bin");
        assert!(find_program(&c).is_ok());
        // Without PATH in the environment, the execvp default applies.
        let mut c = Command::new("sh");
        c.env_clear();
        assert!(find_program(&c).is_ok());
    }

    #[test]
    fn a_program_is_allowed_and_a_script_is_not() {
        let a = program_allowance(&Command::new("/bin/sh")).unwrap();
        assert!(a.program.is_absolute());
        #[cfg(target_os = "linux")]
        if let Some(i) = &a.interpreter {
            assert!(i.is_absolute() && i.is_file(), "{}", i.display());
        }
        let dir = std::env::temp_dir().join(format!("procage-script-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let script = dir.join("s");
        std::fs::write(&script, "#!/bin/sh\nexit 0\n").unwrap();
        std::fs::set_permissions(&script, std::os::unix::fs::PermissionsExt::from_mode(0o755))
            .unwrap();
        let err = program_allowance(&Command::new(&script)).unwrap_err();
        assert!(matches!(err, AllowanceError::Script(_)), "{err:?}");
        let _ = std::fs::remove_dir_all(dir);
        let err = program_allowance(&Command::new("procage-no-such-program")).unwrap_err();
        assert!(matches!(err, AllowanceError::Io(_)), "{err:?}");
    }

    #[test]
    fn the_observer_works_with_this_std() {
        assert!(observer_works());
    }

    #[test]
    fn values_cannot_fake_a_clear() {
        let mut c = Command::new("p");
        c.arg("\n        clear: true,\n")
            .arg("env: CommandEnv {")
            .env("V", "env: CommandEnv {\nclear: true,");
        assert_eq!(cleared(&c), Some(false));
        c.env_clear();
        assert_eq!(cleared(&c), Some(true));
        let mut d = Command::new("env: CommandEnv {\n    clear: true,");
        d.current_dir("/tmp/env: CommandEnv {\nclear: true,");
        assert_eq!(cleared(&d), Some(false));
    }

    #[test]
    fn an_unexpected_shape_is_unknown() {
        assert_eq!(observe("env: CommandEnv {\n  cleared: yes,"), None);
        assert_eq!(observe("Command {\n}"), Some(false));
    }

    #[test]
    fn the_decision_fails_closed_only_for_passthrough() {
        let pass = EnvPolicy::Passthrough { deny: vec![] };
        let allow = EnvPolicy::Allowlist(vec!["PATH".into()]);
        assert!(decide(true, Some(true), &pass).unwrap());
        assert!(!decide(true, Some(false), &pass).unwrap());
        assert!(decide(false, Some(false), &pass).is_err());
        assert!(decide(true, None, &pass).is_err());
        assert!(!decide(false, Some(true), &allow).unwrap());
        assert!(decide(true, Some(true), &allow).unwrap());
    }
}

/// The process a run spawned, through std or through tokio.
#[derive(Debug)]
pub(crate) enum Proc {
    Std(std::process::Child),
    /// tokio's child is not unwind safe, which would take `UnwindSafe` from
    /// `Child` once the feature is on anywhere in a build; the handle keeps
    /// no invariant a panic could break.
    #[cfg(feature = "tokio")]
    Tokio(std::panic::AssertUnwindSafe<tokio::process::Child>),
}

impl Proc {
    /// The pid of a process that has not been waited for yet.
    pub(crate) fn pid(&self) -> u32 {
        match self {
            Proc::Std(c) => c.id(),
            #[cfg(feature = "tokio")]
            Proc::Tokio(c) => c
                .id()
                .unwrap_or_else(|| unreachable!("a child not yet waited for has a pid")),
        }
    }

    pub(crate) fn try_wait(&mut self) -> io::Result<Option<std::process::ExitStatus>> {
        match self {
            Proc::Std(c) => c.try_wait(),
            #[cfg(feature = "tokio")]
            Proc::Tokio(c) => c.try_wait(),
        }
    }

    /// Whether the process was not reaped yet. One reaped elsewhere (the
    /// caller ignores `SIGCHLD`, or waits for any child) reads as exited,
    /// so its session and group still die with the run.
    pub(crate) fn running(&mut self) -> io::Result<bool> {
        match self.try_wait() {
            Ok(status) => Ok(status.is_none()),
            Err(e) if e.raw_os_error() == Some(libc::ECHILD) => Ok(false),
            Err(e) => Err(e),
        }
    }

    /// Waits for the process, blocking. A tokio child is polled (it may not
    /// be waited for twice); only the end of a run calls this, after the
    /// run's processes were killed.
    pub(crate) fn wait(&mut self) -> io::Result<std::process::ExitStatus> {
        match self {
            Proc::Std(c) => c.wait(),
            #[cfg(feature = "tokio")]
            Proc::Tokio(c) => loop {
                if let Some(status) = c.try_wait()? {
                    return Ok(status);
                }
                std::thread::sleep(std::time::Duration::from_millis(1));
            },
        }
    }
}
