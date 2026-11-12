//! The native module of the `procage` Python package (`procage._native`).
//!
//! A thin layer over the Rust API: policies come only from the presets and
//! the versioned serialised format, every error becomes a typed exception,
//! the interpreter lock is released while procage spawns, waits or reads,
//! and dropping a run ends it. No Python code runs in the child: spawning is
//! procage's own child sequence.

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use procage::native::{self, CageOptions, Child, Grants};
use procage::policy::path::AbsPath;
use procage::policy::{
    self as pp, Construct, HardDenyClass, LowerError, LowerOptions, Relax, Relaxation,
};
use pyo3::create_exception;
use pyo3::exceptions::{PyException, PyTimeoutError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict, PyList};

create_exception!(_native, Error, PyException, "Every procage error.");
create_exception!(
    _native,
    PolicyError,
    Error,
    "An invalid policy document, preset or relaxation."
);
create_exception!(
    _native,
    CapabilityGapError,
    Error,
    "The host cannot enforce the policy; `gaps` lists what it cannot."
);
create_exception!(
    _native,
    UnsupportedError,
    Error,
    "The host lacks something procage needs, or a setting cannot apply."
);
create_exception!(
    _native,
    AlreadySandboxedError,
    Error,
    "The calling process is itself sandboxed (macOS)."
);
create_exception!(
    _native,
    GrantError,
    Error,
    "A grant binding is undeclared, reserved or missing."
);
create_exception!(
    _native,
    SpawnError,
    Error,
    "The spawn failed (a path, a descriptor, the child sequence, I/O)."
);

/// The `Cage` options that would accept a gap of `construct`, if any: the
/// spawn snapshot, or the named relaxation that answers it. Nothing is
/// accepted unless the caller passes it.
fn accept(construct: Construct) -> Vec<String> {
    let mut out = Vec::new();
    if Construct::SPAWN_SNAPSHOT.contains(&construct) {
        out.push("accept_spawn_snapshot=True".to_string());
    }
    let named = [
        (Relaxation::LeaveOutProtect, "leave-out-protect".to_string()),
        (Relaxation::LeaveOutHide, "leave-out-hide".to_string()),
        (Relaxation::NoUnixSockets, "no-unix-sockets".to_string()),
        (Relaxation::SignalsSameUser, "signals-same-user".to_string()),
        (Relaxation::NoLoopback, "no-loopback".to_string()),
    ]
    .into_iter()
    .chain(
        HardDenyClass::ALL
            .iter()
            .filter(|c| **c != HardDenyClass::Secrets)
            .map(|c| (Relaxation::Waive(*c), format!("waive:{c}"))),
    );
    for (relaxation, name) in named {
        if relaxation.answers(construct) {
            out.push(format!("relax=[\"{name}\"]"));
        }
    }
    // Accepted only by name: the exec settings' approximations on Linux.
    if matches!(construct, Construct::ExecNever | Construct::ExecProgram) {
        out.push(format!("allow=[\"{}\"]", construct.as_str()));
    }
    out
}

/// The constructs named in `allow`, accepted as approximated.
fn allowed(names: &[String]) -> PyResult<Vec<Construct>> {
    names
        .iter()
        .map(|name| {
            Construct::ALL
                .iter()
                .copied()
                .find(|c| c.as_str() == name)
                .ok_or_else(|| PolicyError::new_err(format!("no construct {name}")))
        })
        .collect()
}

/// The gaps as dicts: `construct`, `target`, `kind`, `subject` and
/// `accept`, the options that would accept it.
fn gaps<'py>(py: Python<'py>, gaps: &[pp::CapabilityGap]) -> PyResult<Bound<'py, PyList>> {
    let list = PyList::empty(py);
    for g in gaps {
        let d = PyDict::new(py);
        d.set_item("construct", g.construct.as_str())?;
        d.set_item("target", g.target.to_string())?;
        d.set_item("kind", format!("{:?}", g.kind).to_lowercase())?;
        d.set_item("subject", g.subject.clone())?;
        d.set_item("accept", accept(g.construct))?;
        list.append(d)?;
    }
    Ok(list)
}

/// The Rust message, then one line per gap that an option would accept.
fn gap_message(e: &LowerError, found: &[pp::CapabilityGap]) -> String {
    let mut message = e.to_string();
    let mut seen = Vec::new();
    for g in found {
        let options = accept(g.construct);
        if !options.is_empty() && !seen.contains(&g.construct) {
            seen.push(g.construct);
            message.push_str(&format!(
                "\n  {}: Cage(..., {}) accepts it",
                g.construct.as_str(),
                options.join(" or ")
            ));
        }
    }
    message
}

fn lower_error(py: Python<'_>, e: &LowerError) -> PyErr {
    match e {
        LowerError::Gaps(found) => match gaps(py, found) {
            Ok(list) => CapabilityGapError::new_err((gap_message(e, found), list.unbind())),
            Err(err) => err,
        },
        _ => PolicyError::new_err(e.to_string()),
    }
}

/// The exception for a spawn error, with procage's message.
fn spawn_error(py: Python<'_>, e: native::SpawnError) -> PyErr {
    let message = e.to_string();
    match &e {
        native::SpawnError::Lower(lower) => lower_error(py, lower),
        native::SpawnError::Unsupported(_) => UnsupportedError::new_err(message),
        #[cfg(target_os = "macos")]
        native::SpawnError::AlreadySandboxed => AlreadySandboxedError::new_err(message),
        native::SpawnError::Grant(_) => GrantError::new_err(message),
        _ => SpawnError::new_err(message),
    }
}

/// `path` as an absolute path; a trailing slash (not the root's) is
/// dropped, so `"/abs/project/"` names the project.
fn abs(path: &std::path::Path, what: &str) -> PyResult<AbsPath> {
    let bytes = path.as_os_str().as_encoded_bytes();
    let end = bytes.iter().rposition(|&b| b != b'/').map_or(1, |i| i + 1);
    AbsPath::new(&bytes[..end])
        .map_err(|e| PolicyError::new_err(format!("{what} {}: {e}", path.display())))
}

/// A policy: from a preset or from the versioned JSON format.
#[pyclass(frozen, module = "procage._native")]
struct Policy {
    inner: pp::Policy,
    /// The workspace a preset was made for: the default working directory.
    workspace: Option<PathBuf>,
}

#[pymethods]
impl Policy {
    /// A preset by name (`minimal`, `agent_readonly`, `agent_workspace`,
    /// `build`) and version (1 to 3); every preset but `minimal` needs an
    /// absolute `workspace`.
    #[staticmethod]
    #[pyo3(signature = (name, version, workspace=None))]
    fn preset(name: &str, version: u8, workspace: Option<PathBuf>) -> PyResult<Policy> {
        use pp::presets::{agent_readonly, agent_workspace, build, minimal};
        let root = || -> PyResult<AbsPath> {
            let path = workspace
                .as_deref()
                .ok_or_else(|| PolicyError::new_err(format!("preset {name} needs a workspace")))?;
            abs(path, "workspace")
        };
        let inner = match (name, version) {
            ("minimal", 1) => minimal::v1(),
            ("minimal", 2) => minimal::v2(),
            ("minimal", 3) => minimal::v3(),
            ("agent_readonly", 1) => agent_readonly::v1(&root()?),
            ("agent_readonly", 2) => agent_readonly::v2(&root()?),
            ("agent_readonly", 3) => agent_readonly::v3(&root()?),
            ("agent_workspace", 1) => agent_workspace::v1(&root()?),
            ("agent_workspace", 2) => agent_workspace::v2(&root()?),
            ("agent_workspace", 3) => agent_workspace::v3(&root()?),
            ("build", 1) => build::v1(&root()?),
            ("build", 2) => build::v2(&root()?),
            ("build", 3) => build::v3(&root()?),
            _ => {
                return Err(PolicyError::new_err(format!(
                    "no preset {name} version {version}"
                )));
            }
        };
        let workspace = if name == "minimal" { None } else { workspace };
        Ok(Policy { inner, workspace })
    }

    /// A policy from the versioned JSON format (unknown fields are refused).
    #[staticmethod]
    fn from_json(text: &str) -> PyResult<Policy> {
        serde_json::from_str(text)
            .map(|inner| Policy {
                inner,
                workspace: None,
            })
            .map_err(|e| PolicyError::new_err(e.to_string()))
    }

    /// The policy in the versioned JSON format.
    fn to_json(&self) -> PyResult<String> {
        serde_json::to_string(&self.inner).map_err(|e| PolicyError::new_err(e.to_string()))
    }

    /// The workspace of a preset (the default working directory of its
    /// runs), else `None`.
    #[getter]
    fn workspace(&self) -> Option<PathBuf> {
        self.workspace.clone()
    }

    fn __repr__(&self) -> String {
        format!(
            "Policy(base={:?}, rules={})",
            self.inner.base,
            self.inner.fs.len()
        )
    }
}

/// The named relaxations `Cage::fit` accepts.
fn relax(names: &[String]) -> PyResult<Relax> {
    let mut out = Relax::new();
    for name in names {
        out =
            match name.as_str() {
                "leave-out-protect" => out.leave_out_protect(),
                "leave-out-hide" => out.leave_out_hide(),
                "no-unix-sockets" => out.no_unix_sockets(),
                "signals-same-user" => out.signals_same_user(),
                "no-loopback" => out.no_loopback(),
                other => match other.strip_prefix("waive:") {
                    Some(class) => out.waive(class.parse::<HardDenyClass>().map_err(|_| {
                        PolicyError::new_err(format!("no hard-deny class {class}"))
                    })?),
                    None => return Err(PolicyError::new_err(format!("no relaxation {other}"))),
                },
            };
    }
    Ok(out)
}

fn stdio(mode: &str, which: &str) -> PyResult<Stdio> {
    match mode {
        "pipe" => Ok(Stdio::piped()),
        "null" => Ok(Stdio::null()),
        "inherit" => Ok(Stdio::inherit()),
        _ => Err(PyValueError::new_err(format!(
            "{which} must be \"pipe\", \"null\" or \"inherit\", not {mode:?}"
        ))),
    }
}

/// A prepared policy: spawn any number of runs from it, from any thread.
#[pyclass(frozen, module = "procage._native")]
struct Cage {
    inner: native::Cage,
    relaxed: Vec<String>,
    workspace: Option<PathBuf>,
}

#[pymethods]
impl Cage {
    #[new]
    #[pyo3(signature = (policy, *, violations=false, relax=Vec::new(), accept_spawn_snapshot=false, allow=Vec::new()))]
    fn new(
        py: Python<'_>,
        policy: &Policy,
        violations: bool,
        relax: Vec<String>,
        accept_spawn_snapshot: bool,
        allow: Vec<String>,
    ) -> PyResult<Cage> {
        let mut lower = if accept_spawn_snapshot {
            LowerOptions::default().accept_spawn_snapshot()
        } else {
            LowerOptions::default()
        };
        for construct in allowed(&allow)? {
            lower = lower.allow(construct);
        }
        let mut options = CageOptions::default().with_lower(lower);
        if violations {
            options = options.with_violations();
        }
        let policy_workspace = policy.workspace.clone();
        let policy = &policy.inner;
        if relax.is_empty() {
            let inner = py
                .detach(|| native::Cage::with_options(policy, &options))
                .map_err(|e| spawn_error(py, e))?;
            return Ok(Cage {
                inner,
                relaxed: Vec::new(),
                workspace: policy_workspace,
            });
        }
        let named = self::relax(&relax)?;
        let (inner, taken) = py
            .detach(|| native::Cage::fit(policy, &options, &named))
            .map_err(|e| spawn_error(py, e))?;
        Ok(Cage {
            inner,
            relaxed: taken.iter().map(ToString::to_string).collect(),
            workspace: policy_workspace,
        })
    }

    /// The relaxations `relax` applied, as sentences.
    #[getter]
    fn relaxed(&self) -> Vec<String> {
        self.relaxed.clone()
    }

    /// Spawns `args` in this cage, in `cwd` or else the preset's workspace.
    /// Only the variables in `env` are set explicitly; the policy decides
    /// which of the caller's reach the child.
    #[pyo3(signature = (args, *, cwd=None, env=None, grants=None, stdin="null", stdout="pipe", stderr="pipe"))]
    #[allow(clippy::too_many_arguments)]
    fn spawn(
        &self,
        py: Python<'_>,
        args: Vec<String>,
        cwd: Option<PathBuf>,
        env: Option<BTreeMap<String, String>>,
        grants: Option<BTreeMap<String, PathBuf>>,
        stdin: &str,
        stdout: &str,
        stderr: &str,
    ) -> PyResult<Run> {
        let (program, rest) = args
            .split_first()
            .ok_or_else(|| PyValueError::new_err("args is empty"))?;
        let mut cmd = Command::new(program);
        cmd.args(rest)
            .stdin(stdio(stdin, "stdin")?)
            .stdout(stdio(stdout, "stdout")?)
            .stderr(stdio(stderr, "stderr")?);
        // A preset's workspace is the default working directory.
        if let Some(dir) = cwd.or_else(|| self.workspace.clone()) {
            cmd.current_dir(dir);
        }
        for (k, v) in env.unwrap_or_default() {
            cmd.env(k, v);
        }
        let mut bound = Grants::new();
        for (name, path) in grants.unwrap_or_default() {
            bound = bound.bind(&name, path);
        }
        let child = py
            .detach(|| self.inner.spawn(&mut cmd, &bound))
            .map_err(|e| spawn_error(py, e))?;
        Ok(Run {
            pid: child.id(),
            child: Mutex::new(Some(child)),
        })
    }
}

/// A running caged command. Dropping it ends the run: every process of it
/// is killed.
#[pyclass(frozen, module = "procage._native")]
struct Run {
    pid: u32,
    child: Mutex<Option<Child>>,
}

impl Run {
    fn with<T>(&self, f: impl FnOnce(&mut Child) -> T) -> PyResult<T> {
        let mut guard = self.child.lock().unwrap_or_else(|e| e.into_inner());
        match guard.as_mut() {
            Some(child) => Ok(f(child)),
            None => Err(Error::new_err("the run is closed")),
        }
    }

    /// Polls until the child exits or `timeout` passes; the lock on the
    /// handle is held only per poll, so `kill` gets through.
    fn wait_for(&self, timeout: Option<f64>) -> PyResult<Option<i32>> {
        let start = Instant::now();
        loop {
            let status = self.with(|c| c.try_wait())?;
            match status {
                Ok(Some(status)) => return Ok(Some(code(status))),
                Ok(None) => {}
                Err(e) => return Err(SpawnError::new_err(e.to_string())),
            }
            if timeout.is_some_and(|t| start.elapsed() >= Duration::from_secs_f64(t)) {
                return Ok(None);
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    }
}

/// The exit code, or minus the signal number, as Python's subprocess does.
fn code(status: std::process::ExitStatus) -> i32 {
    use std::os::unix::process::ExitStatusExt;
    status
        .code()
        .unwrap_or_else(|| -status.signal().unwrap_or(0))
}

/// Standard output and error read by `communicate`.
type Streams<'py> = (Option<Bound<'py, PyBytes>>, Option<Bound<'py, PyBytes>>);

fn read_all(mut r: impl Read) -> Vec<u8> {
    let mut out = Vec::new();
    let _ = r.read_to_end(&mut out);
    out
}

#[pymethods]
impl Run {
    #[getter]
    fn pid(&self) -> u32 {
        self.pid
    }

    /// The exit code once the child has exited, else `None`.
    fn poll(&self) -> PyResult<Option<i32>> {
        match self.with(|c| c.try_wait())? {
            Ok(status) => Ok(status.map(code)),
            Err(e) => Err(SpawnError::new_err(e.to_string())),
        }
    }

    /// Waits for the child's exit; `TimeoutError` after `timeout` seconds.
    #[pyo3(signature = (timeout=None))]
    fn wait(&self, py: Python<'_>, timeout: Option<f64>) -> PyResult<i32> {
        py.detach(|| self.wait_for(timeout))?.ok_or_else(|| {
            PyTimeoutError::new_err(format!("the run did not end within {timeout:?} s"))
        })
    }

    /// Ends the run: kills the child and every process of the run.
    fn kill(&self, py: Python<'_>) -> PyResult<()> {
        py.detach(|| self.with(|c| c.kill_all()))?
            .map_err(|e| SpawnError::new_err(e.to_string()))
    }

    /// Writes `input` to standard input (then closes it), reads standard
    /// output and error to the end and waits; `(stdout, stderr)` as bytes
    /// (`None` for a stream that is not a pipe).
    #[pyo3(signature = (input=None, timeout=None))]
    fn communicate<'py>(
        &self,
        py: Python<'py>,
        input: Option<Vec<u8>>,
        timeout: Option<f64>,
    ) -> PyResult<Streams<'py>> {
        let (stdin, stdout, stderr) =
            self.with(|c| (c.stdin.take(), c.stdout.take(), c.stderr.take()))?;
        let (out, err, ended) = py.detach(|| {
            let writer = stdin.map(|mut w| {
                std::thread::spawn(move || {
                    if let Some(data) = input {
                        let _ = w.write_all(&data);
                    }
                })
            });
            let out = stdout.map(|r| std::thread::spawn(move || read_all(r)));
            let err = stderr.map(|r| std::thread::spawn(move || read_all(r)));
            let ended = self.wait_for(timeout);
            if let Some(w) = writer {
                let _ = w.join();
            }
            let join = |h: Option<std::thread::JoinHandle<Vec<u8>>>| {
                h.map(|h| h.join().unwrap_or_default())
            };
            match ended {
                Ok(Some(_)) => (join(out), join(err), ended),
                // Readers of a run still going are left to finish with it.
                _ => (None, None, ended),
            }
        });
        match ended? {
            Some(_) => Ok((
                out.map(|b| PyBytes::new(py, &b)),
                err.map(|b| PyBytes::new(py, &b)),
            )),
            None => Err(PyTimeoutError::new_err(format!(
                "the run did not end within {timeout:?} s"
            ))),
        }
    }

    /// The run's violations as dicts: `pid`, `process`, `operation`,
    /// `target`, `denied_by`, `repeats` and `message`. Empty unless the cage
    /// reports violations.
    fn violations<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyList>> {
        let record = py.detach(|| self.with(|c| c.violations()))?;
        let list = PyList::empty(py);
        for v in record.iter() {
            let d = PyDict::new(py);
            d.set_item("pid", v.pid)?;
            d.set_item("process", &v.process)?;
            d.set_item("operation", &v.operation)?;
            d.set_item("target", v.target.clone())?;
            d.set_item("denied_by", v.denied_by.to_string())?;
            d.set_item("repeats", v.repeats)?;
            d.set_item("message", v.to_string())?;
            list.append(d)?;
        }
        Ok(list)
    }

    /// The run's receipt in its JSON form once the child has exited (this
    /// ends the run), else `None`.
    fn receipt_json(&self, py: Python<'_>) -> PyResult<Option<String>> {
        Ok(py
            .detach(|| self.with(|c| c.receipt()))?
            .map(|r| r.to_json()))
    }

    /// Ends the run and releases the handle.
    fn close(&self, py: Python<'_>) {
        let taken = self.child.lock().unwrap_or_else(|e| e.into_inner()).take();
        py.detach(|| drop(taken));
    }
}

#[pymodule]
fn _native(m: &Bound<'_, PyModule>) -> PyResult<()> {
    let py = m.py();
    m.add_class::<Policy>()?;
    m.add_class::<Cage>()?;
    m.add_class::<Run>()?;
    m.add("Error", py.get_type::<Error>())?;
    m.add("PolicyError", py.get_type::<PolicyError>())?;
    m.add("CapabilityGapError", py.get_type::<CapabilityGapError>())?;
    m.add("UnsupportedError", py.get_type::<UnsupportedError>())?;
    m.add(
        "AlreadySandboxedError",
        py.get_type::<AlreadySandboxedError>(),
    )?;
    m.add("GrantError", py.get_type::<GrantError>())?;
    m.add("SpawnError", py.get_type::<SpawnError>())?;
    Ok(())
}
