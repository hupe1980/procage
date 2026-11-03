//! The native addon of the `procage` npm package.
//!
//! A thin layer over the Rust API: policies come only from the presets and
//! the versioned serialised format, every error carries its kind (the
//! JavaScript module turns it into a class), spawning, waiting and reading
//! run on the libuv thread pool, and collecting a run ends it. No
//! JavaScript runs in the child: spawning is procage's own child sequence.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use napi::bindgen_prelude::{AsyncTask, Buffer};
use napi::{Env, Error, Result, Status, Task};
use napi_derive::napi;
use procage::native::{self, CageOptions, Child, Grants};
use procage::policy::path::AbsPath;
use procage::policy::{
    self as pp, Construct, HardDenyClass, LowerError, LowerOptions, Relax, Relaxation,
};

/// An error the JavaScript module turns into its class: a marked JSON
/// document with the kind, procage's message and, for a gap, the gaps.
fn fail(kind: &str, message: String, gaps: Option<serde_json::Value>) -> Error {
    let mut doc = serde_json::json!({ "kind": kind, "message": message });
    if let Some(gaps) = gaps {
        doc["gaps"] = gaps;
    }
    Error::new(Status::GenericFailure, format!("procage:{doc}"))
}

/// The `Cage` options that would accept a gap of `construct`, in
/// JavaScript spelling. Nothing is accepted unless the caller passes it.
fn accept(construct: Construct) -> Vec<String> {
    let mut out = Vec::new();
    if Construct::SPAWN_SNAPSHOT.contains(&construct) {
        out.push("acceptSpawnSnapshot: true".to_string());
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
            out.push(format!("relax: [\"{name}\"]"));
        }
    }
    out
}

fn lower_error(e: &LowerError) -> Error {
    match e {
        LowerError::Gaps(found) => {
            let gaps: Vec<serde_json::Value> = found
                .iter()
                .map(|g| {
                    serde_json::json!({
                        "construct": g.construct.as_str(),
                        "target": g.target.to_string(),
                        "kind": format!("{:?}", g.kind).to_lowercase(),
                        "subject": g.subject,
                        "accept": accept(g.construct),
                    })
                })
                .collect();
            fail(
                "CapabilityGapError",
                e.to_string(),
                Some(serde_json::Value::Array(gaps)),
            )
        }
        _ => fail("PolicyError", e.to_string(), None),
    }
}

fn spawn_error(e: native::SpawnError) -> Error {
    let message = e.to_string();
    match &e {
        native::SpawnError::Lower(lower) => lower_error(lower),
        native::SpawnError::Unsupported(_) => fail("UnsupportedError", message, None),
        #[cfg(target_os = "macos")]
        native::SpawnError::AlreadySandboxed => fail("AlreadySandboxedError", message, None),
        native::SpawnError::Grant(_) => fail("GrantError", message, None),
        _ => fail("SpawnError", message, None),
    }
}

fn policy_error(message: String) -> Error {
    fail("PolicyError", message, None)
}

/// A policy: from a preset or from the versioned JSON format.
#[napi]
pub struct Policy {
    inner: pp::Policy,
    workspace: Option<PathBuf>,
}

#[napi]
impl Policy {
    /// A preset by name (`minimal`, `agent_readonly`, `agent_workspace`,
    /// `build`) and version (1 to 3); every preset but `minimal` needs an
    /// absolute workspace, which becomes its runs' working directory.
    #[napi(factory)]
    pub fn preset(name: String, version: u32, workspace: Option<String>) -> Result<Policy> {
        use pp::presets::{agent_readonly, agent_workspace, build, minimal};
        let root = || -> Result<AbsPath> {
            let path = workspace
                .as_deref()
                .ok_or_else(|| policy_error(format!("preset {name} needs a workspace")))?;
            AbsPath::new(path).map_err(|e| policy_error(format!("workspace {path}: {e}")))
        };
        let inner = match (name.as_str(), version) {
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
            _ => return Err(policy_error(format!("no preset {name} version {version}"))),
        };
        let workspace = if name == "minimal" {
            None
        } else {
            workspace.map(PathBuf::from)
        };
        Ok(Policy { inner, workspace })
    }

    /// A policy from the versioned JSON format (unknown fields are refused).
    #[napi(factory)]
    pub fn from_json(text: String) -> Result<Policy> {
        serde_json::from_str(&text)
            .map(|inner| Policy {
                inner,
                workspace: None,
            })
            .map_err(|e| policy_error(e.to_string()))
    }

    /// The policy in the versioned JSON format.
    #[napi]
    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string(&self.inner).map_err(|e| policy_error(e.to_string()))
    }

    /// The workspace of a preset, else `null`.
    #[napi(getter)]
    pub fn workspace(&self) -> Option<String> {
        self.workspace
            .as_ref()
            .map(|p| p.to_string_lossy().into_owned())
    }
}

/// Options of a cage.
#[napi(object)]
pub struct CageOptionsJs {
    /// Record what the sandbox denied.
    pub violations: Option<bool>,
    /// Named relaxations, applied only where the host needs them.
    pub relax: Option<Vec<String>>,
    /// Accept the Linux approximations taken from the file system at spawn.
    pub accept_spawn_snapshot: Option<bool>,
}

fn relax(names: &[String]) -> Result<Relax> {
    let mut out = Relax::new();
    for name in names {
        out = match name.as_str() {
            "leave-out-protect" => out.leave_out_protect(),
            "leave-out-hide" => out.leave_out_hide(),
            "no-unix-sockets" => out.no_unix_sockets(),
            "signals-same-user" => out.signals_same_user(),
            "no-loopback" => out.no_loopback(),
            other => match other.strip_prefix("waive:") {
                Some(class) => out.waive(
                    class
                        .parse::<HardDenyClass>()
                        .map_err(|_| policy_error(format!("no hard-deny class {class}")))?,
                ),
                None => return Err(policy_error(format!("no relaxation {other}"))),
            },
        };
    }
    Ok(out)
}

/// A prepared policy: spawn any number of runs from it.
#[napi]
pub struct Cage {
    inner: Arc<native::Cage>,
    relaxed: Vec<String>,
    workspace: Option<PathBuf>,
}

/// What `spawn` is given.
#[napi(object)]
pub struct SpawnOptionsJs {
    /// The working directory; the preset's workspace by default.
    pub cwd: Option<String>,
    /// The only variables set explicitly.
    pub env: Option<HashMap<String, String>>,
    /// Paths bound to the policy's declared grants.
    pub grants: Option<HashMap<String, String>>,
    /// Open standard input as a pipe (for `output`'s input).
    pub stdin: Option<bool>,
}

#[napi]
impl Cage {
    /// Lowers `policy` for this host; a gap throws with the options that
    /// would accept it.
    #[napi(constructor)]
    pub fn new(policy: &Policy, options: Option<CageOptionsJs>) -> Result<Self> {
        let o = options.unwrap_or(CageOptionsJs {
            violations: None,
            relax: None,
            accept_spawn_snapshot: None,
        });
        let lower = if o.accept_spawn_snapshot.unwrap_or(false) {
            LowerOptions::default().accept_spawn_snapshot()
        } else {
            LowerOptions::default()
        };
        let mut options = CageOptions::default().with_lower(lower);
        if o.violations.unwrap_or(false) {
            options = options.with_violations();
        }
        let names = o.relax.unwrap_or_default();
        let (inner, relaxed) = if names.is_empty() {
            (
                native::Cage::with_options(&policy.inner, &options).map_err(spawn_error)?,
                Vec::new(),
            )
        } else {
            let (cage, taken) =
                native::Cage::fit(&policy.inner, &options, &relax(&names)?).map_err(spawn_error)?;
            (cage, taken.iter().map(ToString::to_string).collect())
        };
        Ok(Cage {
            inner: Arc::new(inner),
            relaxed,
            workspace: policy.workspace.clone(),
        })
    }

    /// The relaxations applied, as sentences.
    #[napi(getter)]
    pub fn relaxed(&self) -> Vec<String> {
        self.relaxed.clone()
    }

    /// Spawns `argv` on the thread pool; resolves to a `Run`.
    #[napi]
    pub fn spawn(
        &self,
        argv: Vec<String>,
        options: Option<SpawnOptionsJs>,
    ) -> AsyncTask<SpawnTask> {
        AsyncTask::new(SpawnTask {
            cage: self.inner.clone(),
            argv,
            options,
            workspace: self.workspace.clone(),
        })
    }
}

/// `Cage.spawn` on the thread pool.
pub struct SpawnTask {
    cage: Arc<native::Cage>,
    argv: Vec<String>,
    options: Option<SpawnOptionsJs>,
    workspace: Option<PathBuf>,
}

impl Task for SpawnTask {
    type Output = Child;
    type JsValue = Run;

    fn compute(&mut self) -> Result<Child> {
        let (program, rest) = self
            .argv
            .split_first()
            .ok_or_else(|| fail("SpawnError", "the command is empty".into(), None))?;
        let mut cmd = Command::new(program);
        cmd.args(rest).stdout(Stdio::piped()).stderr(Stdio::piped());
        let options = self.options.take();
        let (cwd, env, grants, stdin) = match options {
            Some(o) => (o.cwd, o.env, o.grants, o.stdin.unwrap_or(false)),
            None => (None, None, None, false),
        };
        cmd.stdin(if stdin { Stdio::piped() } else { Stdio::null() });
        if let Some(dir) = cwd.map(PathBuf::from).or_else(|| self.workspace.clone()) {
            cmd.current_dir(dir);
        }
        for (k, v) in env.unwrap_or_default() {
            cmd.env(k, v);
        }
        let mut bound = Grants::new();
        for (name, path) in grants.unwrap_or_default() {
            bound = bound.bind(&name, path);
        }
        self.cage.spawn(&mut cmd, &bound).map_err(spawn_error)
    }

    fn resolve(&mut self, _: Env, child: Child) -> Result<Run> {
        Ok(Run {
            pid: child.id(),
            child: Arc::new(Mutex::new(Some(child))),
        })
    }
}

/// How a run ended.
#[napi(object)]
pub struct ExitJs {
    /// The exit code, or `null` when a signal ended it.
    pub exit_code: Option<i32>,
    /// The signal's name (`SIGKILL`, …), or `null`.
    pub signal: Option<String>,
}

/// What `output` read.
#[napi(object)]
pub struct OutputJs {
    /// The exit code, or `null` when a signal ended it.
    pub exit_code: Option<i32>,
    /// The signal's name, or `null`.
    pub signal: Option<String>,
    /// Standard output.
    pub stdout: Buffer,
    /// Standard error.
    pub stderr: Buffer,
    /// The timeout passed first; the run was ended.
    pub timed_out: bool,
}

/// One denial the sandbox reported.
#[napi(object)]
pub struct ViolationJs {
    /// The denied process.
    pub pid: u32,
    /// Its name.
    pub process: String,
    /// The operation (`file-read-data`, a system call, …).
    pub operation: String,
    /// What it aimed at, when the kernel says.
    pub target: Option<String>,
    /// The kind of rule that denied it.
    pub denied_by: String,
    /// How often.
    pub repeats: u32,
    /// The whole report as a sentence.
    pub message: String,
}

fn signal_name(n: i32) -> String {
    match n {
        1 => "SIGHUP",
        2 => "SIGINT",
        3 => "SIGQUIT",
        6 => "SIGABRT",
        9 => "SIGKILL",
        13 => "SIGPIPE",
        14 => "SIGALRM",
        15 => "SIGTERM",
        _ => return format!("signal {n}"),
    }
    .to_string()
}

fn exit_of(status: std::process::ExitStatus) -> ExitJs {
    use std::os::unix::process::ExitStatusExt;
    ExitJs {
        exit_code: status.code(),
        signal: status.signal().map(signal_name),
    }
}

type Shared = Arc<Mutex<Option<Child>>>;

fn with<T>(child: &Shared, f: impl FnOnce(&mut Child) -> T) -> Result<T> {
    let mut guard = child.lock().unwrap_or_else(|e| e.into_inner());
    match guard.as_mut() {
        Some(c) => Ok(f(c)),
        None => Err(fail("SpawnError", "the run is closed".into(), None)),
    }
}

/// Polls until exit or `timeout`; the handle's lock is held per poll only,
/// so `kill` gets through.
fn wait_for(child: &Shared, timeout: Option<Duration>) -> Result<Option<std::process::ExitStatus>> {
    let start = Instant::now();
    loop {
        match with(child, |c| c.try_wait())? {
            Ok(Some(status)) => return Ok(Some(status)),
            Ok(None) => {}
            Err(e) => return Err(fail("SpawnError", e.to_string(), None)),
        }
        if timeout.is_some_and(|t| start.elapsed() >= t) {
            return Ok(None);
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}

/// A running caged command. Collecting it ends the run.
#[napi]
pub struct Run {
    pid: u32,
    child: Shared,
}

#[napi]
impl Run {
    /// The child's process id.
    #[napi(getter)]
    pub fn pid(&self) -> u32 {
        self.pid
    }

    /// Waits for the exit on the thread pool.
    #[napi]
    pub fn wait(&self) -> AsyncTask<WaitTask> {
        AsyncTask::new(WaitTask(self.child.clone()))
    }

    /// Writes `input` (then closes standard input), reads standard output
    /// and error to the end and waits, on the thread pool; after
    /// `timeoutMs` the run is ended and `timedOut` set.
    #[napi]
    pub fn output(&self, input: Option<Buffer>, timeout_ms: Option<f64>) -> AsyncTask<OutputTask> {
        AsyncTask::new(OutputTask {
            child: self.child.clone(),
            input: input.map(|b| b.to_vec()),
            timeout: timeout_ms.map(|ms| Duration::from_secs_f64(ms.max(0.0) / 1000.0)),
        })
    }

    /// Ends the run: kills the child and every process of the run.
    #[napi]
    pub fn kill(&self) -> Result<()> {
        with(&self.child, |c| c.kill_all())?.map_err(|e| fail("SpawnError", e.to_string(), None))
    }

    /// The run's violations, on the thread pool.
    #[napi]
    pub fn violations(&self) -> AsyncTask<ViolationsTask> {
        AsyncTask::new(ViolationsTask(self.child.clone()))
    }

    /// The receipt in its JSON form once the child has exited (this ends
    /// the run), else `null`.
    #[napi]
    pub fn receipt_json(&self) -> Result<Option<String>> {
        Ok(with(&self.child, |c| c.receipt())?.map(|r| r.to_json()))
    }

    /// Ends the run and releases the handle.
    #[napi]
    pub fn close(&self) {
        let taken = self.child.lock().unwrap_or_else(|e| e.into_inner()).take();
        drop(taken);
    }
}

/// `Run.wait` on the thread pool.
pub struct WaitTask(Shared);

impl Task for WaitTask {
    type Output = ExitJs;
    type JsValue = ExitJs;

    fn compute(&mut self) -> Result<ExitJs> {
        match wait_for(&self.0, None)? {
            Some(status) => Ok(exit_of(status)),
            None => Err(fail("SpawnError", "the run did not end".into(), None)),
        }
    }

    fn resolve(&mut self, _: Env, out: ExitJs) -> Result<ExitJs> {
        Ok(out)
    }
}

/// What `output` collected, before it becomes JavaScript values.
pub struct Collected {
    exit: Option<ExitJs>,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

/// `Run.output` on the thread pool.
pub struct OutputTask {
    child: Shared,
    input: Option<Vec<u8>>,
    timeout: Option<Duration>,
}

fn read_all(mut r: impl Read) -> Vec<u8> {
    let mut out = Vec::new();
    let _ = r.read_to_end(&mut out);
    out
}

impl Task for OutputTask {
    type Output = Collected;
    type JsValue = OutputJs;

    fn compute(&mut self) -> Result<Collected> {
        let (stdin, stdout, stderr) = with(&self.child, |c| {
            (c.stdin.take(), c.stdout.take(), c.stderr.take())
        })?;
        let input = self.input.take();
        let writer = stdin.map(|mut w| {
            std::thread::spawn(move || {
                if let Some(data) = input {
                    let _ = w.write_all(&data);
                }
            })
        });
        let out = stdout.map(|r| std::thread::spawn(move || read_all(r)));
        let err = stderr.map(|r| std::thread::spawn(move || read_all(r)));
        let ended = wait_for(&self.child, self.timeout)?;
        if ended.is_none() {
            // Ending the run closes the pipes, so the readers finish.
            let _ = with(&self.child, |c| c.kill_all());
        }
        if let Some(w) = writer {
            let _ = w.join();
        }
        let join = |h: Option<std::thread::JoinHandle<Vec<u8>>>| {
            h.map(|h| h.join().unwrap_or_default()).unwrap_or_default()
        };
        Ok(Collected {
            exit: ended.map(exit_of),
            stdout: join(out),
            stderr: join(err),
        })
    }

    fn resolve(&mut self, _: Env, c: Collected) -> Result<OutputJs> {
        let timed_out = c.exit.is_none();
        let exit = c.exit.unwrap_or(ExitJs {
            exit_code: None,
            signal: Some("SIGKILL".into()),
        });
        Ok(OutputJs {
            exit_code: exit.exit_code,
            signal: exit.signal,
            stdout: c.stdout.into(),
            stderr: c.stderr.into(),
            timed_out,
        })
    }
}

/// `Run.violations` on the thread pool.
pub struct ViolationsTask(Shared);

impl Task for ViolationsTask {
    type Output = Vec<ViolationJs>;
    type JsValue = Vec<ViolationJs>;

    fn compute(&mut self) -> Result<Vec<ViolationJs>> {
        let record = with(&self.0, |c| c.violations())?;
        Ok(record
            .iter()
            .map(|v| ViolationJs {
                pid: v.pid,
                process: v.process.clone(),
                operation: v.operation.clone(),
                target: v.target.clone(),
                denied_by: v.denied_by.to_string(),
                repeats: v.repeats,
                message: v.to_string(),
            })
            .collect())
    }

    fn resolve(&mut self, _: Env, out: Vec<ViolationJs>) -> Result<Vec<ViolationJs>> {
        Ok(out)
    }
}
