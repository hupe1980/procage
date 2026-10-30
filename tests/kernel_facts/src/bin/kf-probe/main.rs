//! `kf-probe <step> [args…]`: performs exactly one kernel-fact step and prints
//! its observations as `kf key=value` lines.
//!
//! Exit codes: 0 the step ran (a denied action is still 0, with its errno),
//! 2 usage error, 3 setup failure before the observed action. A signal (for
//! example SIGABRT from libsandbox) is itself an observation for the runner.
//!
//! Steps never run a shell and never build arguments from the environment;
//! paths they receive must be scratch paths the runner created.

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;

use std::path::Path;
use std::process::ExitCode;

use procage_kernel_facts::{emit, is_inline_path};

/// Exit code for a usage error.
const USAGE: u8 = 2;
/// Exit code for a setup failure.
const SETUP: u8 = 3;

/// A step's failure before its observed action.
enum Fail {
    Usage(String),
    Setup(String),
}

type StepResult = Result<(), Fail>;

fn setup(what: impl Into<String>) -> Fail {
    Fail::Setup(what.into())
}

/// `args[i]` as a scratch path: absolute, inline-safe and existing.
fn scratch_arg(args: &[String], i: usize) -> Result<&str, Fail> {
    let s = args
        .get(i)
        .ok_or_else(|| Fail::Usage(format!("missing argument {i}")))?;
    let p = Path::new(s);
    if !is_inline_path(p) || !p.is_absolute() || !s.contains("/procage-kf-") {
        return Err(Fail::Usage("not a scratch path".into()));
    }
    Ok(s)
}

/// `args[i]` as one of `choices`.
fn choice<'a>(args: &'a [String], i: usize, choices: &[&str]) -> Result<&'a str, Fail> {
    match args.get(i) {
        Some(s) if choices.contains(&s.as_str()) => Ok(s),
        other => Err(Fail::Usage(format!(
            "argument {i} {other:?} not one of {choices:?}"
        ))),
    }
}

/// The errno of an I/O error, or -1.
fn io_errno(e: &std::io::Error) -> i32 {
    e.raw_os_error().unwrap_or(-1)
}

/// Re-emits the `kf` lines of a nested step with `prefix` on every key.
fn forward(prefix: &str, stdout: &[u8]) {
    let obs = procage_kernel_facts::Observation::parse(&String::from_utf8_lossy(stdout));
    for pair in obs.summary().split_whitespace() {
        if let Some((k, v)) = pair.split_once('=') {
            emit(&format!("{prefix}{k}"), v);
        }
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some(step) = args.first().cloned() else {
        eprintln!("usage: kf-probe <step> [args…]");
        return ExitCode::from(USAGE);
    };
    #[cfg(target_os = "macos")]
    let result = macos::run(&step, &args[1..]);
    #[cfg(target_os = "linux")]
    let result = linux::run(&step, &args[1..]);
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    let result: StepResult = Err(Fail::Usage(format!("no steps on this OS: {step}")));
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(Fail::Usage(m)) => {
            eprintln!("kf-probe {step}: usage: {m}");
            ExitCode::from(USAGE)
        }
        Err(Fail::Setup(m)) => {
            eprintln!("kf-probe {step}: setup: {m}");
            ExitCode::from(SETUP)
        }
    }
}
