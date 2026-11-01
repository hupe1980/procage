//! `Cage::exec`: a helper process becomes the caged command.
//!
//! This target has its own `main` instead of libtest, whose tests run on
//! extra threads: real helpers are single-threaded, and on Linux tier T1
//! `exec` needs that. `main` plays the outside code (it starts this binary
//! as a helper, in its own process group, and checks what the helper's
//! caller sees); with `PROCAGE_EXEC` set, the binary is the helper.
//! Refusals run in this process and are followed by a write outside every
//! policy, which must still succeed.

#![cfg(any(target_os = "macos", target_os = "linux"))]

#[path = "support/scratch.rs"]
mod scratch_support;
use scratch_support::Scratch;

use std::io::{BufRead, BufReader};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use procage::native::{Cage, CageOptions, GrantError, Grants, SpawnError};
use procage::policy::{
    AbsPath, Access, Base, EnvPolicy, Exec, FsRule, FsTarget, Grant, GrantName, LowerOptions,
    Policy,
};
#[cfg(target_os = "linux")]
use procage::policy::{HardDenyClass, Tier};

const ROLE: &str = "PROCAGE_EXEC";

// ---- tiers -------------------------------------------------------------

/// The tiers to run on: both on a T1 host, T2 otherwise; one pass on macOS.
#[cfg(target_os = "linux")]
fn tiers() -> Vec<String> {
    match procage::linux::probe().tier {
        Some(Tier::T1) => vec!["T1".into(), "T2".into()],
        Some(Tier::T2) => vec!["T2".into()],
        None => panic!("these tests need Landlock"),
    }
}

#[cfg(target_os = "macos")]
fn tiers() -> Vec<String> {
    vec!["macos".into()]
}

#[cfg(target_os = "linux")]
fn options(tier: &str) -> CageOptions {
    let tier = if tier == "T1" { Tier::T1 } else { Tier::T2 };
    CageOptions::default()
        .with_tier(tier)
        .with_lower(LowerOptions::default().accept_spawn_snapshot())
}

#[cfg(target_os = "macos")]
fn options(_tier: &str) -> CageOptions {
    CageOptions::default().with_lower(LowerOptions::default())
}

/// On T2 a write rule reaches trust-handoff names, which only T1 can mask.
#[cfg(target_os = "linux")]
fn for_tier(mut p: Policy, tier: &str) -> Policy {
    if tier == "T2" {
        p.waive.insert(HardDenyClass::TrustHandoff);
    }
    p
}

#[cfg(target_os = "macos")]
fn for_tier(p: Policy, _tier: &str) -> Policy {
    p
}

// ---- helpers -----------------------------------------------------------

fn abs(p: &Path) -> AbsPath {
    AbsPath::new(p.as_os_str().as_encoded_bytes()).unwrap()
}

fn scratch(tag: &str) -> Scratch {
    Scratch::at(
        std::fs::canonicalize(std::env::temp_dir())
            .unwrap()
            .join(format!("procage-exec-{}-{tag}", std::process::id())),
    )
}

/// Base profile V1, fork, exec anywhere, write to `dir`.
fn policy(dir: &Path, tier: &str) -> Policy {
    let mut p = Policy::default();
    p.base = Base::V1;
    p.process.fork = true;
    p.process.exec = Exec::Any;
    p.fs.push(FsRule::new(Access::Write, FsTarget::Subpath(abs(dir))));
    for_tier(p, tier)
}

/// The calling process can still write outside every policy.
fn assert_unconfined() {
    let probe = std::env::temp_dir().join(format!("procage-exec-free-{}", std::process::id()));
    std::fs::write(&probe, "free").expect("the process must be unconfined after a refusal");
    let _ = std::fs::remove_file(probe);
}

/// Whether `pid` lives and is not a zombie (killed orphans stay zombies in
/// a container whose first process does not reap).
fn alive(pid: u32) -> bool {
    if let Ok(stat) = std::fs::read_to_string(format!("/proc/{pid}/stat")) {
        let state = stat
            .rfind(')')
            .and_then(|i| stat[i + 1..].split_whitespace().next());
        return state != Some("Z");
    }
    Command::new("/bin/kill")
        .args(["-0", &pid.to_string()])
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

fn gone_within(pid: u32, timeout: Duration) -> bool {
    let start = Instant::now();
    while start.elapsed() < timeout {
        if !alive(pid) {
            return true;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    false
}

fn kill_group(pgid: u32) {
    let _ = Command::new("/bin/sh")
        .args(["-c", &format!("kill -9 -- -{pgid}")])
        .status();
}

/// This binary as a helper in its own process group, with stdout piped.
fn helper(role: &str, tier: &str, env: &[(&str, &str)]) -> Child {
    let mut cmd = Command::new(std::env::current_exe().unwrap());
    cmd.env(ROLE, role)
        .env("PROCAGE_TIER", tier)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .process_group(0);
    for (k, v) in env {
        cmd.env(k, v);
    }
    cmd.spawn().unwrap()
}

fn lines(child: &mut Child) -> impl Iterator<Item = String> {
    BufReader::new(child.stdout.take().unwrap())
        .lines()
        .map_while(Result::ok)
}

// ---- the helper role ---------------------------------------------------

/// Runs as the helper: builds the cage and execs; exits 126 on failure.
fn as_helper(role: &str) -> ! {
    let var = |k: &str| std::env::var(k).unwrap_or_default();
    let tier = var("PROCAGE_TIER");
    let dir = PathBuf::from(var("IN"));
    let mut p = policy(&dir, &tier);
    let mut cmd = Command::new("/bin/sh");
    match role {
        "shell" => {
            cmd.args(["-c", &var("SCRIPT")])
                .env("IN", var("IN"))
                .env("OUT", var("OUT"));
        }
        "env" => {
            p.env = EnvPolicy::Passthrough { deny: vec![] };
            cmd = Command::new("/usr/bin/env");
            cmd.env_clear().env("A", "1");
        }
        "threads" => {
            std::thread::spawn(|| std::thread::sleep(Duration::from_secs(60)));
            cmd.args(["-c", "echo ok"]);
        }
        other => panic!("unknown role {other}"),
    }
    // A directory the command may read, as a real helper would choose.
    cmd.current_dir(&dir);
    let mut options = options(&tier);
    if var("REPORT") == "1" {
        options = options.with_violations();
    }
    let cage = Cage::with_options(&p, &options).unwrap_or_else(|e| panic!("{e}"));
    let err = cage.exec(&mut cmd, &Grants::new());
    eprintln!("helper: {err}");
    std::process::exit(126);
}

// ---- cases -------------------------------------------------------------

/// The command has the helper's pid, writes only where the policy lets it,
/// and its exit code is the helper's.
fn becomes_the_command(tier: &str) {
    let inside = scratch(&format!("in-{tier}"));
    let outside = scratch(&format!("out-{tier}"));
    let script = r#"echo pid=$$; echo x > "$IN/f" && echo in=ok; (echo x > "$OUT/f") 2>/dev/null || echo out=denied; exit 7"#;
    let mut h = helper(
        "shell",
        tier,
        &[
            ("IN", inside.to_str().unwrap()),
            ("OUT", outside.to_str().unwrap()),
            ("SCRIPT", script),
        ],
    );
    let pid = h.id();
    let out: Vec<String> = lines(&mut h).collect();
    let status = h.wait().unwrap();
    assert_eq!(
        out,
        [format!("pid={pid}"), "in=ok".into(), "out=denied".into()],
        "{tier}"
    );
    assert_eq!(status.code(), Some(7), "{tier}");
    assert!(inside.join("f").exists() && !outside.join("f").exists());
}

/// `env_clear` on the command keeps the helper's environment out, even under
/// passthrough.
fn env_clear_keeps_secrets_out(tier: &str) {
    let dir = scratch(&format!("env-{tier}"));
    let mut h = helper(
        "env",
        tier,
        &[("IN", dir.to_str().unwrap()), ("PROCAGE_SECRET", "s")],
    );
    let out: Vec<String> = lines(&mut h).collect();
    assert!(h.wait().unwrap().success(), "{tier}");
    assert_eq!(out, ["A=1"], "{tier}");
}

/// The command stays in the process group it was started in, even when it
/// does not lead it: killing that group ends the command and a background
/// descendant. (A shell leads the group and starts the helper without
/// replacing itself.)
fn a_group_kill_ends_everything(tier: &str) {
    let dir = scratch(&format!("kill-{tier}"));
    let exe = std::env::current_exe().unwrap();
    let mut leader = Command::new("/bin/sh")
        .args(["-c", r#""$0"; true"#, exe.to_str().unwrap()])
        .env(ROLE, "shell")
        .env("PROCAGE_TIER", tier)
        .env("IN", dir.as_os_str())
        .env("SCRIPT", "/bin/sleep 30 & echo pid=$$ bg=$!; wait")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .process_group(0)
        .spawn()
        .unwrap();
    let line = lines(&mut leader).find(|l| l.starts_with("pid=")).unwrap();
    let pids: Vec<u32> = line
        .split(' ')
        .map(|kv| kv.split_once('=').unwrap().1.parse().unwrap())
        .collect();
    assert_ne!(pids[0], leader.id(), "the helper must not lead the group");
    assert!(pids.iter().all(|&p| alive(p)), "{tier}");
    kill_group(leader.id());
    let _ = leader.wait();
    for pid in pids {
        assert!(
            gone_within(pid, Duration::from_secs(2)),
            "{tier}: {pid} survived"
        );
    }
}

/// A helper that started a thread still execs (macOS; Linux tier T2).
fn a_threaded_helper_execs(tier: &str) {
    if tier == "T1" {
        return;
    }
    let dir = scratch(&format!("threads-{tier}"));
    let mut h = helper("threads", tier, &[("IN", dir.to_str().unwrap())]);
    let out: Vec<String> = lines(&mut h).collect();
    assert!(h.wait().unwrap().success(), "{tier}");
    assert_eq!(out, ["ok"], "{tier}");
}

/// Linux: a descendant of the command cannot start its own session.
#[cfg(target_os = "linux")]
fn descendants_cannot_leave_the_group(tier: &str) {
    if !Path::new("/usr/bin/setsid").exists() {
        println!("  (no /usr/bin/setsid: skipped)");
        return;
    }
    let dir = scratch(&format!("setsid-{tier}"));
    let script = "/usr/bin/setsid /bin/true 2>/dev/null; echo setsid=$?";
    let mut h = helper(
        "shell",
        tier,
        &[("IN", dir.to_str().unwrap()), ("SCRIPT", script)],
    );
    let out: Vec<String> = lines(&mut h).collect();
    h.wait().unwrap();
    assert_eq!(out, ["setsid=1"], "{tier}");
}

/// Linux: an exec'd command has no supervisor, so a reporting cage still
/// has the kernel answer refused calls with EPERM (not ENOSYS, which a
/// listener nobody holds would give).
#[cfg(target_os = "linux")]
fn a_reporting_exec_still_gets_eperm(tier: &str) {
    if !Path::new("/usr/bin/setsid").exists() {
        println!("  (no /usr/bin/setsid: skipped)");
        return;
    }
    let dir = scratch(&format!("report-{tier}"));
    let script = "/usr/bin/setsid /bin/true 2>&1 | head -1";
    let mut h = helper(
        "shell",
        tier,
        &[
            ("IN", dir.to_str().unwrap()),
            ("SCRIPT", script),
            ("REPORT", "1"),
        ],
    );
    let out: Vec<String> = lines(&mut h).collect();
    h.wait().unwrap();
    assert!(
        out.len() == 1 && out[0].contains("Operation not permitted"),
        "{tier}: {out:?}"
    );
}

/// Linux: the command dies when the helper's parent exits.
#[cfg(target_os = "linux")]
fn the_command_dies_with_the_helpers_parent(tier: &str) {
    let dir = scratch(&format!("parent-{tier}"));
    let exe = std::env::current_exe().unwrap();
    let out = Command::new("/bin/sh")
        .args([
            "-c",
            r#""$0" & echo $!; /bin/sleep 1"#,
            exe.to_str().unwrap(),
        ])
        .env(ROLE, "shell")
        .env("PROCAGE_TIER", tier)
        .env("IN", dir.as_os_str())
        .env("SCRIPT", "/bin/sleep 30")
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .unwrap();
    let pid: u32 = String::from_utf8_lossy(&out.stdout).trim().parse().unwrap();
    assert!(
        gone_within(pid, Duration::from_secs(2)),
        "{tier}: the command outlived its parent"
    );
}

/// The `tmpdir` grant is refused before anything changes.
fn the_tmpdir_grant_is_refused(tier: &str) {
    let dir = scratch(&format!("tmpdir-{tier}"));
    let mut p = policy(&dir, tier);
    p.grants.push(Grant {
        name: GrantName::new("tmpdir").unwrap(),
        access: Access::Write,
    });
    let cage = Cage::with_options(&p, &options(tier)).unwrap();
    let err = cage.exec(&mut Command::new("/bin/sh"), &Grants::new());
    assert!(
        matches!(err, SpawnError::Grant(GrantError::TmpdirWithExec)),
        "{err}"
    );
    assert!(err.to_string().contains("Cage::spawn"), "{err}");
    assert_unconfined();
}

/// A program that cannot be found is refused before anything changes.
fn a_missing_program_is_refused(tier: &str) {
    let dir = scratch(&format!("missing-{tier}"));
    let cage = Cage::with_options(&policy(&dir, tier), &options(tier)).unwrap();
    for program in ["/nonexistent/procage-program", "procage-no-such-program"] {
        let err = cage.exec(&mut Command::new(program), &Grants::new());
        match &err {
            SpawnError::Io(e) => assert_eq!(e.kind(), std::io::ErrorKind::NotFound, "{err}"),
            other => panic!("{tier}: {other}"),
        }
        assert!(err.to_string().contains("procage"), "{err}");
        assert_unconfined();
    }
}

/// Linux T1: a process with a second thread is refused before anything
/// changes. Runs last: the thread stays.
#[cfg(target_os = "linux")]
fn a_threaded_caller_is_refused_on_t1(tier: &str) {
    if tier != "T1" {
        return;
    }
    let dir = scratch("threads-t1");
    let cage = Cage::with_options(&policy(&dir, tier), &options(tier)).unwrap();
    std::thread::spawn(|| std::thread::sleep(Duration::from_secs(600)));
    std::thread::sleep(Duration::from_millis(50));
    let err = cage.exec(&mut Command::new("/bin/sh"), &Grants::new());
    assert!(
        matches!(
            err,
            SpawnError::Unsupported(procage::linux::Unsupported::ExecThreads { threads }) if threads >= 2
        ),
        "{err}"
    );
    assert!(err.to_string().contains("tier T2"), "{err}");
    assert_unconfined();
}

type Case = (&'static str, fn(&str));

fn cases() -> Vec<Case> {
    #[cfg_attr(not(target_os = "linux"), allow(unused_mut))]
    let mut cases: Vec<Case> = vec![
        ("becomes_the_command", becomes_the_command),
        ("env_clear_keeps_secrets_out", env_clear_keeps_secrets_out),
        ("a_group_kill_ends_everything", a_group_kill_ends_everything),
        ("a_threaded_helper_execs", a_threaded_helper_execs),
        ("the_tmpdir_grant_is_refused", the_tmpdir_grant_is_refused),
        ("a_missing_program_is_refused", a_missing_program_is_refused),
    ];
    #[cfg(target_os = "linux")]
    cases.extend([
        (
            "descendants_cannot_leave_the_group",
            descendants_cannot_leave_the_group as fn(&str),
        ),
        (
            "the_command_dies_with_the_helpers_parent",
            the_command_dies_with_the_helpers_parent,
        ),
        (
            "a_reporting_exec_still_gets_eperm",
            a_reporting_exec_still_gets_eperm,
        ),
        (
            "a_threaded_caller_is_refused_on_t1",
            a_threaded_caller_is_refused_on_t1,
        ),
    ]);
    cases
}

fn main() {
    if let Ok(role) = std::env::var(ROLE) {
        as_helper(&role);
    }
    // Arguments that are not flags filter by name, as with libtest.
    let filters: Vec<String> = std::env::args()
        .skip(1)
        .filter(|a| !a.starts_with('-'))
        .collect();
    let (mut passed, mut failed) = (0, 0);
    for tier in tiers() {
        for (name, case) in cases() {
            if !filters.is_empty() && !filters.iter().any(|f| name.contains(f.as_str())) {
                continue;
            }
            println!("test {name} ({tier}) ...");
            match std::panic::catch_unwind(|| case(&tier)) {
                Ok(()) => passed += 1,
                Err(_) => {
                    println!("test {name} ({tier}) ... FAILED");
                    failed += 1;
                }
            }
        }
    }
    println!("\ntest result: passed {passed}; failed {failed}");
    if failed > 0 {
        std::process::exit(101);
    }
}
