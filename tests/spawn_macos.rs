//! Caged children on the running macOS kernel.
//!
//! Every test spawns a real child in a cage and observes what the kernel lets
//! it do. Run them from a plain terminal: inside another Seatbelt sandbox
//! (for example an AI agent's) spawning returns `AlreadySandboxed` and these
//! tests fail rather than skip.
//!
//! Some checks need code inside the cage. For those this test binary runs
//! itself as the caged child (`child_entry`), selected by `PROCAGE_CHILD`.

#![cfg(target_os = "macos")]

use std::io::Read;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use procage::macos::{
    ApplyMethod, Cage, CageOptions, Child, GrantError, Grants, SpawnError, Step, Unsupported,
    probe, testing,
};
use procage::policy::presets;
use procage::policy::{
    AbsPath, Access, Base, EnvPolicy, FsRule, FsTarget, Glob, Grant, GrantName, HardDenyClass,
    Network, Policy, Port, Ports, Tty,
};
use procage::policy::{linux, seatbelt};

static COUNTER: AtomicUsize = AtomicUsize::new(0);

/// A fresh directory under the system temp dir (reached through a symlink).
fn scratch(tag: &str) -> PathBuf {
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("procage-{}-{tag}-{n}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn abs(p: impl AsRef<Path>) -> AbsPath {
    AbsPath::new(p.as_ref().as_os_str().as_encoded_bytes()).unwrap()
}

fn rule(access: Access, p: impl AsRef<Path>) -> FsRule {
    FsRule::new(access, FsTarget::Subpath(abs(p)))
}

/// What a program needs to start under `(deny default)` on macOS 26.6.2:
/// exec of the binary, read + map of `/usr/lib` and `/System`, read of `/`.
fn base() -> Policy {
    let mut p = Policy::default();
    for dir in ["/usr/lib", "/System", "/bin", "/usr/bin"] {
        p.fs.push(rule(Access::Exec, dir));
    }
    p.fs.push(FsRule::new(Access::Read, FsTarget::Literal(abs("/"))));
    p
}

fn command(program: &str, args: &[&Path]) -> Command {
    let mut c = Command::new(program);
    c.args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    c
}

/// Waits up to `timeout`; kills and panics on a hang.
fn finish(mut child: Child, timeout: Duration) -> Output {
    let start = Instant::now();
    loop {
        if child.try_wait().unwrap().is_some() {
            break;
        }
        if start.elapsed() > timeout {
            let _ = child.kill();
            panic!("child hung for more than {timeout:?}");
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    let mut out = Output {
        status: child.wait().unwrap(),
        stdout: Vec::new(),
        stderr: Vec::new(),
    };
    child
        .stdout
        .take()
        .unwrap()
        .read_to_end(&mut out.stdout)
        .unwrap();
    child
        .stderr
        .take()
        .unwrap()
        .read_to_end(&mut out.stderr)
        .unwrap();
    out
}

fn run(cage: &Cage, mut cmd: Command, grants: &Grants) -> Output {
    let child = cage
        .spawn(&mut cmd, grants)
        .unwrap_or_else(|e| panic!("spawn: {e}"));
    finish(child, Duration::from_secs(10))
}

fn denied(out: &Output) -> bool {
    !out.status.success()
        && String::from_utf8_lossy(&out.stderr).contains("Operation not permitted")
}

// ---- User story 1: a cage that holds ----

#[test]
fn reads_inside_the_grant_and_is_refused_outside() {
    let (a, b) = (scratch("read-a"), scratch("read-b"));
    std::fs::write(a.join("a.txt"), "inside").unwrap();
    std::fs::write(b.join("b.txt"), "outside").unwrap();
    let mut p = base();
    p.fs.push(rule(Access::Read, &a));
    let cage = Cage::new(&p).unwrap();
    let ok = run(
        &cage,
        command("/bin/cat", &[&a.join("a.txt")]),
        &Grants::new(),
    );
    assert!(
        ok.status.success(),
        "{}",
        String::from_utf8_lossy(&ok.stderr)
    );
    assert_eq!(ok.stdout, b"inside");
    let refused = run(
        &cage,
        command("/bin/cat", &[&b.join("b.txt")]),
        &Grants::new(),
    );
    assert!(denied(&refused), "{refused:?}");
}

#[test]
fn a_protected_subtree_cannot_be_written() {
    let w = scratch("write");
    std::fs::create_dir(w.join("protected")).unwrap();
    let mut p = base();
    p.fs.push(rule(Access::Write, &w));
    p.fs.push(rule(Access::Protect, w.join("protected")));
    let cage = Cage::new(&p).unwrap();
    let ok = run(
        &cage,
        command("/usr/bin/touch", &[&w.join("x")]),
        &Grants::new(),
    );
    assert!(
        ok.status.success(),
        "{}",
        String::from_utf8_lossy(&ok.stderr)
    );
    assert!(w.join("x").exists());
    let refused = run(
        &cage,
        command("/usr/bin/touch", &[&w.join("protected/y")]),
        &Grants::new(),
    );
    assert!(denied(&refused), "{refused:?}");
    assert!(!w.join("protected/y").exists());
}

#[test]
fn network_only_as_the_policy_says() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let probe = |net: Network| {
        let mut p = base();
        p.net = net;
        let cage = Cage::new(&p).unwrap();
        let mut cmd = Command::new("/usr/bin/nc");
        cmd.args(["-z", "-n", "-w", "2", "127.0.0.1", &port.to_string()])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        run(&cage, cmd, &Grants::new())
    };
    let none = probe(Network::None);
    assert!(!none.status.success(), "connected without network access");
    let allowed = probe(Network::Loopback(Ports::List(
        [Port::new(port).unwrap()].into(),
    )));
    assert!(
        allowed.status.success(),
        "{}",
        String::from_utf8_lossy(&allowed.stderr)
    );
}

#[test]
fn a_failed_step_never_runs_the_target() {
    let w = scratch("failed-step");
    let mut p = base();
    p.fs.push(rule(Access::Write, &w));
    p.limits.nofile = Some(u64::MAX);
    let cage = Cage::new(&p).unwrap();
    let marker = w.join("marker");
    let err = cage
        .spawn(&mut command("/usr/bin/touch", &[&marker]), &Grants::new())
        .unwrap_err();
    assert!(
        matches!(
            err,
            SpawnError::Apply {
                step: Step::Rlimit,
                ..
            }
        ),
        "{err}"
    );
    assert!(!marker.exists());
}

#[test]
fn a_target_the_policy_does_not_let_run_is_refused() {
    let w = scratch("no-exec");
    let mut p = Policy::default();
    for dir in ["/usr/lib", "/System"] {
        p.fs.push(rule(Access::Exec, dir));
    }
    p.fs.push(FsRule::new(Access::Read, FsTarget::Literal(abs("/"))));
    p.fs.push(rule(Access::Write, &w));
    let cage = Cage::new(&p).unwrap();
    let marker = w.join("marker");
    match cage.spawn(&mut command("/usr/bin/touch", &[&marker]), &Grants::new()) {
        Err(SpawnError::Io(e)) => assert_eq!(e.kind(), std::io::ErrorKind::PermissionDenied, "{e}"),
        other => panic!("expected a permission error, got {other:?}"),
    }
    assert!(!marker.exists());
}

#[test]
fn contention_every_child_is_caged_and_none_hangs() {
    let secret = scratch("contention");
    std::fs::write(secret.join("s.txt"), "secret").unwrap();
    let cage = Cage::new(&base()).unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let churn: Vec<_> = (0..4)
        .map(|_| {
            let stop = stop.clone();
            std::thread::spawn(move || testing::dyld_churn(&stop))
        })
        .collect();
    let mut caged = 0;
    for _ in 0..100 {
        let out = run(
            &cage,
            command("/bin/cat", &[&secret.join("s.txt")]),
            &Grants::new(),
        );
        if denied(&out) {
            caged += 1;
        }
    }
    stop.store(true, Ordering::Relaxed);
    for t in churn {
        t.join().unwrap();
    }
    assert_eq!(caged, 100);
}

// ---- User story 2: paths mean what was written ----

fn tmp_dir(tag: &str) -> PathBuf {
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let dir = PathBuf::from(format!("/tmp/procage-{}-{tag}-{n}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn a_tmp_spelling_works_as_written() {
    let dir = tmp_dir("spelling");
    let mut p = base();
    p.fs.push(rule(Access::Write, &dir));
    let cage = Cage::new(&p).unwrap();
    let to = format!("/private{}", dir.display());
    assert!(
        cage.rewrites()
            .iter()
            .any(|r| r.from == dir.display().to_string() && r.to == to),
        "{:?}",
        cage.rewrites()
    );
    let ok = run(
        &cage,
        command("/usr/bin/touch", &[&dir.join("x")]),
        &Grants::new(),
    );
    assert!(
        ok.status.success(),
        "{}",
        String::from_utf8_lossy(&ok.stderr)
    );
}

#[test]
fn a_missing_leaf_keeps_its_remainder() {
    let dir = tmp_dir("leaf");
    let mut p = base();
    p.fs.push(rule(Access::Write, dir.join("not/yet")));
    let cage = Cage::new(&p).unwrap();
    let to = format!("/private{}/not/yet", dir.display());
    assert!(
        cage.rewrites().iter().any(|r| r.to == to),
        "{:?}",
        cage.rewrites()
    );
}

#[test]
fn glob_characters_in_a_resolved_prefix_are_literal() {
    let dir = tmp_dir("glob");
    std::fs::create_dir(dir.join("real*dir")).unwrap();
    std::fs::create_dir(dir.join("realXdir")).unwrap();
    std::fs::write(dir.join("real*dir/f.txt"), "match").unwrap();
    std::fs::write(dir.join("realXdir/f.txt"), "sibling").unwrap();
    std::os::unix::fs::symlink(dir.join("real*dir"), dir.join("link")).unwrap();
    let mut p = base();
    let glob = Glob::new(&format!("{}/link/*.txt", dir.display())).unwrap();
    p.fs.push(FsRule::new(Access::Read, FsTarget::Glob(glob)));
    let cage = Cage::new(&p).unwrap();
    assert!(
        cage.rewrites()
            .iter()
            .any(|r| r.to.ends_with("real\\*dir/*.txt")),
        "{:?}",
        cage.rewrites()
    );
    let ok = run(
        &cage,
        command("/bin/cat", &[&dir.join("real*dir/f.txt")]),
        &Grants::new(),
    );
    assert_eq!(
        ok.stdout,
        b"match",
        "{}",
        String::from_utf8_lossy(&ok.stderr)
    );
    let sibling = run(
        &cage,
        command("/bin/cat", &[&dir.join("realXdir/f.txt")]),
        &Grants::new(),
    );
    assert!(denied(&sibling), "{sibling:?}");
}

#[test]
fn a_data_volume_spelling_resolves_to_the_visible_one() {
    let home = PathBuf::from(std::env::var_os("HOME").expect("HOME"));
    let data = PathBuf::from(format!("/System/Volumes/Data{}", home.display()));
    if !data.exists() {
        panic!("{} does not exist on this machine", data.display());
    }
    let mut p = base();
    p.fs.push(rule(Access::Read, &data));
    let cage = Cage::new(&p).unwrap();
    let home = std::fs::canonicalize(&home).unwrap();
    assert!(
        cage.rewrites()
            .iter()
            .any(|r| r.from == data.display().to_string() && r.to == home.display().to_string()),
        "{:?}",
        cage.rewrites()
    );
}

// ---- User story 3: compile once, grants per spawn ----

fn grant_policy() -> Policy {
    let mut p = base();
    p.grants.push(Grant {
        name: GrantName::new("scratch").unwrap(),
        access: Access::Write,
    });
    p
}

#[test]
fn a_grant_binds_for_one_spawn_only() {
    let (a, b) = (scratch("grant-a"), scratch("grant-b"));
    let cage = Cage::new(&grant_policy()).unwrap();
    let touch = |n: &str| command("/usr/bin/touch", &[&a.join(n), &b.join(n)]);
    run(&cage, touch("one"), &Grants::new().bind("scratch", &a));
    run(&cage, touch("two"), &Grants::new().bind("scratch", &b));
    run(&cage, touch("three"), &Grants::new());
    assert!(a.join("one").exists() && !b.join("one").exists());
    assert!(b.join("two").exists() && !a.join("two").exists());
    assert!(!a.join("three").exists() && !b.join("three").exists());
}

#[test]
fn wrong_bindings_are_typed_errors() {
    let a = scratch("grant-err");
    let cage = Cage::new(&grant_policy()).unwrap();
    let err = cage
        .spawn(
            &mut command("/usr/bin/true", &[]),
            &Grants::new().bind("nope", &a),
        )
        .unwrap_err();
    assert!(
        matches!(err, SpawnError::Grant(GrantError::Undeclared { .. })),
        "{err}"
    );
    let err = cage
        .spawn(
            &mut command("/usr/bin/true", &[]),
            &Grants::new().bind("scratch", a.join("missing")),
        )
        .unwrap_err();
    assert!(
        matches!(err, SpawnError::Grant(GrantError::Missing { .. })),
        "{err}"
    );
}

#[test]
fn the_same_policy_is_compiled_once() {
    let dir = scratch("cache");
    let mut p = base();
    p.fs.push(rule(Access::Read, &dir));
    assert!(Cage::new(&p).unwrap().compiled());
    assert!(!Cage::new(&p).unwrap().compiled());
    p.fs.push(rule(Access::Read, dir.join("other")));
    assert!(Cage::new(&p).unwrap().compiled());
}

#[test]
fn one_cage_spawns_from_several_threads() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<Cage>();
    let dir = scratch("threads");
    std::fs::write(dir.join("f"), "x").unwrap();
    let mut p = base();
    p.fs.push(rule(Access::Read, &dir));
    let cage = Arc::new(Cage::new(&p).unwrap());
    let handles: Vec<_> = (0..2)
        .map(|_| {
            let (cage, file) = (cage.clone(), dir.join("f"));
            std::thread::spawn(move || {
                (0..10).all(|_| {
                    run(&cage, command("/bin/cat", &[&file]), &Grants::new())
                        .status
                        .success()
                })
            })
        })
        .collect();
    assert!(handles.into_iter().all(|h| h.join().unwrap()));
}

// ---- User story 4: never nest, never weaker; checks inside the child ----

/// Runs this test binary as a caged child performing `action`; returns its
/// `result:` line.
fn in_child(action: &str, policy: Policy) -> String {
    in_child_with(action, policy, &[], |_| {})
}

/// The policy for running this test binary as a caged child.
fn child_policy(mut policy: Policy) -> Policy {
    let exe = std::env::current_exe().unwrap();
    policy.fs.push(FsRule::new(
        Access::Exec,
        FsTarget::Literal(abs(std::fs::canonicalize(&exe).unwrap())),
    ));
    // The Rust runtime reads sysctls (the page size) when it starts.
    policy
        .seatbelt
        .get_or_insert_with(Default::default)
        .rules
        .push(seatbelt::Rule {
            effect: seatbelt::Effect::Allow,
            ops: vec![seatbelt::Operation::SysctlRead],
            filters: vec![],
        });
    policy
}

/// This test binary as a caged child performing `action`.
fn child_command(action: &str) -> Command {
    let mut cmd = Command::new(std::env::current_exe().unwrap());
    cmd.args(["--exact", "child_entry", "--nocapture", "--test-threads=1"])
        .env("PROCAGE_CHILD", action)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    cmd
}

/// Runs `action` in a caged child with `fds` handed over; `adjust` may
/// change the command first. Returns the child's `result:` line.
fn in_child_with(
    action: &str,
    policy: Policy,
    fds: &[std::os::fd::BorrowedFd<'_>],
    adjust: impl FnOnce(&mut Command),
) -> String {
    let cage = Cage::new(&child_policy(policy)).unwrap();
    let mut cmd = child_command(action);
    adjust(&mut cmd);
    let child = cage
        .spawn_with_fds(&mut cmd, &Grants::new(), fds)
        .unwrap_or_else(|e| panic!("spawn: {e}"));
    let out = finish(child, Duration::from_secs(10));
    let stdout = String::from_utf8_lossy(&out.stdout);
    stdout
        .lines()
        .find_map(|l| l.split_once("procage-result: ").map(|(_, r)| r))
        .map(str::to_string)
        .unwrap_or_else(|| {
            panic!(
                "no result from the child:\n{stdout}\n{}",
                String::from_utf8_lossy(&out.stderr)
            )
        })
}

#[test]
fn child_entry() {
    let Ok(action) = std::env::var("PROCAGE_CHILD") else {
        return;
    };
    let result = match action.as_str() {
        "nested" => match Cage::new(&base())
            .and_then(|c| c.spawn(&mut Command::new("/usr/bin/true"), &Grants::new()))
        {
            Err(SpawnError::AlreadySandboxed) => "already-sandboxed".to_string(),
            other => format!("unexpected {other:?}"),
        },
        "session" => format!("leader={}", testing::is_session_leader()),
        "group" => format!(
            "session-leader={} group-leader={}",
            testing::is_session_leader(),
            testing::is_group_leader()
        ),
        "rlimit" => {
            let (nofile, core) = testing::nofile_and_core().unwrap();
            format!("nofile={nofile} core={core}")
        }
        "env" => {
            let mut names: Vec<String> = std::env::vars_os()
                .map(|(k, _)| k.to_string_lossy().into_owned())
                .collect();
            names.sort();
            names.join(",")
        }
        "fdcount" => {
            let open = (3..4096).filter(|&fd| testing::fd_is_open(fd)).count();
            format!("fdcount={open}")
        }
        fd if fd.starts_with("fd:") => {
            let n: i32 = fd[3..].parse().unwrap();
            format!("open={}", testing::fd_is_open(n))
        }
        "sleepers" => {
            let same = testing::spawn_sleeper(false).unwrap();
            let session = testing::spawn_sleeper(true).unwrap();
            println!("procage-result: {same} {session}");
            std::thread::sleep(Duration::from_secs(30));
            return;
        }
        "sleeper-exit" => format!("{}", testing::spawn_sleeper(false).unwrap()),
        "tmpdir" => {
            let dir = std::env::var("TMPDIR").unwrap_or_default();
            let wrote = std::fs::write(Path::new(&dir).join("f"), "x").is_ok();
            format!("{dir} wrote={wrote}")
        }
        "outer-env" => outer_env(),
        other => format!("unknown action {other}"),
    };
    println!("procage-result: {result}");
}

/// Runs uncaged with secret-looking variables in its environment and
/// reports what a passthrough child sees.
fn outer_env() -> String {
    let mut p = base();
    p.env = EnvPolicy::Passthrough { deny: vec![] };
    let cage = Cage::new(&child_policy(p)).unwrap();
    let mut cmd = child_command("env");
    let child = cage.spawn(&mut cmd, &Grants::new()).unwrap();
    let dropped = child.dropped_env().join(",");
    let seen = String::from_utf8_lossy(&finish(child, Duration::from_secs(10)).stdout).into_owned();
    let mut cmd = child_command("env");
    cmd.env("GITHUB_TOKEN", "explicit");
    let child = cage.spawn(&mut cmd, &Grants::new()).unwrap();
    let explicit =
        String::from_utf8_lossy(&finish(child, Duration::from_secs(10)).stdout).into_owned();
    let has = |out: &str, name: &str| {
        out.lines()
            .any(|l| l.contains("procage-result: ") && l.split([',', ' ']).any(|w| w == name))
    };
    format!(
        "dropped={dropped} token={} sock={} dyld={} explicit-token={}",
        has(&seen, "GITHUB_TOKEN"),
        has(&seen, "SSH_AUTH_SOCK"),
        has(&seen, "DYLD_PROCAGE_PROBE"),
        has(&explicit, "GITHUB_TOKEN")
    )
}

// ---- 005: hygiene ----

#[test]
fn an_inherited_descriptor_does_not_reach_the_child() {
    let dir = scratch("fd-leak");
    std::fs::write(dir.join("secret"), "secret").unwrap();
    let file = std::fs::File::open(dir.join("secret")).unwrap();
    use std::os::fd::{AsFd, AsRawFd};
    let fd = file.as_raw_fd();
    assert!(testing::clear_cloexec(fd));
    assert_eq!(in_child(&format!("fd:{fd}"), base()), "open=false");
    assert_eq!(
        in_child_with(&format!("fd:{fd}"), base(), &[file.as_fd()], |_| {}),
        "open=true"
    );
    // Naming a standard descriptor is a no-op.
    let stdout = std::io::stdout();
    assert_eq!(
        in_child_with(&format!("fd:{fd}"), base(), &[stdout.as_fd()], |_| {}),
        "open=false"
    );
}

#[test]
fn a_thousand_open_descriptors_are_all_closed() {
    let dir = scratch("fd-flood");
    std::fs::write(dir.join("f"), "x").unwrap();
    let files: Vec<std::fs::File> = (0..1000)
        .map(|_| std::fs::File::open(dir.join("f")).unwrap())
        .collect();
    use std::os::fd::AsRawFd;
    for f in &files {
        assert!(testing::clear_cloexec(f.as_raw_fd()));
    }
    assert_eq!(in_child("fdcount", base()), "fdcount=0");
}

#[test]
fn a_failed_step_after_the_sweep_is_still_reported() {
    let mut p = base();
    p.limits.nofile = Some(u64::MAX);
    let cage = Cage::new(&p).unwrap();
    let err = cage
        .spawn(&mut Command::new("/usr/bin/true"), &Grants::new())
        .unwrap_err();
    assert!(
        matches!(
            err,
            SpawnError::Apply {
                step: Step::Rlimit,
                ..
            }
        ),
        "{err}"
    );
}

fn forking_policy() -> Policy {
    let mut p = base();
    p.process.fork = true;
    p
}

/// Spawns `action` in a caged child and returns the handle and the first
/// `result:` line, without waiting for the child to exit.
fn start(action: &str, policy: Policy) -> (Child, String) {
    use std::io::BufRead;
    let cage = Cage::new(&child_policy(policy)).unwrap();
    let mut child = cage
        .spawn(&mut child_command(action), &Grants::new())
        .unwrap();
    let stdout = child.stdout.take().unwrap();
    let mut lines = std::io::BufReader::new(stdout).lines();
    let line = lines.find_map(|l| {
        l.ok()
            .and_then(|l| l.split_once("procage-result: ").map(|(_, r)| r.to_string()))
    });
    let Some(line) = line else {
        let mut err = String::new();
        let _ = child.stderr.take().unwrap().read_to_string(&mut err);
        panic!("no result from the child: {err}");
    };
    (child, line)
}

fn gone_within(pid: u32, timeout: Duration) -> bool {
    let start = Instant::now();
    while start.elapsed() < timeout {
        if !testing::alive(pid) {
            return true;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    false
}

#[test]
fn dropping_the_handle_kills_every_descendant() {
    let (child, pids) = start("sleepers", forking_policy());
    let pids: Vec<u32> = pids.split(' ').map(|p| p.parse().unwrap()).collect();
    assert!(pids.iter().all(|&p| testing::alive(p)));
    let leader = child.id();
    drop(child);
    assert!(gone_within(leader, Duration::from_secs(1)));
    for pid in pids {
        assert!(
            gone_within(pid, Duration::from_secs(1)),
            "descendant {pid} survived"
        );
    }
}

#[test]
fn a_reaped_leader_still_takes_its_group_down() {
    let (mut child, pid) = start("sleeper-exit", forking_policy());
    let pid: u32 = pid.parse().unwrap();
    child.wait().unwrap();
    assert!(testing::alive(pid));
    drop(child);
    assert!(
        gone_within(pid, Duration::from_secs(1)),
        "group member {pid} survived"
    );
}

#[test]
fn a_detached_child_keeps_running() {
    let (child, pids) = start("sleepers", forking_policy());
    let mut inner = child.detach();
    std::thread::sleep(Duration::from_millis(100));
    assert!(
        inner.try_wait().unwrap().is_none(),
        "the detached child was killed"
    );
    inner.kill().unwrap();
    inner.wait().unwrap();
    for pid in pids.split(' ') {
        let _ = Command::new("/bin/kill").args(["-9", pid]).status();
    }
}

#[test]
fn passthrough_drops_secrets_unless_set_explicitly() {
    let mut cmd = child_command("outer-env");
    cmd.env("GITHUB_TOKEN", "t")
        .env("SSH_AUTH_SOCK", "/tmp/agent.sock")
        .env("DYLD_PROCAGE_PROBE", "1");
    let out = cmd.output().unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    let result = stdout
        .lines()
        .find_map(|l| l.split_once("procage-result: ").map(|(_, r)| r.to_string()))
        .unwrap_or_else(|| panic!("{stdout}\n{}", String::from_utf8_lossy(&out.stderr)));
    assert!(
        result.contains("token=false sock=false dyld=false explicit-token=true"),
        "{result}"
    );
    for name in ["DYLD_PROCAGE_PROBE", "GITHUB_TOKEN", "SSH_AUTH_SOCK"] {
        assert!(result.contains(name), "{name} not reported: {result}");
    }
}

#[test]
fn each_run_gets_its_own_private_tmpdir() {
    let mut p = base();
    p.grants.push(Grant {
        name: GrantName::new("tmpdir").unwrap(),
        access: Access::Write,
    });
    let first = in_child("tmpdir", p.clone());
    let second = in_child("tmpdir", p.clone());
    let (a, b) = (
        first.split(' ').next().unwrap(),
        second.split(' ').next().unwrap(),
    );
    assert!(
        first.ends_with("wrote=true") && second.ends_with("wrote=true"),
        "{first} / {second}"
    );
    assert_ne!(a, b);
    assert!(
        !Path::new(a).exists() && !Path::new(b).exists(),
        "tmpdirs were not removed"
    );
    let cage = Cage::new(&p).unwrap();
    let err = cage
        .spawn(
            &mut Command::new("/usr/bin/true"),
            &Grants::new().bind("tmpdir", "/tmp"),
        )
        .unwrap_err();
    assert!(
        matches!(err, SpawnError::Grant(GrantError::Reserved { .. })),
        "{err}"
    );
}

#[test]
fn a_caged_process_cannot_spawn_a_nested_cage() {
    assert_eq!(in_child("nested", base()), "already-sandboxed");
}

#[test]
fn the_child_leads_its_own_session_unless_the_terminal_is_inherited() {
    assert_eq!(in_child("session", base()), "leader=true");
    let mut p = base();
    p.tty = Tty::Inherit;
    assert_eq!(in_child("session", p), "leader=false");
}

#[test]
fn with_an_inherited_terminal_the_child_still_has_its_own_group() {
    let mut p = base();
    p.tty = Tty::Inherit;
    assert_eq!(
        in_child("group", p),
        "session-leader=false group-leader=true"
    );
    assert_eq!(
        in_child("group", base()),
        "session-leader=true group-leader=true"
    );
}

#[test]
fn resource_limits_are_set_in_the_child() {
    let mut p = base();
    p.limits.nofile = Some(256);
    assert_eq!(in_child("rlimit", p), "nofile=256 core=0");
}

#[test]
fn the_environment_is_the_policys() {
    assert!(std::env::var_os("HOME").is_some() && std::env::var_os("PATH").is_some());
    let mut p = base();
    p.env = EnvPolicy::Allowlist(vec!["PATH".into()]);
    assert_eq!(in_child("env", p), "PATH,PROCAGE_CHILD");
    let mut p = base();
    p.env = EnvPolicy::Passthrough {
        deny: vec!["HOME".into()],
    };
    let names = in_child("env", p);
    let names: Vec<&str> = names.split(',').collect();
    assert!(
        !names.contains(&"HOME") && names.contains(&"PATH"),
        "{names:?}"
    );
}

#[test]
fn the_apply_method_passes_its_probe() {
    assert_eq!(probe().unwrap(), ApplyMethod::PathA);
}

#[test]
fn a_missing_symbol_is_unsupported_and_named() {
    match testing::resolve_symbol("procage_no_such_symbol") {
        Err(SpawnError::Unsupported(Unsupported::Symbol { symbol, os_build })) => {
            assert_eq!(symbol, "procage_no_such_symbol");
            assert!(!os_build.is_empty() && os_build != "unknown");
        }
        other => panic!("{other:?}"),
    }
    assert!(testing::resolve_symbol("sandbox_compile_string").is_ok());
}

#[test]
fn refusals_before_any_child() {
    let options = CageOptions::default().with_compile_limit(5);
    assert!(matches!(
        Cage::with_options(&base(), &options),
        Err(SpawnError::LimitExceeded { limit: 5, .. })
    ));
    let mut p = base();
    p.tty = Tty::NewPty;
    assert!(matches!(
        Cage::new(&p),
        Err(SpawnError::Unsupported(Unsupported::Setting {
            setting: "Tty::NewPty"
        }))
    ));
    let mut p = base();
    p.linux = Some(linux::Layer::default());
    assert!(matches!(Cage::new(&p), Err(SpawnError::Lower(_))));
}

/// SC-005 (recorded, not gated): median spawn latency, caged versus not.
#[test]
#[ignore = "measurement; run with --release --ignored --nocapture"]
fn latency() {
    // The caller holds 1,000 extra descriptors (SC-004 of the hygiene feature).
    let dir = scratch("latency");
    std::fs::write(dir.join("f"), "x").unwrap();
    let _files: Vec<std::fs::File> = (0..1000)
        .map(|_| std::fs::File::open(dir.join("f")).unwrap())
        .collect();
    let cage = Cage::new(&base()).unwrap();
    let median = |mut f: Box<dyn FnMut() -> Duration>| {
        let mut v: Vec<Duration> = (0..50).map(|_| f()).collect();
        v.sort();
        v[25]
    };
    let plain = median(Box::new(|| {
        let t = Instant::now();
        Command::new("/usr/bin/true").status().unwrap();
        t.elapsed()
    }));
    let caged = median(Box::new(|| {
        let t = Instant::now();
        let mut cmd = Command::new("/usr/bin/true");
        cage.spawn(&mut cmd, &Grants::new())
            .unwrap()
            .wait()
            .unwrap();
        t.elapsed()
    }));
    println!(
        "latency: plain {plain:?}, caged {caged:?}, overhead {:?}",
        caged.saturating_sub(plain)
    );
}

// ---- 006: base profile ----

fn base_v1() -> Policy {
    let mut p = Policy::default();
    p.base = Base::V1;
    p
}

fn outside(program: &str, args: &[&str]) -> String {
    let out = Command::new(program).args(args).output().unwrap();
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

#[test]
fn base_runs_ordinary_programs() {
    let work = scratch("base-work");
    let mut p = base_v1();
    p.fs.push(rule(Access::Read, &work));
    let cage = Cage::new(&p).unwrap();
    let cases: &[(&str, &[&str], Option<String>)] = &[
        (
            "/usr/bin/id",
            &["-un"],
            Some(outside("/usr/bin/id", &["-un"])),
        ),
        (
            "/usr/bin/whoami",
            &[],
            Some(outside("/usr/bin/whoami", &[])),
        ),
        ("/bin/date", &["+%Z"], Some(outside("/bin/date", &["+%Z"]))),
        ("/usr/bin/uname", &["-s"], Some("Darwin".into())),
        ("/bin/sh", &["-c", "echo ok"], Some("ok".into())),
        ("/bin/zsh", &["-c", "echo ok"], Some("ok".into())),
        (
            "/bin/bash",
            &["-c", "pwd >/dev/null && echo ok"],
            Some("ok".into()),
        ),
        ("/bin/cat", &["/etc/hosts"], None),
        ("/usr/bin/sort", &["/dev/null"], Some(String::new())),
        ("/usr/bin/sed", &["-n", "1p", "/etc/hosts"], None),
        ("/usr/bin/awk", &["BEGIN { print 1 + 1 }"], Some("2".into())),
        ("/usr/bin/xxd", &["-l", "4", "/dev/urandom"], None),
        ("/usr/bin/perl", &["-e", "print 42"], Some("42".into())),
        ("/usr/bin/tar", &["--version"], None),
        ("/usr/bin/gzip", &["-V"], None),
    ];
    let mut failures = Vec::new();
    for (program, args, expected) in cases {
        let mut cmd = Command::new(program);
        cmd.args(*args)
            .current_dir(&work)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let out = run(&cage, cmd, &Grants::new());
        let stdout = String::from_utf8_lossy(&out.stdout).trim().to_string();
        let ok = out.status.success() && expected.as_ref().is_none_or(|e| *e == stdout);
        if !ok {
            failures.push(format!(
                "{program} {args:?}: {:?} stdout={stdout:?} stderr={:?}",
                out.status,
                String::from_utf8_lossy(&out.stderr)
            ));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn base_runs_a_rust_program_and_dev_null_stdio() {
    // The test binary itself, with nothing but its own exec added: the base
    // covers the Rust runtime's sysctl reads.
    let exe = std::fs::canonicalize(std::env::current_exe().unwrap()).unwrap();
    let mut p = base_v1();
    p.fs.push(FsRule::new(Access::Exec, FsTarget::Literal(abs(&exe))));
    let cage = Cage::new(&p).unwrap();
    let out = run(&cage, child_command("session"), &Grants::new());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("procage-result: leader=true"),
        "{stdout}\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let mut cmd = Command::new("/bin/echo");
    cmd.arg("hi")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let status = cage
        .spawn(&mut cmd, &Grants::new())
        .unwrap()
        .wait()
        .unwrap();
    assert!(
        status.success(),
        "a child with /dev/null stdio failed: {status:?}"
    );
}

#[test]
fn base_grants_nothing_personal() {
    let home = std::env::var("HOME").unwrap();
    let tmp_file = scratch("base-personal").join("f");
    std::fs::write(&tmp_file, "secret").unwrap();
    let marker = PathBuf::from(format!("/tmp/procage-{}-base-marker", std::process::id()));
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port().to_string();
    let cage = Cage::new(&base_v1()).unwrap();
    let refused = |program: &str, args: &[&str]| {
        let mut cmd = Command::new(program);
        cmd.args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let out = run(&cage, cmd, &Grants::new());
        assert!(
            !out.status.success(),
            "{program} {args:?} succeeded under the base alone"
        );
    };
    refused("/bin/ls", &[&home]);
    refused("/usr/bin/stat", &[&home]);
    refused("/bin/cat", &[tmp_file.to_str().unwrap()]);
    refused("/usr/bin/touch", &[marker.to_str().unwrap()]);
    refused("/usr/bin/nc", &["-z", "-n", "-w", "2", "127.0.0.1", &port]);
    assert!(!marker.exists());
}

// ---- 007: data-driven hard denies and presets ----

fn succeeds(cage: &Cage, program: &str, args: &[&Path]) -> bool {
    run(cage, command(program, args), &Grants::new())
        .status
        .success()
}

#[test]
fn hard_deny_secrets() {
    let home = PathBuf::from(std::env::var("HOME").unwrap());
    for dir in [".ssh", ".aws", ".gnupg"] {
        assert!(home.join(dir).exists(), "this test needs ~/{dir} to exist");
    }
    let mut p = base_v1();
    p.fs.push(rule(Access::Read, &home));
    let cage = Cage::new(&p).unwrap();
    assert!(succeeds(&cage, "/bin/ls", &[&home]), "listing HOME failed");
    for dir in [".ssh", ".aws", ".gnupg", ".SSH"] {
        assert!(
            !succeeds(&cage, "/bin/ls", &[&home.join(dir)]),
            "~/{dir} was readable"
        );
    }
    p.waive.insert(HardDenyClass::Secrets);
    let waived = Cage::new(&p).unwrap();
    assert_eq!(waived.plan().waivers, vec![HardDenyClass::Secrets]);
    assert!(
        succeeds(&waived, "/bin/ls", &[&home.join(".ssh")]),
        "waiving secrets did not allow ~/.ssh"
    );
}

/// A writable workspace with `.git/hooks`, `.git/objects` and `src`.
fn repo(tag: &str) -> PathBuf {
    let w = scratch(tag);
    for dir in [".git/hooks", ".git/objects", ".git/refs/heads", "src"] {
        std::fs::create_dir_all(w.join(dir)).unwrap();
    }
    w
}

#[test]
fn hard_deny_trust_handoff() {
    let w = repo("handoff");
    let mut p = base_v1();
    p.fs.push(rule(Access::Write, &w));
    let cage = Cage::new(&p).unwrap();
    for refused in [
        ".git/hooks/pre-commit",
        ".git/config",
        ".gitmodules",
        ".zshrc",
        ".ZSHRC",
        ".envrc",
        ".GIT/HOOKS/post-checkout",
        "src/.bashrc",
    ] {
        assert!(
            !succeeds(&cage, "/usr/bin/touch", &[&w.join(refused)]),
            "{refused} was writable"
        );
    }
    assert!(
        !succeeds(&cage, "/bin/mkdir", &[&w.join(".vscode")]),
        ".vscode was creatable"
    );
    assert!(
        !succeeds(&cage, "/bin/mv", &[&w.join(".git"), &w.join("moved")]),
        ".git could be renamed"
    );
    assert!(w.join(".git").is_dir() && !w.join("moved").exists());
    for allowed in [
        "src/main.rs",
        ".git/objects/ab",
        ".git/index",
        ".git/HEAD",
        ".git/refs/heads/main",
        "notes.txt",
    ] {
        assert!(
            succeeds(&cage, "/usr/bin/touch", &[&w.join(allowed)]),
            "{allowed} was not writable"
        );
    }
    p.waive.insert(HardDenyClass::TrustHandoff);
    let waived = Cage::new(&p).unwrap();
    assert!(succeeds(
        &waived,
        "/usr/bin/touch",
        &[&w.join(".git/hooks/pre-commit")]
    ));
}

#[test]
fn hard_deny_persistence() {
    let agents = PathBuf::from(std::env::var("HOME").unwrap()).join("Library/LaunchAgents");
    assert!(agents.is_dir(), "this test needs ~/Library/LaunchAgents");
    let plist = agents.join(format!("procage-test-{}.plist", std::process::id()));
    let mut p = base_v1();
    p.fs.push(rule(Access::Write, &agents));
    let cage = Cage::new(&p).unwrap();
    let created = succeeds(&cage, "/usr/bin/touch", &[&plist]);
    let exists = plist.exists();
    let _ = std::fs::remove_file(&plist);
    assert!(!created && !exists, "a launch agent could be planted");
}

#[test]
fn preset_agent_workspace() {
    let w = repo("preset-ws");
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port().to_string();
    let cage = Cage::new(&presets::agent_workspace::v1(&abs(&w))).unwrap();
    assert!(succeeds(&cage, "/usr/bin/touch", &[&w.join("src/x")]));
    assert!(!succeeds(
        &cage,
        "/usr/bin/touch",
        &[&w.join(".git/hooks/x")]
    ));
    let home = PathBuf::from(std::env::var("HOME").unwrap());
    assert!(!succeeds(&cage, "/bin/ls", &[&home.join(".ssh")]));
    let mut nc = Command::new("/usr/bin/nc");
    nc.args(["-z", "-n", "-w", "2", "127.0.0.1", &port])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    assert!(
        !run(&cage, nc, &Grants::new()).status.success(),
        "agent_workspace reached the network"
    );
}

#[test]
fn preset_agent_readonly() {
    let w = scratch("preset-ro");
    std::fs::write(w.join("f"), "content").unwrap();
    let cage = Cage::new(&presets::agent_readonly::v1(&abs(&w))).unwrap();
    assert!(succeeds(&cage, "/bin/cat", &[&w.join("f")]));
    assert!(!succeeds(&cage, "/usr/bin/touch", &[&w.join("x")]));
    assert!(!w.join("x").exists());
}

#[test]
fn preset_build_runs_what_it_builds() {
    let w = scratch("preset-build");
    let cage = Cage::new(&presets::build::v1(&abs(&w))).unwrap();
    let mut write = Command::new("/bin/sh");
    write
        .args([
            "-c",
            "printf '#!/bin/sh\\necho built\\n' > run.sh && chmod +x run.sh",
        ])
        .current_dir(&w)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let out = run(&cage, write, &Grants::new());
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let out = run(
        &cage,
        command(w.join("run.sh").to_str().unwrap(), &[]),
        &Grants::new(),
    );
    assert_eq!(
        String::from_utf8_lossy(&out.stdout).trim(),
        "built",
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn preset_minimal_runs_echo() {
    let cage = Cage::new(&presets::minimal::v1()).unwrap();
    let out = run(
        &cage,
        command("/bin/echo", &[Path::new("hi")]),
        &Grants::new(),
    );
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "hi");
    assert_eq!(cage.plan().waivers, Vec::<HardDenyClass>::new());
}
