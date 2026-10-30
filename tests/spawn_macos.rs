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
use std::process::{Child, Command, Output, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use procage::macos::{
    ApplyMethod, Cage, CageOptions, GrantError, Grants, SpawnError, Step, Unsupported, probe,
    testing,
};
use procage::policy::{
    AbsPath, Access, EnvPolicy, FsRule, FsTarget, Glob, Grant, GrantName, Network, Policy, Port,
    Ports, Tty,
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
fn in_child(action: &str, mut policy: Policy) -> String {
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
    let cage = Cage::new(&policy).unwrap();
    let mut cmd = Command::new(&exe);
    cmd.args(["--exact", "child_entry", "--nocapture", "--test-threads=1"])
        .env("PROCAGE_CHILD", action)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let out = run(&cage, cmd, &Grants::new());
    let stdout = String::from_utf8_lossy(&out.stdout);
    stdout
        .lines()
        .find_map(|l| l.split_once("result: ").map(|(_, r)| r))
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
        other => format!("unknown action {other}"),
    };
    println!("result: {result}");
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
