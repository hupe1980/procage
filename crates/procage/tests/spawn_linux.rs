//! Caged children on the running Linux kernel.
//!
//! Every test spawns a real child in a cage and observes what the kernel lets
//! it do. `just linux` runs them in a container under Docker's default
//! seccomp profile (tier T2) and `just linux-t1` with seccomp unconfined
//! (tier T1); `PROCAGE_EXPECT_TIER` makes a lane that measures another tier
//! fail. Tests of tier T2 also run on a T1 host, by asking for T2. Tests of
//! tier T1 only report themselves as not applicable on a T2 host.
//!
//! Some checks need code inside the cage. For those this test binary runs
//! itself as the caged child (`child_entry`), selected by `PROCAGE_CHILD`.

#![cfg(target_os = "linux")]

#[path = "support/scratch.rs"]
mod scratch_support;
use scratch_support::Scratch;

use std::io::Read;
use std::net::TcpListener;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

use procage::linux::{
    Cage, CageOptions, Child, GrantError, Grants, SpawnError, Step, Unsupported, probe, testing,
};
use procage::policy::{
    AbsPath, Access, Base, Construct, EnvPolicy, FsRule, FsTarget, GapKind, Grant, GrantName,
    HardDenyClass, LowerError, LowerOptions, Network, Policy, Signals, Tier,
};

const EACCES: i32 = 13;
const EPERM: i32 = 1;
const EROFS: i32 = 30;
const EBUSY: i32 = 16;

fn abs(p: impl AsRef<Path>) -> AbsPath {
    AbsPath::new(p.as_ref().to_str().unwrap()).unwrap()
}

/// A fresh directory for one test.
fn scratch(name: &str) -> Scratch {
    Scratch::at(std::env::temp_dir().join(format!("procage-linux-{name}-{}", std::process::id())))
        .canonical()
}

fn host_tier() -> Tier {
    probe().tier.expect("a tier: these tests need Landlock")
}

/// Whether the host gives T1; says so when it does not.
fn t1(test: &str) -> bool {
    let yes = host_tier() == Tier::T1;
    if !yes {
        println!("{test}: not applicable on tier T2");
    }
    yes
}

fn base() -> Policy {
    let mut p = Policy::default();
    p.base = Base::V1;
    p
}

/// Every data class may be approximated (T1 masks at spawn).
fn masked() -> LowerOptions {
    LowerOptions::default()
        .allow(Construct::HdSecrets)
        .allow(Construct::HdTrustHandoff)
        .allow(Construct::HdPersistence)
}

/// Options for `tier`: on T1 the data classes may be approximated.
fn options(tier: Tier) -> CageOptions {
    CageOptions::default().with_tier(tier).with_lower(masked())
}

/// The policy for running this test binary as a caged child.
fn child_policy(mut policy: Policy) -> Policy {
    let exe = std::fs::canonicalize(std::env::current_exe().unwrap()).unwrap();
    policy.fs.push(FsRule::new(
        Access::Exec,
        FsTarget::Subpath(abs(exe.parent().unwrap())),
    ));
    policy
}

/// On T2 a write rule reaches trust-handoff names, which only a waiver lets
/// through.
fn for_tier(mut policy: Policy, tier: Tier) -> Policy {
    if tier == Tier::T2 {
        policy.waive.insert(HardDenyClass::TrustHandoff);
    }
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

fn result(out: &Output) -> String {
    let stdout = String::from_utf8_lossy(&out.stdout);
    stdout
        .lines()
        .find_map(|l| l.split_once("procage-result: ").map(|(_, r)| r.to_string()))
        .unwrap_or_else(|| {
            panic!(
                "no result from the child ({}):\n{stdout}\n{}",
                out.status,
                String::from_utf8_lossy(&out.stderr)
            )
        })
}

/// Runs `action` in a caged child of `cage`; returns its result line.
fn run_in(cage: &Cage, action: &str, grants: &Grants) -> String {
    let child = cage
        .spawn(&mut child_command(action), grants)
        .unwrap_or_else(|e| panic!("spawn: {e}"));
    result(&finish(child, Duration::from_secs(20)))
}

/// Runs `action` in a child caged by `policy` at `tier`.
fn in_child(action: &str, policy: Policy, tier: Tier) -> String {
    let cage = Cage::with_options(&child_policy(policy), &options(tier))
        .unwrap_or_else(|e| panic!("cage: {e}"));
    run_in(&cage, action, &Grants::new())
}

fn tiers() -> Vec<Tier> {
    match host_tier() {
        Tier::T1 => vec![Tier::T1, Tier::T2],
        Tier::T2 => vec![Tier::T2],
    }
}

fn errno_of(r: std::io::Result<()>) -> String {
    match r {
        Ok(()) => "ok".into(),
        Err(e) => format!("{}", e.raw_os_error().unwrap_or(-1)),
    }
}

/// One operation in the child: `verb:argument`.
fn op(spec: &str) -> String {
    let (verb, arg) = spec.split_once(':').unwrap_or((spec, ""));
    let r = match verb {
        "read" => std::fs::read(arg).map(drop),
        "sleep" => {
            std::thread::sleep(Duration::from_millis(arg.parse().unwrap()));
            Ok(())
        }
        "write" => std::fs::write(arg, "x"),
        "append" => std::fs::OpenOptions::new().append(true).open(arg).map(drop),
        "mkdir" => std::fs::create_dir(arg),
        "list" => std::fs::read_dir(arg).and_then(|d| {
            for e in d {
                e?;
            }
            Ok(())
        }),
        "count" => {
            return std::fs::read_dir(arg)
                .map(|d| d.count().to_string())
                .unwrap_or_else(|e| format!("{}", e.raw_os_error().unwrap_or(-1)));
        }
        "rename" => {
            let (from, to) = arg.split_once('|').unwrap();
            std::fs::rename(from, to)
        }
        "connect" => {
            std::net::TcpStream::connect(("127.0.0.1", arg.parse::<u16>().unwrap())).map(drop)
        }
        "socket" => std::net::UdpSocket::bind("127.0.0.1:0").map(drop),
        "umount" => {
            return testing::umount(arg).to_string();
        }
        "remount" => {
            return testing::remount_rw(arg).to_string();
        }
        "syscall" => {
            return testing::syscall_errno(arg).unwrap().to_string();
        }
        "median" => {
            // `median:<syscall>:<n>`: the median time of n calls, in µs.
            let (name, n) = arg.split_once(':').unwrap();
            let mut times: Vec<u128> = (0..n.parse::<usize>().unwrap())
                .map(|_| {
                    let start = Instant::now();
                    testing::syscall_errno(name).unwrap();
                    start.elapsed().as_micros()
                })
                .collect();
            times.sort_unstable();
            return format!("median={}", times[times.len() / 2]);
        }
        "flood" => {
            // `flood:<syscall>:<n>`: how many of n calls failed with EPERM.
            let (name, n) = arg.split_once(':').unwrap();
            let refused = (0..n.parse::<usize>().unwrap())
                .filter(|_| testing::syscall_errno(name) == Some(EPERM))
                .count();
            return format!("refused={refused}");
        }
        "kill" => {
            return match testing::kill_errno(arg.parse().unwrap(), 0) {
                0 => "ok".into(),
                e => e.to_string(),
            };
        }
        other => return format!("unknown-op-{other}"),
    };
    errno_of(r)
}

#[test]
fn child_entry() {
    let Ok(action) = std::env::var("PROCAGE_CHILD") else {
        return;
    };
    let result = match action.as_str() {
        "session" => format!(
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
        "caps" => {
            let (eff, perm, bounding) = testing::capabilities();
            format!("eff={eff:#x} perm={perm:#x} bounding={bounding:#x}")
        }
        "sleepers" => {
            let same = testing::spawn_sleeper(false).unwrap();
            let session = testing::spawn_sleeper(true).unwrap();
            println!("procage-result: {same} {session}");
            std::thread::sleep(Duration::from_secs(30));
            return;
        }
        "tmpdir" => {
            let dir = std::env::var("TMPDIR").unwrap_or_default();
            let wrote = std::fs::write(Path::new(&dir).join("f"), "x").is_ok();
            format!("{dir} wrote={wrote}")
        }
        "outer-env" => outer_env(),
        "cleared-env" => cleared_env(),
        ops => ops.split(';').map(op).collect::<Vec<_>>().join(" "),
    };
    println!("procage-result: {result}");
}

// ---- A Linux harness spawns a caged child ----

#[test]
fn the_probe_reports_the_expected_tier() {
    let p = probe();
    println!(
        "tier {:?} landlock abi {} errata {} userns {:?}",
        p.tier, p.landlock_abi, p.errata, p.userns_errno
    );
    assert!(
        p.landlock_abi >= Tier::T2.min_landlock_abi(),
        "Landlock ABI {}",
        p.landlock_abi
    );
    if let Ok(expected) = std::env::var("PROCAGE_EXPECT_TIER") {
        let measured = format!("{}", host_tier());
        assert_eq!(measured, expected, "TIER MISMATCH");
    }
    assert_eq!(p.tier == Some(Tier::T1), p.userns_errno.is_none());
}

#[test]
fn files_outside_the_policy_are_refused() {
    let r = scratch("us1-r");
    let w = scratch("us1-w");
    let o = scratch("us1-o");
    std::fs::write(r.join("f"), "r").unwrap();
    std::fs::write(o.join("secret"), "o").unwrap();
    for tier in tiers() {
        let mut p = base();
        p.fs.push(FsRule::new(Access::Read, FsTarget::Subpath(abs(&r))));
        p.fs.push(FsRule::new(Access::Write, FsTarget::Subpath(abs(&w))));
        let ops = format!(
            "read:{}/f;write:{}/g;read:{}/secret;write:{}/h;list:{}",
            r.display(),
            w.display(),
            o.display(),
            r.display(),
            o.display()
        );
        assert_eq!(
            in_child(&ops, for_tier(p, tier), tier),
            format!("ok ok {EACCES} {EACCES} {EACCES}"),
            "{tier}"
        );
    }
}

#[test]
fn a_grant_applies_to_its_spawn_only() {
    let data = scratch("grant");
    std::fs::write(data.join("f"), "g").unwrap();
    for tier in tiers() {
        let mut p = base();
        p.grants.push(Grant {
            name: GrantName::new("data").unwrap(),
            access: Access::Read,
        });
        let cage = Cage::with_options(&child_policy(p), &options(tier)).unwrap();
        let read = format!("read:{}/f", data.display());
        assert_eq!(
            run_in(&cage, &read, &Grants::new().bind("data", &data)),
            "ok"
        );
        assert_eq!(run_in(&cage, &read, &Grants::new()), EACCES.to_string());
        let err = cage
            .spawn(
                &mut child_command(&read),
                &Grants::new().bind("other", &data),
            )
            .unwrap_err();
        assert!(
            matches!(err, SpawnError::Grant(GrantError::Undeclared { .. })),
            "{err}"
        );
        let err = cage
            .spawn(
                &mut child_command(&read),
                &Grants::new().bind("data", data.join("missing")),
            )
            .unwrap_err();
        assert!(
            matches!(err, SpawnError::Grant(GrantError::Missing { .. })),
            "{err}"
        );
    }
}

#[test]
fn without_network_nothing_is_reachable() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    for tier in tiers() {
        let mut p = base();
        p.net = Network::None;
        let r = in_child(&format!("connect:{port};socket"), p, tier);
        let (connect, socket) = r.split_once(' ').unwrap();
        assert_ne!(connect, "ok", "{tier}: connected to the host loopback");
        if tier == Tier::T2 {
            assert_eq!(socket, EPERM.to_string(), "{tier}");
        }
    }
}

/// The hard-deny syscalls, called with arguments that fail without effect
/// when allowed: the caged result must be EPERM. Where the uncaged control
/// already gets EPERM (Docker's default profile denies some of them), the
/// call says nothing and is reported, not counted.
#[test]
fn hard_deny_syscalls_are_refused() {
    let names = [
        "ptrace",
        "io_uring_setup",
        "bpf",
        "keyctl",
        "unshare",
        "setns",
        "perf_event_open",
        "userfaultfd",
        "open_tree",
    ];
    for tier in tiers() {
        let ops: Vec<String> = names.iter().map(|n| format!("syscall:{n}")).collect();
        let r = in_child(&ops.join(";"), base(), tier);
        let caged: Vec<&str> = r.split(' ').collect();
        let mut informative = 0;
        for (name, caged) in names.iter().zip(&caged) {
            let control = testing::syscall_errno(name).unwrap();
            if control == EPERM {
                println!("{tier}: {name} is already denied outside the cage");
                continue;
            }
            informative += 1;
            assert_eq!(
                *caged,
                EPERM.to_string(),
                "{tier}: {name} (control {control})"
            );
        }
        // Unconfined (T1 lane), only `userfaultfd` and `perf_event_open` may
        // be refused by sysctls; under Docker's profile, `ptrace` remains.
        let required = if host_tier() == Tier::T1 { 7 } else { 1 };
        assert!(
            informative >= required,
            "{tier}: only {informative} informative calls"
        );
    }
}

// ---- Never silently weaker ----

#[test]
fn t2_cannot_protect_inside_a_writable_tree() {
    let w = scratch("us2-protect");
    std::fs::create_dir_all(w.join("p")).unwrap();
    let mut p = base();
    p.fs.push(FsRule::new(Access::Write, FsTarget::Subpath(abs(&w))));
    p.fs.push(FsRule::new(
        Access::Protect,
        FsTarget::Subpath(abs(w.join("p"))),
    ));
    let p = for_tier(p, Tier::T2);
    let err = Cage::with_options(&p, &options(Tier::T2)).unwrap_err();
    let SpawnError::Lower(LowerError::Gaps(gaps)) = &err else {
        panic!("{err}");
    };
    assert!(
        gaps.iter()
            .any(|g| g.construct == Construct::FsProtect && g.kind == GapKind::Unsupported),
        "{err}"
    );
    // An approximation is accepted by name and recorded.
    let mut q = base();
    q.fs.push(FsRule::new(
        Access::Read,
        FsTarget::Literal(abs("/etc/hostname")),
    ));
    assert!(Cage::with_options(&q, &options(Tier::T2)).is_err());
    let allowed = CageOptions::default()
        .with_tier(Tier::T2)
        .with_lower(LowerOptions::default().allow(Construct::FsLiteral));
    let cage = Cage::with_options(&q, &allowed).unwrap();
    assert!(
        cage.plan()
            .degradations
            .iter()
            .any(|d| d.construct == Construct::FsLiteral)
    );
}

#[test]
fn t1_on_a_host_without_user_namespaces_is_unsupported() {
    if host_tier() == Tier::T1 {
        println!("not applicable on tier T1");
        return;
    }
    let err = Cage::with_options(&base(), &CageOptions::default().with_tier(Tier::T1)).unwrap_err();
    assert!(
        matches!(
            err,
            SpawnError::Unsupported(Unsupported::Tier {
                requested: Tier::T1,
                ..
            })
        ),
        "{err}"
    );
}

#[test]
fn a_missing_policy_path_fails_before_any_child_runs() {
    for tier in tiers() {
        let mut p = base();
        p.fs.push(FsRule::new(
            Access::Read,
            FsTarget::Subpath(abs("/nonexistent/procage")),
        ));
        let cage = Cage::with_options(&p, &options(tier)).unwrap();
        let err = cage
            .spawn(&mut Command::new("/bin/true"), &Grants::new())
            .unwrap_err();
        assert!(matches!(err, SpawnError::Path { .. }), "{tier}: {err}");
    }
}

#[test]
fn a_failed_step_is_named_and_the_target_does_not_run() {
    let dir = scratch("us2-step");
    for tier in tiers() {
        let mut p = base();
        p.limits.nofile = Some(u64::MAX - 1);
        p.fs.push(FsRule::new(Access::Write, FsTarget::Subpath(abs(&dir))));
        let cage = Cage::with_options(&for_tier(p, tier), &options(tier)).unwrap();
        let marker = dir.join(format!("ran-{tier}"));
        let mut cmd = Command::new("/bin/touch");
        cmd.arg(&marker);
        let err = cage.spawn(&mut cmd, &Grants::new()).unwrap_err();
        assert!(
            matches!(
                err,
                SpawnError::Apply {
                    step: Step::Rlimit,
                    ..
                }
            ),
            "{tier}: {err}"
        );
        assert!(!marker.exists(), "{tier}: the target ran");
    }
}

// ---- Data-driven hard-deny classes ----

/// A home with secrets and a persistence directory.
fn fake_home(name: &str) -> Scratch {
    let home = scratch(name);
    for d in [".ssh", ".aws", ".config/systemd/user"] {
        std::fs::create_dir_all(home.join(d)).unwrap();
    }
    std::fs::write(home.join(".ssh/id_ed25519"), "key").unwrap();
    std::fs::write(home.join(".aws/credentials"), "cred").unwrap();
    std::fs::write(home.join("notes.txt"), "n").unwrap();
    home
}

#[test]
fn t1_masks_secrets_in_a_readable_home() {
    if !t1("t1_masks_secrets_in_a_readable_home") {
        return;
    }
    let home = fake_home("us3-home");
    let mut p = child_policy(base());
    p.fs.push(FsRule::new(Access::Read, FsTarget::Subpath(abs(&home))));
    let h = home.display();
    let ops = format!(
        "read:{h}/notes.txt;list:{h};read:{h}/.ssh/id_ed25519;list:{h}/.ssh;read:{h}/.aws/credentials"
    );
    // A rule reaches the home's secrets: an approximation on T1.
    let plain = CageOptions::default().with_tier(Tier::T1).with_home(&home);
    let err = Cage::with_options(&p, &plain).unwrap_err();
    assert!(err.to_string().contains("hd-secrets"), "{err}");
    let cage = Cage::with_options(&p, &options(Tier::T1).with_home(&home)).unwrap();
    assert_eq!(
        run_in(&cage, &ops, &Grants::new()),
        format!("ok ok {EACCES} {EACCES} {EACCES}")
    );
    // Waived: readable.
    p.waive.insert(HardDenyClass::Secrets);
    let cage = Cage::with_options(&p, &options(Tier::T1).with_home(&home)).unwrap();
    assert_eq!(run_in(&cage, &ops, &Grants::new()), "ok ok ok ok ok");
    assert!(cage.plan().waivers.contains(&HardDenyClass::Secrets));
}

/// A workspace with a repository and trust-handoff files.
fn workspace(name: &str) -> Scratch {
    let w = scratch(name);
    for d in [
        ".git/hooks",
        ".git/objects",
        ".git/refs/heads",
        ".vscode",
        "src",
    ] {
        std::fs::create_dir_all(w.join(d)).unwrap();
    }
    std::fs::write(w.join(".git/config"), "[core]").unwrap();
    std::fs::write(w.join(".git/HEAD"), "ref: refs/heads/main").unwrap();
    std::fs::write(w.join(".bashrc"), "").unwrap();
    w
}

#[test]
fn t1_protects_trust_handoff_paths_in_a_writable_workspace() {
    if !t1("t1_protects_trust_handoff_paths_in_a_writable_workspace") {
        return;
    }
    let w = workspace("us3-ws");
    let mut p = base();
    p.fs.push(FsRule::new(Access::Write, FsTarget::Subpath(abs(&w))));
    let d = w.display();
    let ops = format!(
        "write:{d}/.git/hooks/pre-commit;append:{d}/.git/config;write:{d}/.vscode/settings.json;\
         append:{d}/.bashrc;rename:{d}/.git|{d}/moved;write:{d}/.git/objects/x;write:{d}/src/x;\
         write:{d}/.git/index;write:{d}/.git/refs/heads/main"
    );
    assert_eq!(
        in_child(&ops, p.clone(), Tier::T1),
        format!("{EROFS} {EROFS} {EROFS} {EROFS} {EBUSY} ok ok ok ok")
    );
    assert!(w.join(".git").is_dir());
    // Waived: hooks are writable.
    p.waive.insert(HardDenyClass::TrustHandoff);
    assert_eq!(
        in_child(&format!("write:{d}/.git/hooks/pre-commit"), p, Tier::T1),
        "ok"
    );
}

#[test]
fn t1_makes_persistence_paths_read_only() {
    if !t1("t1_makes_persistence_paths_read_only") {
        return;
    }
    let home = fake_home("us3-persist");
    let mut p = child_policy(base());
    p.fs.push(FsRule::new(Access::Write, FsTarget::Subpath(abs(&home))));
    p.waive.insert(HardDenyClass::Secrets);
    let cage = Cage::with_options(&p, &options(Tier::T1).with_home(&home)).unwrap();
    let ops = format!(
        "write:{}/.config/systemd/user/evil.service;write:{}/ok.txt",
        home.display(),
        home.display()
    );
    assert_eq!(run_in(&cage, &ops, &Grants::new()), format!("{EROFS} ok"));
}

#[test]
fn t2_cannot_enforce_classes_a_rule_reaches() {
    let w = workspace("us3-t2");
    let mut p = base();
    p.fs.push(FsRule::new(Access::Write, FsTarget::Subpath(abs(&w))));
    let err = Cage::with_options(&p, &options(Tier::T2)).unwrap_err();
    let SpawnError::Lower(LowerError::Gaps(gaps)) = &err else {
        panic!("{err}");
    };
    assert!(
        gaps.iter()
            .any(|g| g.construct == Construct::HdTrustHandoff && g.kind == GapKind::Unsupported)
    );
    p.waive.insert(HardDenyClass::TrustHandoff);
    let cage = Cage::with_options(&p, &options(Tier::T2)).unwrap();
    assert!(cage.plan().waivers.contains(&HardDenyClass::TrustHandoff));
    // A home outside /home is checked by the backend: read only, its
    // secrets are hidden piecewise (an accepted approximation); written, it
    // is refused.
    let home = fake_home("us3-t2-home");
    let mut q = base();
    q.fs.push(FsRule::new(Access::Read, FsTarget::Subpath(abs(&home))));
    let cage = Cage::with_options(&q, &options(Tier::T2).with_home(&home)).unwrap();
    assert!(
        cage.plan()
            .degradations
            .iter()
            .any(|d| d.construct == Construct::HdSecrets && d.note.contains("entry by entry"))
    );
    q.fs.push(FsRule::new(Access::Write, FsTarget::Subpath(abs(&home))));
    q.waive.insert(HardDenyClass::TrustHandoff);
    let err = Cage::with_options(&q, &options(Tier::T2).with_home(&home)).unwrap_err();
    assert!(err.to_string().contains("hd-secrets"), "{err}");
}

#[test]
fn t2_refuses_a_grant_that_reaches_secrets() {
    let home = fake_home("us3-grant");
    let mut p = child_policy(base());
    p.grants.push(Grant {
        name: GrantName::new("home").unwrap(),
        access: Access::Read,
    });
    let cage = Cage::with_options(&p, &options(Tier::T2).with_home(&home)).unwrap();
    let err = cage
        .spawn(
            &mut child_command("session"),
            &Grants::new().bind("home", &home),
        )
        .unwrap_err();
    assert!(
        matches!(
            err,
            SpawnError::Grant(GrantError::CoversClass {
                class: HardDenyClass::Secrets,
                ..
            })
        ),
        "{err}"
    );
    // A grant inside the home that avoids the secrets is fine.
    let notes = home.join("docs");
    std::fs::create_dir_all(&notes).unwrap();
    assert!(
        run_in(&cage, "session", &Grants::new().bind("home", &notes)).contains("session-leader")
    );
}

#[test]
fn an_oversized_writable_tree_fails_the_spawn() {
    if !t1("an_oversized_writable_tree_fails_the_spawn") {
        return;
    }
    let w = scratch("us3-walk");
    for i in 0..50 {
        std::fs::write(w.join(format!("f{i}")), "").unwrap();
    }
    let mut p = base();
    p.fs.push(FsRule::new(Access::Write, FsTarget::Subpath(abs(&w))));
    let cage = Cage::with_options(&p, &options(Tier::T1).with_walk_limit(10)).unwrap();
    let err = cage
        .spawn(&mut Command::new("/bin/true"), &Grants::new())
        .unwrap_err();
    assert!(matches!(err, SpawnError::Walk { limit: 10, .. }), "{err}");
}

// ---- Hygiene ----

#[test]
fn base_v1_runs_ordinary_programs() {
    let private = scratch("us4-private");
    std::fs::write(private.join("f"), "p").unwrap();
    let mut p = base();
    // The shell forks to run each program.
    p.process.fork = true;
    for tier in tiers() {
        let cage = Cage::with_options(&p, &options(tier)).unwrap();
        let script = format!(
            "echo ok; ls /usr >/dev/null && echo ls; cat /etc/passwd >/dev/null && echo cat; \
             cat {}/f 2>/dev/null || echo refused",
            private.display()
        );
        let mut cmd = Command::new("/bin/sh");
        cmd.args(["-c", &script])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let out = finish(
            cage.spawn(&mut cmd, &Grants::new()).unwrap(),
            Duration::from_secs(10),
        );
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert_eq!(
            stdout.lines().collect::<Vec<_>>(),
            ["ok", "ls", "cat", "refused"],
            "{tier}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
}

#[test]
fn descriptors_reach_the_child_only_when_handed_over() {
    use std::os::fd::{AsFd, AsRawFd};
    let dir = scratch("us4-fd");
    std::fs::write(dir.join("secret"), "s").unwrap();
    let file = std::fs::File::open(dir.join("secret")).unwrap();
    let fd = file.as_raw_fd();
    assert!(testing::clear_cloexec(fd));
    let leak: Vec<std::fs::File> = (0..200)
        .map(|_| std::fs::File::open(dir.join("secret")).unwrap())
        .collect();
    for f in &leak {
        assert!(testing::clear_cloexec(f.as_raw_fd()));
    }
    for tier in tiers() {
        let cage = Cage::with_options(&child_policy(base()), &options(tier)).unwrap();
        assert_eq!(
            run_in(&cage, &format!("fd:{fd}"), &Grants::new()),
            "open=false"
        );
        assert_eq!(run_in(&cage, "fdcount", &Grants::new()), "fdcount=0");
        let child = cage
            .spawn_with_fds(
                &mut child_command(&format!("fd:{fd}")),
                &Grants::new(),
                &[file.as_fd()],
            )
            .unwrap();
        assert_eq!(result(&finish(child, Duration::from_secs(10))), "open=true");
    }
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
    use std::io::BufRead;
    for tier in tiers() {
        let mut p = base();
        p.process.fork = true;
        let cage = Cage::with_options(&child_policy(p), &options(tier)).unwrap();
        let mut child = cage
            .spawn(&mut child_command("sleepers"), &Grants::new())
            .unwrap();
        let stdout = child.stdout.take().unwrap();
        let line = std::io::BufReader::new(stdout)
            .lines()
            .find_map(|l| {
                l.ok()
                    .and_then(|l| l.split_once("procage-result: ").map(|(_, r)| r.to_string()))
            })
            .expect("pids");
        let pids: Vec<u32> = line.split(' ').map(|p| p.parse().unwrap()).collect();
        assert!(pids.iter().all(|&p| testing::alive(p)), "{tier}");
        let leader = child.id();
        drop(child);
        assert!(gone_within(leader, Duration::from_secs(2)), "{tier}");
        for pid in pids {
            assert!(
                gone_within(pid, Duration::from_secs(2)),
                "{tier}: {pid} survived"
            );
        }
    }
}

#[test]
fn session_and_limits_are_the_policys() {
    for tier in tiers() {
        let mut p = base();
        p.limits.nofile = Some(64);
        assert_eq!(
            in_child("session", p.clone(), tier),
            "session-leader=true group-leader=true"
        );
        assert_eq!(in_child("rlimit", p, tier), "nofile=64 core=0");
    }
}

/// Runs uncaged with secret-looking variables in its environment and
/// reports what a passthrough child sees.
fn outer_env() -> String {
    let mut p = base();
    p.env = EnvPolicy::Passthrough { deny: vec![] };
    let tier = host_tier();
    let cage = Cage::with_options(&child_policy(p), &options(tier)).unwrap();
    let child = cage
        .spawn(&mut child_command("env"), &Grants::new())
        .unwrap();
    let dropped = child.dropped_env().join(",");
    let seen = result(&finish(child, Duration::from_secs(10)));
    let has = |name: &str| seen.split(',').any(|w| w == name);
    format!(
        "dropped={dropped} token={} sock={} preload={} path={}",
        has("GITHUB_TOKEN"),
        has("SSH_AUTH_SOCK"),
        has("LD_PRELOAD"),
        has("PATH")
    )
}

/// Runs uncaged with `PROCAGE_SECRET` in its environment and reports the
/// names a child sees whose command called `env_clear` and set `A`, under
/// passthrough and under an allowlist naming the secret and `PATH`.
fn cleared_env() -> String {
    let tier = host_tier();
    let seen = |env: EnvPolicy| {
        let mut p = base();
        p.env = env;
        let cage = Cage::with_options(&child_policy(p), &options(tier)).unwrap();
        let mut cmd = child_command("env");
        cmd.env_clear().env("PROCAGE_CHILD", "env").env("A", "1");
        result(&finish(
            cage.spawn(&mut cmd, &Grants::new()).unwrap(),
            Duration::from_secs(10),
        ))
    };
    format!(
        "passthrough=[{}] allowlist=[{}]",
        seen(EnvPolicy::Passthrough { deny: vec![] }),
        seen(EnvPolicy::Allowlist(vec![
            "PATH".into(),
            "PROCAGE_SECRET".into()
        ]))
    )
}

/// `env_clear` on the command keeps every caller variable out, whatever the
/// policy says about the caller's environment.
#[test]
fn env_clear_keeps_the_caller_environment_out() {
    let out = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "child_entry", "--nocapture", "--test-threads=1"])
        .env("PROCAGE_CHILD", "cleared-env")
        .env("PROCAGE_SECRET", "s")
        .output()
        .unwrap();
    assert_eq!(
        result(&out),
        "passthrough=[A,PROCAGE_CHILD] allowlist=[A,PROCAGE_CHILD]"
    );
}

#[test]
fn passthrough_drops_secret_variables() {
    let out = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "child_entry", "--nocapture", "--test-threads=1"])
        .env("PROCAGE_CHILD", "outer-env")
        .env("GITHUB_TOKEN", "t")
        .env("SSH_AUTH_SOCK", "/s")
        .env("LD_PRELOAD", "/nonexistent.so")
        .output()
        .unwrap();
    let r = result(&out);
    let (dropped, seen) = r.split_once(' ').unwrap();
    let dropped: Vec<&str> = dropped.trim_start_matches("dropped=").split(',').collect();
    for name in ["GITHUB_TOKEN", "LD_PRELOAD", "SSH_AUTH_SOCK"] {
        assert!(dropped.contains(&name), "{r}");
    }
    assert_eq!(seen, "token=false sock=false preload=false path=true");
}

#[test]
fn the_tmpdir_grant_gives_a_private_directory() {
    for tier in tiers() {
        let mut p = base();
        p.grants.push(Grant {
            name: GrantName::new("tmpdir").unwrap(),
            access: Access::Write,
        });
        let cage = Cage::with_options(&child_policy(for_tier(p, tier)), &options(tier)).unwrap();
        let child = cage
            .spawn(&mut child_command("tmpdir"), &Grants::new())
            .unwrap();
        let dir = child.tmpdir().unwrap().to_path_buf();
        let r = result(&finish(child, Duration::from_secs(10)));
        assert_eq!(r, format!("{} wrote=true", dir.display()), "{tier}");
        assert!(!dir.exists(), "{tier}: tmpdir left behind");
    }
}

#[test]
fn many_spawns_from_many_threads_are_all_caged() {
    let tier = host_tier();
    let mut p = base();
    p.process.fork = true;
    let cage = std::sync::Arc::new(Cage::with_options(&p, &options(tier)).unwrap());
    let threads: Vec<_> = (0..4)
        .map(|_| {
            let cage = cage.clone();
            std::thread::spawn(move || {
                for _ in 0..25 {
                    let mut cmd = Command::new("/bin/sh");
                    cmd.args([
                        "-c",
                        "cat /proc/self/status >/dev/null 2>&1 && exit 3; exit 0",
                    ])
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped());
                    let child = cage.spawn(&mut cmd, &Grants::new()).unwrap();
                    let out = finish(child, Duration::from_secs(10));
                    // /proc is outside the base profile: reading it fails.
                    assert_eq!(out.status.code(), Some(0));
                }
            })
        })
        .collect();
    for t in threads {
        t.join().unwrap();
    }
}

/// The T1 mount sequence (by descriptor: openat2, open_tree, fsmount,
/// mount_setattr, move_mount) runs in the child between fork and exec, so
/// it must stay system calls only: 1,000 spawns of a policy with every
/// mount kind, from four threads, while four more allocate and lock.
#[test]
fn t1_mounts_from_a_busy_multithreaded_parent() {
    if !t1("t1_mounts_from_a_busy_multithreaded_parent") {
        return;
    }
    use std::sync::atomic::{AtomicBool, Ordering};
    let w = scratch("t1-mt");
    for dir in ["p", "h", "f", ".git/hooks", "sub/.vscode"] {
        std::fs::create_dir_all(w.join(dir)).unwrap();
    }
    std::fs::write(w.join("f/secret"), "secret").unwrap();
    let mut p = base();
    p.process.fork = true;
    p.fs.push(FsRule::new(Access::Write, FsTarget::Subpath(abs(&w))));
    p.fs.push(FsRule::new(
        Access::Protect,
        FsTarget::Subpath(abs(w.join("p"))),
    ));
    p.fs.push(FsRule::new(
        Access::Hide,
        FsTarget::Subpath(abs(w.join("h"))),
    ));
    p.fs.push(FsRule::new(
        Access::Hide,
        FsTarget::Literal(abs(w.join("f/secret"))),
    ));
    let cage = std::sync::Arc::new(Cage::with_options(&p, &options(Tier::T1)).unwrap());
    let stop = std::sync::Arc::new(AtomicBool::new(false));
    let lock = std::sync::Arc::new(std::sync::Mutex::new(Vec::<u8>::new()));
    let churn: Vec<_> = (0..4)
        .map(|_| {
            let (stop, lock) = (stop.clone(), lock.clone());
            std::thread::spawn(move || {
                while !stop.load(Ordering::Relaxed) {
                    let mut held = lock.lock().unwrap();
                    held.extend(std::iter::repeat_n(1, 4096));
                    held.clear();
                    held.shrink_to_fit();
                }
            })
        })
        .collect();
    let script = format!(
        "touch {d}/p/x 2>/dev/null && exit 3; cat {d}/f/secret 2>/dev/null && exit 4; exit 0",
        d = w.display()
    );
    let spawners: Vec<_> = (0..4)
        .map(|_| {
            let (cage, script) = (cage.clone(), script.clone());
            std::thread::spawn(move || {
                for _ in 0..250 {
                    let mut cmd = Command::new("/bin/sh");
                    cmd.args(["-c", &script])
                        .stdout(Stdio::piped())
                        .stderr(Stdio::piped());
                    let child = cage.spawn(&mut cmd, &Grants::new()).unwrap();
                    let out = finish(child, Duration::from_secs(10));
                    assert_eq!(out.status.code(), Some(0));
                }
            })
        })
        .collect();
    for t in spawners {
        t.join().unwrap();
    }
    stop.store(true, Ordering::Relaxed);
    for t in churn {
        t.join().unwrap();
    }
}

// ---- T1 isolation ----

#[test]
fn t1_protect_is_read_only_and_cannot_be_undone() {
    if !t1("t1_protect_is_read_only_and_cannot_be_undone") {
        return;
    }
    let w = scratch("us5-protect");
    std::fs::create_dir_all(w.join("p")).unwrap();
    let mut p = base();
    p.fs.push(FsRule::new(Access::Write, FsTarget::Subpath(abs(&w))));
    p.fs.push(FsRule::new(
        Access::Protect,
        FsTarget::Subpath(abs(w.join("p"))),
    ));
    let d = w.display();
    let ops = format!("write:{d}/p/x;write:{d}/x;umount:{d}/p;remount:{d}/p;write:{d}/p/y");
    let r = in_child(&ops, p, Tier::T1);
    let parts: Vec<&str> = r.split(' ').collect();
    assert_eq!(parts[0], EROFS.to_string());
    assert_eq!(parts[1], "ok");
    assert_ne!(parts[2], "0", "umount succeeded");
    assert_ne!(parts[3], "0", "remount succeeded");
    assert_eq!(parts[4], EROFS.to_string());
}

#[test]
fn t1_hide_leaves_nothing_readable() {
    if !t1("t1_hide_leaves_nothing_readable") {
        return;
    }
    let r = scratch("us5-hide");
    std::fs::create_dir_all(r.join("h")).unwrap();
    std::fs::write(r.join("h/f"), "hidden").unwrap();
    std::fs::write(r.join("file"), "hidden").unwrap();
    let mut p = base();
    p.fs.push(FsRule::new(Access::Read, FsTarget::Subpath(abs(&r))));
    p.fs.push(FsRule::new(
        Access::Hide,
        FsTarget::Subpath(abs(r.join("h"))),
    ));
    p.fs.push(FsRule::new(
        Access::Hide,
        FsTarget::Literal(abs(r.join("file"))),
    ));
    let d = r.display();
    let opts = options(Tier::T1).with_lower(masked().allow(Construct::FsLiteral));
    let cage = Cage::with_options(&child_policy(p), &opts).unwrap();
    assert_eq!(
        run_in(
            &cage,
            &format!("list:{d}/h;read:{d}/h/f;read:{d}/file"),
            &Grants::new()
        ),
        format!("{EACCES} {EACCES} {EACCES}")
    );
}

/// Base V2 is V1 on Linux: the same programs run, on every tier.
#[test]
fn base_v2_runs_programs_on_linux() {
    for tier in tiers() {
        let mut p = Policy::default();
        p.base = procage::policy::Base::V2;
        p.process.fork = true;
        let cage = Cage::with_options(&p, &options(tier)).unwrap();
        let mut cmd = Command::new("/bin/sh");
        cmd.args(["-c", "cat /etc/hostname >/dev/null && echo ok"])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let out = finish(
            cage.spawn(&mut cmd, &Grants::new()).unwrap(),
            Duration::from_secs(10),
        );
        assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "ok", "{tier}");
    }
}

/// The snapshot options for tier T2.
fn t2_snapshot() -> CageOptions {
    CageOptions::default()
        .with_tier(Tier::T2)
        .with_lower(LowerOptions::default().accept_spawn_snapshot())
}

/// On T2 a hidden path inside a read-only tree is kept out piecewise: its
/// contents stay unreadable, also through a symbolic link next to it, the
/// rest of the tree reads, and an entry added on the way after the spawn is
/// denied. Without the snapshot accepted, the policy is refused.
#[test]
fn t2_hide_is_piecewise() {
    let r = scratch("t2-hide");
    std::fs::create_dir_all(r.join("h")).unwrap();
    std::fs::create_dir_all(r.join("sub")).unwrap();
    std::fs::write(r.join("h/f"), "hidden").unwrap();
    std::fs::write(r.join("file"), "ok").unwrap();
    std::fs::write(r.join("sub/x"), "ok").unwrap();
    std::os::unix::fs::symlink(r.join("h"), r.join("link")).unwrap();
    let mut p = base();
    p.fs.push(FsRule::new(Access::Read, FsTarget::Subpath(abs(&r))));
    p.fs.push(FsRule::new(
        Access::Hide,
        FsTarget::Subpath(abs(r.join("h"))),
    ));
    let p = child_policy(p);
    match Cage::with_options(&p, &options(Tier::T2)) {
        Err(SpawnError::Lower(LowerError::Gaps(gaps))) => {
            let hide = gaps
                .iter()
                .find(|g| g.construct == Construct::FsHide)
                .unwrap();
            assert_eq!(hide.kind, GapKind::Approximation);
            assert!(hide.to_string().contains("accept_spawn_snapshot"), "{hide}");
        }
        other => panic!("expected the approximation to be refused: {other:?}"),
    }
    let cage = Cage::with_options(&p, &t2_snapshot()).unwrap();
    let d = r.display();
    let action = format!(
        "read:{d}/file;read:{d}/sub/x;read:{d}/h/f;read:{d}/link/f;list:{d}/h;sleep:300;read:{d}/later"
    );
    let child = cage
        .spawn(&mut child_command(&action), &Grants::new())
        .unwrap();
    std::thread::sleep(Duration::from_millis(100));
    std::fs::write(r.join("later"), "new").unwrap();
    let first = result(&finish(child, Duration::from_secs(10)));
    assert_eq!(
        first,
        format!("ok ok {EACCES} {EACCES} {EACCES} ok {EACCES}")
    );
}

/// On T2 a write rule around a hidden path cannot keep it out: refused.
#[test]
fn t2_hide_inside_a_writable_tree_is_refused() {
    let r = scratch("t2-hide-w");
    std::fs::create_dir_all(r.join("h")).unwrap();
    let mut p = base();
    p.fs.push(FsRule::new(Access::Write, FsTarget::Subpath(abs(&r))));
    p.fs.push(FsRule::new(
        Access::Hide,
        FsTarget::Subpath(abs(r.join("h"))),
    ));
    p.waive.insert(HardDenyClass::TrustHandoff);
    match Cage::with_options(&child_policy(p), &t2_snapshot()) {
        Err(SpawnError::Lower(LowerError::Gaps(gaps))) => assert!(
            gaps.iter()
                .any(|g| g.construct == Construct::FsHide && g.kind == GapKind::Unsupported),
            "{gaps:?}"
        ),
        other => panic!("expected a gap: {other:?}"),
    }
}

/// On T2 a write grant bound around a hidden path fails the spawn, naming
/// both.
#[test]
fn t2_a_write_grant_around_a_hidden_path_fails_the_spawn() {
    let r = scratch("t2-hide-g");
    std::fs::create_dir_all(r.join("h")).unwrap();
    let mut p = base();
    p.fs.push(FsRule::new(Access::Read, FsTarget::Subpath(abs(&r))));
    p.fs.push(FsRule::new(
        Access::Hide,
        FsTarget::Subpath(abs(r.join("h"))),
    ));
    p.grants.push(Grant {
        name: GrantName::new("out").unwrap(),
        access: Access::Write,
    });
    p.waive.insert(HardDenyClass::TrustHandoff);
    let cage = Cage::with_options(&child_policy(p), &t2_snapshot()).unwrap();
    let err = cage
        .spawn(&mut child_command("read:/"), &Grants::new().bind("out", &r))
        .map(drop)
        .unwrap_err();
    match &err {
        SpawnError::Grant(GrantError::Covers { name, hidden }) => {
            assert_eq!(name, "out");
            assert_eq!(hidden, &r.join("h"));
        }
        other => panic!("{other}"),
    }
    assert!(err.to_string().contains("tier T2"), "{err}");
}

/// On T2, reading everything with the secrets class in force keeps a home's
/// `.ssh` unreadable while the rest reads.
#[test]
fn t2_reading_everything_except_secrets() {
    let home = scratch("t2-home");
    std::fs::create_dir_all(home.join(".ssh")).unwrap();
    std::fs::write(home.join(".ssh/id_ed25519"), "key").unwrap();
    std::fs::write(home.join("notes"), "ok").unwrap();
    let mut p = base();
    p.fs.push(FsRule::new(
        Access::Read,
        FsTarget::Subpath(AbsPath::root()),
    ));
    // Reading everything reaches other processes' /proc entries.
    let options = t2_snapshot().with_home(&home);
    let lower = options.lower.clone().allow(Construct::ProcOtherProcesses);
    let cage = Cage::with_options(&child_policy(p), &options.with_lower(lower)).unwrap();
    let h = home.display();
    assert_eq!(
        run_in(
            &cage,
            &format!("read:{h}/.ssh/id_ed25519;read:{h}/notes;read:/etc/hostname"),
            &Grants::new()
        ),
        format!("{EACCES} ok ok")
    );
}

#[test]
fn t1_children_hold_no_capabilities() {
    if !t1("t1_children_hold_no_capabilities") {
        return;
    }
    assert_eq!(
        in_child("caps", base(), Tier::T1),
        "eff=0x0 perm=0x0 bounding=0x0"
    );
}

#[test]
#[ignore = "latency, recorded by hand"]
fn latency() {
    let cage = Cage::new(&base()).unwrap();
    let mut times = Vec::new();
    for _ in 0..50 {
        let start = Instant::now();
        let mut child = cage
            .spawn(&mut Command::new("/bin/true"), &Grants::new())
            .unwrap();
        child.wait().unwrap();
        times.push(start.elapsed());
    }
    times.sort();
    println!("tier {} median {:?}", cage.tier(), times[times.len() / 2]);
}

// ---- Older kernels: the Landlock ABI cap ----

/// The ABIs to try: the oldest of each kind of change, and the kernel's.
fn abis() -> Vec<u8> {
    let kernel = probe().landlock_abi.min(procage::linux::BACKEND_MAX_ABI);
    let mut abis: Vec<u8> = [1, 2, 3, 5].into_iter().filter(|&a| a < kernel).collect();
    abis.push(kernel);
    abis
}

/// At every ABI from 1, on both tiers, writes stay in the workspace, the
/// network is off and the hard-deny syscalls are refused.
#[test]
fn older_kernels_keep_writes_the_network_and_hard_denies() {
    for tier in tiers() {
        for abi in abis() {
            let w = scratch(&format!("abi-w-{tier}-{abi}"));
            let o = scratch(&format!("abi-o-{tier}-{abi}"));
            let mut p = base();
            p.fs.push(FsRule::new(Access::Write, FsTarget::Subpath(abs(&w))));
            let p = for_tier(p, tier);
            let cage = Cage::with_options(&child_policy(p), &options(tier).with_landlock_abi(abi))
                .unwrap_or_else(|e| panic!("{tier} ABI {abi}: {e}"));
            assert_eq!(cage.landlock_abi(), abi);
            let got = run_in(
                &cage,
                &format!(
                    "write:{}/f;write:{}/f;socket;connect:9;syscall:ptrace",
                    w.display(),
                    o.display()
                ),
                &Grants::new(),
            );
            assert_eq!(
                got,
                format!("ok {EACCES} {EPERM} {EPERM} {EPERM}"),
                "{tier} ABI {abi}"
            );
            assert!(!o.join("f").exists());
        }
    }
}

/// The cap never raises the ABI, and a cap of 0 is a kernel without
/// Landlock.
#[test]
fn the_abi_cap_only_lowers() {
    let kernel = probe().landlock_abi.min(procage::linux::BACKEND_MAX_ABI);
    let cage = Cage::with_options(&base(), &CageOptions::default().with_landlock_abi(200)).unwrap();
    assert_eq!(cage.landlock_abi(), kernel);
    assert_eq!(cage.plan().landlock_abi, kernel);
    let err =
        Cage::with_options(&base(), &CageOptions::default().with_landlock_abi(0)).unwrap_err();
    assert!(
        matches!(
            err,
            SpawnError::Unsupported(Unsupported::Landlock { abi: 0, needed: 1 })
        ),
        "{err}"
    );
}

/// Signals reach a process outside the cage only with `SameUser`. Below
/// ABI 6 `SelfAndChildren` is refused, never widened.
#[test]
fn signals_reach_outside_processes_only_when_the_policy_says_so() {
    let mut sleeper = Command::new("/bin/sleep").arg("30").spawn().unwrap();
    let action = format!("kill:{}", sleeper.id());
    let kernel = probe().landlock_abi.min(procage::linux::BACKEND_MAX_ABI);
    for tier in tiers() {
        let with = |signals: Signals| {
            let mut p = base();
            p.process.fork = true;
            p.process.signals = signals;
            p
        };
        assert_eq!(
            in_child(&action, with(Signals::SameUser), tier),
            "ok",
            "{tier}"
        );
        assert_eq!(
            in_child(&action, with(Signals::None), tier),
            EPERM.to_string(),
            "{tier}"
        );
        if kernel >= 6 {
            let got = in_child(&action, with(Signals::SelfAndChildren), tier);
            assert_eq!(got, EPERM.to_string(), "{tier}");
        } else {
            println!("{tier}: ABI {kernel} has no signal scope");
        }
        let capped = options(tier).with_landlock_abi(5.min(kernel));
        match Cage::with_options(&child_policy(with(Signals::SelfAndChildren)), &capped) {
            Err(SpawnError::Lower(LowerError::Gaps(gaps))) => {
                assert!(
                    gaps.iter()
                        .any(|g| g.construct == Construct::SignalsSelfAndChildren),
                    "{gaps:?}"
                );
            }
            other => panic!("{tier}: expected the signal gap, got {other:?}"),
        }
        let cage = Cage::with_options(&child_policy(with(Signals::SameUser)), &capped).unwrap();
        assert_eq!(run_in(&cage, &action, &Grants::new()), "ok", "{tier} ABI 5");
    }
    assert!(
        sleeper.try_wait().unwrap().is_none(),
        "signal 0 kills nothing"
    );
    let _ = sleeper.kill();
    let _ = sleeper.wait();
}

// ---- Fitting a policy to the host ----

/// A harness-shaped policy on T2: the parts T2 cannot enforce (four below
/// Landlock ABI 9) are relaxed by name, each with what would lift it, and
/// the rest still holds.
/// Below ABI 6 the signal scope joins them; without its relaxation the cage
/// fails with exactly that gap.
#[test]
fn a_fitted_cage_gives_up_only_what_was_named() {
    use procage::policy::{Relax, Relaxation};
    let w = scratch("fit-w");
    let o = scratch("fit-o");
    std::fs::create_dir(w.join(".git")).unwrap();
    std::fs::write(w.join(".env"), "secret").unwrap();
    let mut p = base();
    p.fs.push(FsRule::new(Access::Write, FsTarget::Subpath(abs(&w))));
    p.fs.push(FsRule::new(
        Access::Protect,
        FsTarget::Subpath(abs(w.join(".git"))),
    ));
    p.fs.push(FsRule::new(
        Access::Hide,
        FsTarget::Subpath(abs(w.join(".env"))),
    ));
    p.ipc.unix_sockets = vec![abs(&w)];
    p.process.fork = true;
    p.process.signals = Signals::SelfAndChildren;
    let p = child_policy(p);
    let relax = Relax::new()
        .leave_out_protect()
        .leave_out_hide()
        .waive(HardDenyClass::TrustHandoff)
        .no_unix_sockets()
        .signals_same_user();
    let kernel = probe().landlock_abi.min(procage::linux::BACKEND_MAX_ABI);
    let (cage, relaxed) = Cage::fit(&p, &options(Tier::T2), &relax).unwrap();
    for r in &relaxed {
        println!("{r}");
    }
    let mut got: Vec<Relaxation> = relaxed.iter().map(|r| r.relaxation).collect();
    got.sort();
    let mut want = vec![
        Relaxation::LeaveOutProtect,
        Relaxation::LeaveOutHide,
        Relaxation::Waive(HardDenyClass::TrustHandoff),
    ];
    // Landlock restricts pathname sockets from ABI 9.
    if kernel < 9 {
        want.push(Relaxation::NoUnixSockets);
    }
    if kernel < 6 {
        want.push(Relaxation::SignalsSameUser);
    }
    want.sort();
    assert_eq!(got, want);
    let protect = relaxed
        .iter()
        .find(|r| r.relaxation == Relaxation::LeaveOutProtect)
        .unwrap();
    assert!(protect.lift.tier1, "{protect}");
    let got = run_in(
        &cage,
        &format!(
            "write:{o}/f;socket;write:{w}/.git/x;read:{w}/.env",
            o = o.display(),
            w = w.display()
        ),
        &Grants::new(),
    );
    assert_eq!(got, format!("{EACCES} {EPERM} ok ok"));

    // As on a kernel without the signal scope.
    let old = options(Tier::T2).with_landlock_abi(5.min(kernel));
    let (_, relaxed) = Cage::fit(&p, &old, &relax).unwrap();
    let signals = relaxed
        .iter()
        .find(|r| r.relaxation == Relaxation::SignalsSameUser)
        .expect("the signal scope is relaxed below ABI 6");
    if kernel >= 6 {
        assert_eq!(signals.lift.landlock_abi, Some(6), "{signals}");
        assert!(!signals.lift.tier1, "{signals}");
    }
    let without = Relax::new()
        .leave_out_protect()
        .leave_out_hide()
        .waive(HardDenyClass::TrustHandoff)
        .no_unix_sockets();
    match Cage::fit(&p, &old, &without) {
        Err(SpawnError::Lower(LowerError::Gaps(gaps))) => {
            let constructs: Vec<Construct> = gaps.iter().map(|g| g.construct).collect();
            assert_eq!(constructs, [Construct::SignalsSelfAndChildren]);
        }
        other => panic!("expected the signal gap, got {other:?}"),
    }

    // Nothing to relax: the same cage as without fitting.
    let (cage, relaxed) = Cage::fit(&child_policy(base()), &options(host_tier()), &relax).unwrap();
    assert!(relaxed.is_empty());
    assert_eq!(cage.tier(), host_tier());
}

// ---- Violations: the system calls the filter refused ----

fn reporting(policy: Policy, tier: Tier) -> Cage {
    Cage::with_options(&child_policy(policy), &options(tier).with_violations())
        .unwrap_or_else(|e| panic!("cage: {e}"))
}

/// `secs` seconds, times `PROCAGE_TIME_SCALE` (an emulated kernel lane
/// runs many times slower).
fn patience(secs: u64) -> Duration {
    let scale = std::env::var("PROCAGE_TIME_SCALE")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(1);
    Duration::from_secs(secs * scale)
}

/// A policy that forks under `Lifetime::Run` and has no network.
fn refusing() -> Policy {
    let mut p = base();
    p.process.fork = true;
    p.process.lifetime = procage::policy::Lifetime::Run;
    p.net = Network::None;
    p
}

/// Spawns `action`, waits for the exit and returns the result line and
/// the record read right after it.
fn reported(cage: &Cage, action: &str) -> (String, procage::Violations) {
    let mut child = cage
        .spawn(&mut child_command(action), &Grants::new())
        .unwrap();
    let start = Instant::now();
    while child.try_wait().unwrap().is_none() {
        assert!(start.elapsed() < patience(20), "child hung");
        std::thread::sleep(Duration::from_millis(5));
    }
    let mut out = String::new();
    child
        .stdout
        .take()
        .unwrap()
        .read_to_string(&mut out)
        .unwrap();
    let line = out
        .lines()
        .find_map(|l| l.split_once("procage-result: ").map(|(_, r)| r.to_string()))
        .unwrap_or_else(|| panic!("no result: {out}"));
    (line, child.violations())
}

fn by_op<'a>(record: &'a procage::Violations, op: &str) -> Vec<&'a procage::Violation> {
    record.iter().filter(|v| v.operation == op).collect()
}

/// Each refused call is listed with its reason, and the call still
/// failed with EPERM.
#[test]
fn refused_calls_are_reported_with_their_reason() {
    use procage::DeniedBy;
    for tier in tiers() {
        let cage = reporting(refusing(), tier);
        let (line, record) = reported(&cage, "syscall:ptrace;socket;syscall:setsid");
        assert_eq!(line, format!("{EPERM} {EPERM} {EPERM}"), "{tier:?}");
        assert_eq!(record.coverage(), &procage::Coverage::SystemCalls);
        assert!(record.complete(), "{tier:?} {record:#?}");
        let one = |op: &str| {
            let found = by_op(&record, op);
            assert_eq!(found.len(), 1, "{tier:?} {op}: {record:#?}");
            found[0].clone()
        };
        let ptrace = one("ptrace");
        assert_eq!(
            ptrace.denied_by,
            DeniedBy::HardDeny(HardDenyClass::ProcessAccess)
        );
        // The process, not the libtest thread that made the call.
        assert!(ptrace.process.starts_with("spawn_linux"), "{ptrace:?}");
        let socket = one("socket");
        assert_eq!(socket.denied_by, DeniedBy::NotGranted);
        assert_eq!(socket.target.as_deref(), Some("family AF_INET"));
        assert_eq!(one("setsid").denied_by, DeniedBy::Lifetime);
        assert!(
            socket
                .to_string()
                .contains("was denied socket family AF_INET: not granted")
        );
    }
}

#[test]
fn reporting_is_off_by_default_on_linux() {
    let cage = Cage::with_options(&child_policy(refusing()), &options(host_tier())).unwrap();
    let mut child = cage
        .spawn(&mut child_command("syscall:ptrace"), &Grants::new())
        .unwrap();
    child.wait().unwrap();
    let record = child.violations();
    assert_eq!(record.coverage(), &procage::Coverage::Off);
    assert!(record.is_empty());
    assert!(child.violation_receiver().is_none());
}

/// The receiver yields while the child runs, the record stays open
/// while a process of the run is left, and kill_all completes it.
#[test]
fn a_record_completes_when_the_run_ends() {
    let cage = reporting(refusing(), host_tier());
    let mut child = cage
        .spawn(
            &mut child_command("syscall:ptrace;sleep:5000"),
            &Grants::new(),
        )
        .unwrap();
    let rx = child.violation_receiver().expect("SystemCalls");
    let v = rx
        .recv_timeout(Duration::from_secs(5))
        .expect("a live violation");
    assert_eq!(v.operation, "ptrace");
    assert!(!child.violations().complete());
    child.kill_all().unwrap();
    let record = child.violations();
    assert!(record.complete(), "{record:#?}");
    assert_eq!(by_op(&record, "ptrace").len(), 1);
}

/// A descendant that outlives the child keeps the record open.
#[test]
fn a_surviving_descendant_keeps_the_record_open() {
    let mut policy = refusing();
    policy
        .fs
        .push(FsRule::new(Access::Exec, FsTarget::Subpath(abs("/bin"))));
    policy
        .fs
        .push(FsRule::new(Access::Exec, FsTarget::Subpath(abs("/usr"))));
    policy
        .fs
        .push(FsRule::new(Access::Exec, FsTarget::Subpath(abs("/lib"))));
    let cage = reporting(policy, host_tier());
    let mut cmd = Command::new("/bin/sh");
    cmd.args(["-c", "sleep 5 & exit 0"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let mut child = cage.spawn(&mut cmd, &Grants::new()).unwrap();
    child.wait().unwrap();
    assert!(!child.violations().complete());
    child.kill_all().unwrap();
    assert!(child.violations().complete());
}

#[test]
fn concurrent_runs_keep_their_own_calls() {
    let cage = reporting(refusing(), host_tier());
    let spawn = |action: &str| {
        cage.spawn(&mut child_command(action), &Grants::new())
            .unwrap()
    };
    let (mut a, mut b) = (
        spawn("syscall:ptrace;sleep:300"),
        spawn("syscall:setsid;sleep:300"),
    );
    a.wait().unwrap();
    b.wait().unwrap();
    let (ra, rb) = (a.violations(), b.violations());
    assert!(
        by_op(&ra, "ptrace").len() == 1 && by_op(&ra, "setsid").is_empty(),
        "{ra:#?}"
    );
    assert!(
        by_op(&rb, "setsid").len() == 1 && by_op(&rb, "ptrace").is_empty(),
        "{rb:#?}"
    );
}

/// A detached run is still answered: its refused calls return
/// EPERM instead of blocking.
#[test]
fn a_detached_run_is_still_answered() {
    let cage = reporting(refusing(), host_tier());
    let child = cage
        .spawn(
            &mut child_command("sleep:200;syscall:ptrace;syscall:setsid"),
            &Grants::new(),
        )
        .unwrap()
        .detach();
    let out = child.wait_with_output().unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains(&format!("procage-result: ok {EPERM} {EPERM}")),
        "{stdout}"
    );
}

/// The supervisor answers at once.
#[test]
fn refused_calls_are_answered_quickly() {
    let cage = reporting(refusing(), host_tier());
    let (line, record) = reported(&cage, "median:ptrace:20");
    let median: u128 = line.strip_prefix("median=").unwrap().parse().unwrap();
    assert!(median < 10_000, "median {median} µs");
    let ptrace = by_op(&record, "ptrace");
    assert!(ptrace.len() == 1 && ptrace[0].repeats == 20, "{record:#?}");
}

/// A flood is answered in full, and identical refusals merge into
/// one entry with their count (036). (`ptrace`: Docker's own profile refuses
/// `bpf` first, and a call an outer filter refuses never reaches procage's.)
#[test]
fn a_flood_is_answered_and_merged() {
    let cage = reporting(refusing(), host_tier());
    let (line, record) = reported(&cage, "flood:ptrace:20000");
    assert_eq!(line, "refused=20000");
    let ptrace = by_op(&record, "ptrace");
    assert_eq!(ptrace.len(), 1, "{record:#?}");
    assert_eq!(ptrace[0].repeats, 20_000);
    assert_eq!(record.dropped(), 0);
    assert!(record.complete());
}

/// Inside a sandbox whose filter already has a listener, the run is
/// confined as without reporting and the record says why.
#[test]
fn without_a_listener_the_run_is_still_confined() {
    // The outer filter stays on this test's thread only.
    let _outer = testing::install_outer_listener().unwrap();
    let cage = reporting(refusing(), host_tier());
    let (line, record) = reported(&cage, "syscall:ptrace");
    assert_eq!(line, EPERM.to_string());
    match record.coverage() {
        procage::Coverage::Unavailable(reason) => {
            assert!(reason.contains("busy"), "{reason}");
        }
        other => panic!("{other:?}"),
    }
}

/// Constitution IV: reporting spawns from many threads at once.
#[test]
fn reporting_spawns_from_many_threads() {
    let cage = std::sync::Arc::new(reporting(refusing(), host_tier()));
    let threads: Vec<_> = (0..4)
        .map(|_| {
            let cage = cage.clone();
            std::thread::spawn(move || {
                for _ in 0..5 {
                    let (line, record) = reported(&cage, "syscall:ptrace");
                    assert_eq!(line, EPERM.to_string());
                    assert_eq!(by_op(&record, "ptrace").len(), 1, "{record:#?}");
                }
            })
        })
        .collect();
    for t in threads {
        t.join().unwrap();
    }
}

/// A class name the caller cannot reach (a GitHub runner's root-only
/// `/run/podman`) is not covered and does not fail the spawn: the child,
/// the same user without capabilities over the host's files, cannot reach
/// it either. As root the name is reachable and covered as usual.
#[test]
fn a_cover_the_caller_cannot_reach_does_not_fail_the_spawn() {
    if !t1("a_cover_the_caller_cannot_reach_does_not_fail_the_spawn") {
        return;
    }
    let d = scratch("unreachable-runtime");
    let dir = d.join("run");
    std::fs::create_dir_all(&dir).unwrap();
    let _listener = std::os::unix::net::UnixListener::bind(dir.join("docker.sock")).unwrap();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o000)).unwrap();
    // The socket classes are in force with the network on; both are
    // accepted as covered at spawn.
    let mut p = base();
    p.net = Network::All;
    let lower = masked()
        .allow(Construct::of_class(HardDenyClass::ServiceHandoff))
        .allow(Construct::of_class(HardDenyClass::ContainerEngines))
        .accept_spawn_snapshot();
    let opts = options(Tier::T1).with_runtime_dir(&dir).with_lower(lower);
    let result = Cage::with_options(&p, &opts).and_then(|cage| {
        let mut cmd = Command::new("/bin/true");
        cage.spawn(&mut cmd, &Grants::new())
    });
    // Restored before asserting, so the scratch directory can be removed.
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    let mut child = result.unwrap_or_else(|e| panic!("spawn: {e}"));
    assert!(child.wait().unwrap().success());
}

/// On T1 the foreign sockets found at spawn are masked in the child. A
/// socket removed between that scan and the child's mount has nothing left
/// to mask: the spawn goes on (here, with another thread binding and
/// removing a socket the whole time).
#[test]
fn a_socket_removed_during_the_spawn_does_not_fail_it() {
    if !t1("a_socket_removed_during_the_spawn_does_not_fail_it") {
        return;
    }
    let allowed = scratch("churn-allowed");
    let churn = scratch("churn-foreign");
    let mut p = base();
    p.ipc.unix_sockets = vec![abs(&allowed)];
    // Every cover found at spawn is accepted: the host's own buses and
    // container engines are masked too (a GitHub runner has both).
    let lower = masked().accept_spawn_snapshot();
    let cage = Cage::with_options(&p, &options(Tier::T1).with_lower(lower)).unwrap();
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let flag = stop.clone();
    let socket = churn.join("s");
    let churner = std::thread::spawn(move || {
        let mut n = 0u64;
        while !flag.load(std::sync::atomic::Ordering::Relaxed) {
            let listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
            let _ = std::fs::remove_file(&socket);
            drop(listener);
            n += 1;
        }
        n
    });
    for i in 0..300 {
        let mut cmd = Command::new("/bin/true");
        let mut child = cage
            .spawn(&mut cmd, &Grants::new())
            .unwrap_or_else(|e| panic!("spawn {i}: {e}"));
        assert!(child.wait().unwrap().success(), "spawn {i}");
    }
    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    let rounds = churner.join().unwrap();
    assert!(rounds > 300, "the socket barely changed ({rounds} rounds)");
}
