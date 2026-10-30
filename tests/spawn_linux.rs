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

use std::io::Read;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

use procage::linux::{
    Cage, CageOptions, Child, GrantError, Grants, SpawnError, Step, Unsupported, probe, testing,
};
use procage::policy::{
    AbsPath, Access, Base, Construct, EnvPolicy, FsRule, FsTarget, GapKind, Grant, GrantName,
    HardDenyClass, LowerError, LowerOptions, Network, Policy, Tier,
};

const EACCES: i32 = 13;
const EPERM: i32 = 1;
const EROFS: i32 = 30;
const EBUSY: i32 = 16;

fn abs(p: impl AsRef<Path>) -> AbsPath {
    AbsPath::new(p.as_ref().to_str().unwrap()).unwrap()
}

/// A fresh directory for one test.
fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("procage-linux-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::canonicalize(dir).unwrap()
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
        ops => ops.split(';').map(op).collect::<Vec<_>>().join(" "),
    };
    println!("procage-result: {result}");
}

// ---- US1: a Linux harness spawns a caged child ----

#[test]
fn the_probe_reports_the_expected_tier() {
    let p = probe();
    println!(
        "tier {:?} landlock abi {} errata {} userns {:?}",
        p.tier, p.landlock_abi, p.errata, p.userns_errno
    );
    assert!(p.landlock_abi >= 4, "Landlock ABI {}", p.landlock_abi);
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

// ---- US2: never silently weaker ----

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

// ---- US3: data-driven hard-deny classes ----

/// A home with secrets and a persistence directory.
fn fake_home(name: &str) -> PathBuf {
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
fn workspace(name: &str) -> PathBuf {
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
    // A home outside /home is checked by the backend.
    let home = fake_home("us3-t2-home");
    let mut q = base();
    q.fs.push(FsRule::new(Access::Read, FsTarget::Subpath(abs(&home))));
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

// ---- US4: hygiene ----

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

// ---- US5: T1 isolation ----

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
