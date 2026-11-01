//! The escape suite on Linux: one or more canaries per escape class of the
//! published threat model.
//!
//! A canary is a test named after its class (`r21_…` for R-21). It spawns a
//! caged child that attempts the escape and asserts the specific refusal,
//! on every tier the host offers (a T1 host also runs the T2 cage). Where a
//! tier cannot express the protection, the canary asserts the typed refusal
//! before any child runs: failing closed counts as handled.
//!
//! Next to the attempt each canary runs a positive control under the same
//! cage: the same operation on a target the policy allows, or the same
//! attempt with the class waived. Syscall canaries print `informative=` per
//! call: under Docker's default seccomp profile many calls are refused by
//! the host already, and their evidence comes from the T1 lane.
//!
//! A variant this release does not handle is a canary marked
//! `#[ignore = "open: R-NN …"]`; `-- --ignored` shows the escape.
//! `PROCAGE_EXPECT_TIER` makes a lane that measures another tier fail.
//! Canaries write only to scratch directories and kill every process they
//! learn of.

#![cfg(target_os = "linux")]

use std::io::{BufRead, Read};
use std::net::TcpListener;
use std::os::fd::{AsFd, AsRawFd};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

use procage::linux::{Cage, CageOptions, Child, Grants, SpawnError, probe, testing};
use procage::policy::{
    AbsPath, Access, Base, Construct, EnvPolicy, FsRule, FsTarget, GapKind, Grant, GrantName,
    HardDenyClass, Lifetime, LowerError, LowerOptions, Network, Policy, Port, Ports, Tier,
};

const EPERM: i32 = 1;
const ECONNREFUSED: i32 = 111;
const EACCES: i32 = 13;
const EROFS: i32 = 30;
const EBUSY: i32 = 16;
const ENOSYS: i32 = 38;

fn abs(p: impl AsRef<Path>) -> AbsPath {
    AbsPath::new(p.as_ref().to_str().unwrap()).unwrap()
}

/// A fresh directory for one canary.
fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("procage-esc-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::canonicalize(dir).unwrap()
}

fn host_tier() -> Tier {
    let tier = probe()
        .tier
        .expect("a tier: the escape suite needs Landlock");
    if let Ok(expected) = std::env::var("PROCAGE_EXPECT_TIER") {
        assert_eq!(format!("{tier}"), expected, "TIER MISMATCH");
    }
    tier
}

fn tiers() -> Vec<Tier> {
    match host_tier() {
        Tier::T1 => vec![Tier::T1, Tier::T2],
        Tier::T2 => vec![Tier::T2],
    }
}

/// Whether the host gives T1; says so when it does not.
fn t1(canary: &str) -> bool {
    let yes = host_tier() == Tier::T1;
    if !yes {
        println!("{canary}: the T1 part is not applicable on this host");
    }
    yes
}

/// Base profile V1 plus exec of this test binary's directory.
fn policy() -> Policy {
    let mut p = Policy::default();
    p.base = Base::V1;
    let exe = std::fs::canonicalize(std::env::current_exe().unwrap()).unwrap();
    p.fs.push(FsRule::new(
        Access::Exec,
        FsTarget::Subpath(abs(exe.parent().unwrap())),
    ));
    p
}

fn rule(access: Access, p: impl AsRef<Path>) -> FsRule {
    FsRule::new(access, FsTarget::Subpath(abs(p)))
}

fn waived(mut p: Policy, classes: &[HardDenyClass]) -> Policy {
    p.waive.extend(classes.iter().copied());
    p
}

/// On T2 a write rule reaches trust-handoff names, which only a waiver
/// lets through.
fn for_tier(mut p: Policy, tier: Tier) -> Policy {
    if tier == Tier::T2 {
        p.waive.insert(HardDenyClass::TrustHandoff);
    }
    p
}

/// Options for `tier`: on T1 the data classes and literal rules may be
/// approximated.
fn options(tier: Tier) -> CageOptions {
    CageOptions::default().with_tier(tier).with_lower(
        LowerOptions::default()
            .allow(Construct::HdSecrets)
            .allow(Construct::HdTrustHandoff)
            .allow(Construct::HdPersistence)
            .allow(Construct::FsLiteral),
    )
}

fn cage(p: &Policy, tier: Tier) -> Cage {
    Cage::with_options(p, &options(tier)).unwrap_or_else(|e| panic!("{tier} cage: {e}"))
}

/// The gaps of a cage that must be refused.
fn refused(p: &Policy, opts: &CageOptions) -> Vec<(Construct, GapKind)> {
    match Cage::with_options(p, opts) {
        Err(SpawnError::Lower(LowerError::Gaps(gaps))) => {
            gaps.iter().map(|g| (g.construct, g.kind.clone())).collect()
        }
        Err(e) => panic!("unexpected error: {e}"),
        Ok(_) => panic!("the cage was prepared"),
    }
}

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
    while child.try_wait().unwrap().is_none() {
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

fn run_in(cage: &Cage, action: &str, grants: &Grants) -> String {
    let child = cage
        .spawn(&mut child_command(action), grants)
        .unwrap_or_else(|e| panic!("spawn: {e}"));
    result(&finish(child, Duration::from_secs(20)))
}

/// Runs `action` in a child caged by `policy` at `tier`.
fn in_child(action: &str, p: &Policy, tier: Tier) -> String {
    run_in(&cage(p, tier), action, &Grants::new())
}

/// Spawns `action` and returns the handle and the first result line,
/// without waiting for the child to exit.
fn start(cage: &Cage, action: &str) -> (Child, String) {
    let mut child = cage
        .spawn(&mut child_command(action), &Grants::new())
        .unwrap();
    let stdout = child.stdout.take().unwrap();
    let line = first_result(stdout);
    let Some(line) = line else {
        let mut err = String::new();
        let _ = child.stderr.take().unwrap().read_to_string(&mut err);
        panic!("no result from the child: {err}");
    };
    (child, line)
}

fn first_result(stdout: impl Read) -> Option<String> {
    std::io::BufReader::new(stdout).lines().find_map(|l| {
        l.ok()
            .and_then(|l| l.split_once("procage-result: ").map(|(_, r)| r.to_string()))
    })
}

fn errno_of<T>(r: std::io::Result<T>) -> String {
    match r {
        Ok(_) => "ok".into(),
        Err(e) => e.raw_os_error().unwrap_or(-1).to_string(),
    }
}

fn code(n: i32) -> String {
    if n == 0 { "ok".into() } else { n.to_string() }
}

/// One operation in the child: `verb:argument`.
fn op(spec: &str) -> String {
    let (verb, arg) = spec.split_once(':').unwrap_or((spec, ""));
    match verb {
        "read" => errno_of(std::fs::read(arg)),
        "write" => errno_of(std::fs::write(arg, "canary")),
        "rename" => {
            let (from, to) = arg.split_once('|').unwrap();
            errno_of(std::fs::rename(from, to))
        }
        "connect" => errno_of(std::net::TcpStream::connect((
            "127.0.0.1",
            arg.parse::<u16>().unwrap(),
        ))),
        "unix" => errno_of(std::os::unix::net::UnixStream::connect(arg)),
        "unix-serve" => match std::os::unix::net::UnixListener::bind(arg) {
            Ok(listener) => match std::os::unix::net::UnixStream::connect(arg) {
                Ok(_) => errno_of(listener.accept()),
                Err(e) => format!("connect-{}", e.raw_os_error().unwrap_or(-1)),
            },
            Err(e) => format!("bind-{}", e.raw_os_error().unwrap_or(-1)),
        },
        "abstract" => {
            use std::os::linux::net::SocketAddrExt;
            let addr = std::os::unix::net::SocketAddr::from_abstract_name(arg).unwrap();
            errno_of(std::os::unix::net::UnixStream::connect_addr(&addr))
        }
        "parent" => {
            let ppid = std::os::unix::process::parent_id();
            errno_of(std::fs::read(format!("/proc/{ppid}/{arg}")))
        }
        "tiocsti" => match std::fs::OpenOptions::new().read(true).write(true).open(arg) {
            Ok(f) => {
                let fd = f.as_raw_fd();
                format!(
                    "ctty={} sti={}",
                    code(testing::make_controlling(fd)),
                    code(testing::tiocsti_errno(fd, b'x'))
                )
            }
            Err(e) => format!("open-{}", e.raw_os_error().unwrap_or(-1)),
        },
        "umount" => code(testing::umount(arg)),
        "remount" => code(testing::remount_rw(arg)),
        "syscall" => code(testing::syscall_errno(arg).unwrap()),
        "trunc" => {
            let (route, path) = arg.split_once('|').unwrap();
            testing::truncate_errno(route, Path::new(path)).map_or("n/a".into(), code)
        }
        "setlen" => errno_of(
            std::fs::OpenOptions::new()
                .write(true)
                .open(arg)
                .and_then(|f| f.set_len(1)),
        ),
        other => format!("unknown-op-{other}"),
    }
}

#[test]
fn child_entry() {
    let Ok(action) = std::env::var("PROCAGE_CHILD") else {
        return;
    };
    let result = match action.as_str() {
        "env" => {
            let mut names: Vec<String> = std::env::vars_os()
                .map(|(k, _)| k.to_string_lossy().into_owned())
                .collect();
            names.sort();
            names.join(",")
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
        "session-sleeper" => format!("{}", testing::spawn_sleeper(true).unwrap()),
        "sessions" => {
            // The child leads its group and session already; each call is
            // tried in a process that leads neither.
            let try_in_child = |call: &str| {
                let mut cmd = child_command(&format!("syscall:{call}"));
                cmd.stderr(Stdio::null());
                let out = cmd.output().unwrap();
                first_result(&out.stdout[..]).unwrap_or_default()
            };
            format!("{} {}", try_in_child("setsid"), try_in_child("setpgid"))
        }
        "double-fork" => {
            // An intermediate starts a sleeper in its own session and exits;
            // the sleeper is reparented away from this child. The sleeper
            // inherits the pipe, so read one line, not to EOF.
            let mut cmd = child_command("session-sleeper");
            cmd.stderr(Stdio::null());
            let mut intermediate = cmd.spawn().unwrap();
            let pid = first_result(intermediate.stdout.take().unwrap()).unwrap();
            intermediate.wait().unwrap();
            println!("procage-result: {pid}");
            std::thread::sleep(Duration::from_secs(30));
            return;
        }
        "hold-tmpdir" => {
            let dir = std::env::var("TMPDIR").unwrap_or_default();
            let wrote = errno_of(std::fs::write(Path::new(&dir).join("f"), "mine"));
            println!("procage-result: {dir} {wrote}");
            std::thread::sleep(Duration::from_secs(30));
            return;
        }
        "own-tmpdir" => {
            let dir = std::env::var("TMPDIR").unwrap_or_default();
            errno_of(std::fs::write(Path::new(&dir).join("g"), "mine"))
        }
        "outer-env" => outer_env(),
        ops => ops.split(';').map(op).collect::<Vec<_>>().join(" "),
    };
    println!("procage-result: {result}");
}

/// Runs uncaged with secrets in its own environment (set by the canary) and
/// reports which names reach a child under the default policy and under
/// passthrough, and whether an explicitly set variable does.
fn outer_env() -> String {
    let tier = host_tier();
    let names = |p: &Policy, explicit: bool| {
        let mut cmd = child_command("env");
        if explicit {
            cmd.env("PROCAGE_EXPLICIT", "yes");
        }
        let child = cage(p, tier).spawn(&mut cmd, &Grants::new()).unwrap();
        result(&finish(child, Duration::from_secs(20)))
    };
    let mut passthrough = policy();
    passthrough.env = EnvPolicy::Passthrough { deny: vec![] };
    format!(
        "default=[{}] passthrough=[{}] explicit=[{}]",
        names(&policy(), false),
        names(&passthrough, false),
        names(&passthrough, true)
    )
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

fn kill_now(pid: u32) {
    let _ = Command::new("kill").args(["-9", &pid.to_string()]).status();
}

/// Runs syscall probes caged with unrestricted network, and caged with
/// `classes` waived as well. Every
/// informative call (one the waived cage does not refuse with EPERM) must
/// be refused with `expected` when caged; returns how many were informative.
fn syscalls(names: &[&str], expected: &[i32], classes: &[HardDenyClass], tier: Tier) -> usize {
    let ops: Vec<String> = names.iter().map(|n| format!("syscall:{n}")).collect();
    let ops = ops.join(";");
    // `Network::None` refuses every socket; both cages allow them, so only
    // the class's own rules can refuse.
    let mut open = policy();
    open.net = Network::All;
    let caged = in_child(&ops, &open, tier);
    let control = in_child(&ops, &waived(open, classes), tier);
    let mut informative = 0;
    for (((name, caged), control), want) in names
        .iter()
        .zip(caged.split(' '))
        .zip(control.split(' '))
        .zip(expected)
    {
        let useful = control != EPERM.to_string() && control != want.to_string();
        println!("{tier}: {name} caged={caged} waived={control} informative={useful}");
        if useful {
            informative += 1;
            assert_eq!(caged, want.to_string(), "{tier}: {name}");
        }
    }
    informative
}

// ---- R-02 Non-canonical path rules ----

/// A rule spelled through a symbolic link binds the link's target: a write
/// rule reaches the target and nothing beside it, and on T1 a protect rule
/// through the link holds for the real path. On T2 protect is refused.
#[test]
fn r02_a_rule_spelled_through_a_symlink_binds_its_target() {
    let w = scratch("r02");
    std::fs::create_dir_all(w.join("t/p")).unwrap();
    std::os::unix::fs::symlink(w.join("t"), w.join("link")).unwrap();
    let d = w.display();
    for tier in tiers() {
        let mut p = policy();
        p.fs.push(rule(Access::Write, w.join("link")));
        let p = for_tier(p, tier);
        let got = in_child(&format!("write:{d}/t/f;write:{d}/f"), &p, tier);
        assert_eq!(got, format!("ok {EACCES}"), "{tier}");
    }
    let mut p = policy();
    p.fs.push(rule(Access::Write, &w));
    p.fs.push(rule(Access::Protect, w.join("link/p")));
    if t1("r02") {
        let got = in_child(&format!("write:{d}/q;write:{d}/t/p/f"), &p, Tier::T1);
        assert_eq!(got, format!("ok {EROFS}"));
    }
    let gaps = refused(&for_tier(p, Tier::T2), &options(Tier::T2));
    assert!(
        gaps.contains(&(Construct::FsProtect, GapKind::Unsupported)),
        "{gaps:?}"
    );
}

// ---- R-04 Ancestor rename ----

/// After renaming an ancestor of a protected directory, the protected file
/// is unwritable under every name. On T2 protect is refused.
#[test]
fn r04_a_protected_file_stays_protected_when_an_ancestor_is_renamed() {
    let w = scratch("r04");
    std::fs::create_dir_all(w.join("sub/p")).unwrap();
    std::fs::write(w.join("sub/p/c"), "original").unwrap();
    let mut p = policy();
    p.fs.push(rule(Access::Write, &w));
    p.fs.push(rule(Access::Protect, w.join("sub/p")));
    if t1("r04") {
        let d = w.display();
        let got = in_child(
            &format!(
                "write:{d}/other;rename:{d}/sub|{d}/moved;write:{d}/sub/p/c;write:{d}/moved/p/c"
            ),
            &p,
            Tier::T1,
        );
        let r: Vec<&str> = got.split(' ').collect();
        assert_eq!(r[0], "ok", "{got}");
        assert!(r[2] != "ok" && r[3] != "ok", "{got}");
        let content = std::fs::read_to_string(w.join("sub/p/c"))
            .or_else(|_| std::fs::read_to_string(w.join("moved/p/c")))
            .unwrap();
        assert_eq!(content, "original");
    }
    let gaps = refused(&for_tier(p, Tier::T2), &options(Tier::T2));
    assert!(
        gaps.contains(&(Construct::FsProtect, GapKind::Unsupported)),
        "{gaps:?}"
    );
}

// ---- R-07 Trust handoff (the part procage handles) ----

/// Hooks, git config and shell startup files in a writable workspace are
/// read-only on T1; on T2 such a policy is refused unless waived.
#[test]
fn r07_trust_handoff_files_are_protected_in_a_writable_workspace() {
    let w = scratch("r07");
    std::fs::create_dir_all(w.join(".git/hooks")).unwrap();
    std::fs::create_dir_all(w.join("src")).unwrap();
    std::fs::write(w.join(".git/config"), "[core]").unwrap();
    std::fs::write(w.join(".bashrc"), "").unwrap();
    let mut p = policy();
    p.fs.push(rule(Access::Write, &w));
    if t1("r07") {
        let d = w.display();
        let got = in_child(
            &format!(
                "write:{d}/src/main.rs;write:{d}/.git/hooks/pre-commit;write:{d}/.git/config;write:{d}/.bashrc"
            ),
            &p,
            Tier::T1,
        );
        assert_eq!(got, format!("ok {EROFS} {EROFS} {EROFS}"));
    }
    let gaps = refused(&p, &options(Tier::T2));
    assert!(
        gaps.contains(&(Construct::HdTrustHandoff, GapKind::Unsupported)),
        "{gaps:?}"
    );
}

// ---- R-08 Pre-existing hard links ----

/// A hard link made before the run gives a hidden file a second name.
#[test]
#[ignore = "open: R-08 a pre-existing hard link to a hidden file is neither reported nor refused"]
fn r08_a_hard_link_to_a_hidden_file_is_refused() {
    if !t1("r08") {
        return;
    }
    let d = scratch("r08");
    std::fs::create_dir_all(d.join("secret")).unwrap();
    std::fs::create_dir_all(d.join("ws")).unwrap();
    std::fs::write(d.join("secret/key"), "key").unwrap();
    std::fs::hard_link(d.join("secret/key"), d.join("ws/key")).unwrap();
    let mut p = policy();
    p.fs.push(rule(Access::Read, &d));
    p.fs.push(rule(Access::Hide, d.join("secret")));
    let got = in_child(
        &format!("read:{0}/secret/key;read:{0}/ws/key", d.display()),
        &p,
        Tier::T1,
    );
    assert_eq!(got, format!("{EACCES} {EACCES}"));
}

// ---- R-09 Local daemons ----

/// Without network access the child reaches neither a loopback port nor a
/// unix-domain socket in a readable directory; with unrestricted network it
/// reaches the socket. Loopback ports, which Linux cannot enforce in this
/// release, are refused.
#[test]
fn r09_daemons_are_unreachable_without_network_access() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let d = scratch("r09");
    let sock = d.join("daemon.sock");
    let _daemon = std::os::unix::net::UnixListener::bind(&sock).unwrap();
    let attempt = format!("connect:{port};unix:{}", sock.display());
    for tier in tiers() {
        let mut p = policy();
        p.fs.push(rule(Access::Read, &d));
        p.net = Network::None;
        assert_eq!(
            in_child(&attempt, &p, tier),
            format!("{EPERM} {EPERM}"),
            "{tier}"
        );
        p.net = Network::All;
        let control = in_child(&format!("unix:{}", sock.display()), &p, tier);
        assert_eq!(control, "ok", "{tier}");
        p.net = Network::Loopback(Ports::List([Port::new(port).unwrap()].into()));
        let gaps = refused(&p, &options(tier));
        assert!(
            gaps.iter().any(|g| g.0 == Construct::NetLoopback),
            "{tier} {gaps:?}"
        );
    }
}

/// `ipc.unix_sockets` lets the child bind and connect under its paths only.
/// On T1 a daemon socket elsewhere (masked at spawn), a host abstract socket
/// (another network namespace) and TCP stay out, and the setting needs the
/// snapshot accepted; T2 refuses it below Landlock ABI 9.
#[test]
fn r09_unix_sockets_reach_only_their_paths() {
    use std::os::linux::net::SocketAddrExt;
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let d = scratch("r09-ipc");
    let ws = d.join("ws");
    std::fs::create_dir_all(&ws).unwrap();
    let sock = d.join("daemon.sock");
    let _daemon = std::os::unix::net::UnixListener::bind(&sock).unwrap();
    let name = format!("procage-r09-{}", std::process::id());
    let addr = std::os::unix::net::SocketAddr::from_abstract_name(&name).unwrap();
    let _abstract = std::os::unix::net::UnixListener::bind_addr(&addr).unwrap();
    let attempt = format!(
        "unix-serve:{};unix:{};abstract:{name};connect:{port}",
        ws.join("s.sock").display(),
        sock.display()
    );
    for tier in tiers() {
        let mut p = policy();
        p.fs.push(rule(Access::Read, &d));
        p.fs.push(rule(Access::Write, &ws));
        p.ipc.unix_sockets = vec![abs(&ws)];
        let gaps = refused(&p, &options(tier));
        assert!(
            gaps.iter().any(|g| g.0 == Construct::IpcUnixSockets),
            "{tier} {gaps:?}"
        );
        if tier == Tier::T2 && probe().landlock_abi < 9 {
            continue;
        }
        let snapshot = CageOptions::default()
            .with_tier(tier)
            .with_lower(LowerOptions::default().accept_spawn_snapshot());
        let cage = Cage::with_options(&p, &snapshot).unwrap();
        let got = run_in(&cage, &attempt, &Grants::new());
        assert_eq!(
            got,
            format!("ok {ECONNREFUSED} {ECONNREFUSED} {EPERM}"),
            "{tier}"
        );
    }
}

// ---- R-10 Shared temporary directory ----

/// While one run holds its private temporary directory, another run can
/// neither read nor write it, nor write the shared temporary root.
#[test]
fn r10_runs_do_not_share_temporary_files() {
    for tier in tiers() {
        let mut p = policy();
        p.grants.push(Grant {
            name: GrantName::new("tmpdir").unwrap(),
            access: Access::Write,
        });
        let c = cage(&for_tier(p, tier), tier);
        let (holder, line) = start(&c, "hold-tmpdir");
        let (dir, wrote) = line.split_once(' ').unwrap();
        assert_eq!(wrote, "ok", "{tier}");
        let shared = std::env::temp_dir();
        let got = run_in(
            &c,
            &format!(
                "read:{dir}/f;write:{dir}/g;write:{}/procage-r10",
                shared.display()
            ),
            &Grants::new(),
        );
        let own = run_in(&c, "own-tmpdir", &Grants::new());
        drop(holder);
        assert_eq!(got, format!("{EACCES} {EACCES} {EACCES}"), "{tier}");
        assert_eq!(own, "ok", "{tier}");
    }
}

// ---- R-21 Inherited file descriptors ----

/// A descriptor to a file outside the policy, inheritable in the parent,
/// does not reach the child; handed over explicitly, it does.
#[test]
fn r21_an_inherited_descriptor_does_not_reach_the_child() {
    let d = scratch("r21");
    std::fs::write(d.join("secret"), "secret").unwrap();
    let file = std::fs::File::open(d.join("secret")).unwrap();
    let fd = file.as_raw_fd();
    assert!(testing::clear_cloexec(fd));
    let action = format!("fd:{fd}");
    for tier in tiers() {
        let c = cage(&policy(), tier);
        assert_eq!(run_in(&c, &action, &Grants::new()), "open=false", "{tier}");
        let child = c
            .spawn_with_fds(&mut child_command(&action), &Grants::new(), &[file.as_fd()])
            .unwrap();
        let control = result(&finish(child, Duration::from_secs(20)));
        assert_eq!(control, "open=true", "{tier}");
    }
}

// ---- R-22 Terminal input injection ----

/// A child cannot push input into a terminal. seccomp refuses TIOCSTI with
/// EPERM before anything else checks it; with the class waived the call
/// gets past the filter (Landlock's device-ioctl right, or the kernel's
/// controlling-terminal check, then answers instead).
#[test]
fn r22_terminal_input_injection_is_refused() {
    let (_controller, device) = testing::open_pty().unwrap();
    let attempt = format!("tiocsti:{}", device.display());
    for tier in tiers() {
        let mut p = policy();
        p.fs.push(FsRule::new(Access::Write, FsTarget::Literal(abs(&device))));
        let p = for_tier(p, tier);
        let got = in_child(&attempt, &p, tier);
        let control = in_child(
            &attempt,
            &waived(p, &[HardDenyClass::TerminalInjection]),
            tier,
        );
        println!("{tier}: caged {got}; waived {control}");
        assert!(got.ends_with(&format!("sti={EPERM}")), "{tier}: {got}");
        assert!(
            !control.ends_with(&format!("sti={EPERM}")),
            "{tier}: {control}"
        );
    }
}

// ---- R-23 Outliving the run ----

/// Dropping the handle kills a descendant in the child's group and one in a
/// session of its own.
#[test]
fn r23_descendants_die_with_the_run() {
    for tier in tiers() {
        let mut p = policy();
        p.process.fork = true;
        let (child, pids) = start(&cage(&p, tier), "sleepers");
        let pids: Vec<u32> = pids.split(' ').map(|p| p.parse().unwrap()).collect();
        assert!(pids.iter().all(|&p| testing::alive(p)), "{tier}");
        drop(child);
        for pid in pids {
            let gone = gone_within(pid, Duration::from_secs(2));
            if !gone {
                kill_now(pid);
            }
            assert!(gone, "{tier}: descendant {pid} survived");
        }
    }
}

/// Asserts that `pid` dies within two seconds, killing it otherwise.
fn assert_dies(pid: u32, what: &str) {
    let gone = gone_within(pid, Duration::from_secs(2));
    if !gone {
        kill_now(pid);
    }
    assert!(gone, "{what} {pid} survived");
}

/// A descendant whose parent exited before the run ended cannot leave the
/// child's process group (its `setsid` fails), so it is reparented outside
/// the child's tree but still dies with the group.
#[test]
fn r23_a_double_forked_descendant_dies_with_the_run() {
    for tier in tiers() {
        let mut p = policy();
        p.process.fork = true;
        let (child, pid) = start(&cage(&p, tier), "double-fork");
        let pid: u32 = pid.parse().unwrap();
        assert!(testing::alive(pid), "{tier}");
        drop(child);
        assert_dies(pid, &format!("{tier}: descendant"));
    }
}

/// A descendant left by a child that exited and was waited for before the
/// run ended dies when the handle is dropped.
#[test]
fn r23_descendants_of_an_exited_child_die_with_the_run() {
    for tier in tiers() {
        let mut p = policy();
        p.process.fork = true;
        let (mut child, pid) = start(&cage(&p, tier), "session-sleeper");
        let pid: u32 = pid.parse().unwrap();
        // Its exit status is not the point: the harness may write after
        // the result to the pipe the test already closed.
        child.wait().unwrap();
        assert!(
            testing::alive(pid),
            "{tier}: the descendant must outlive the child"
        );
        drop(child);
        assert_dies(pid, &format!("{tier}: descendant"));
    }
}

/// By default no process of the run can start a session or a process group.
#[test]
fn r23_sessions_are_locked() {
    for tier in tiers() {
        let mut p = policy();
        p.process.fork = true;
        let (child, got) = start(&cage(&p, tier), "sessions");
        drop(child);
        assert_eq!(got, format!("{EPERM} {EPERM}"), "{tier}");
    }
}

/// With `Lifetime::Tree` processes may start sessions and process groups.
#[test]
fn r23_tree_lifetime_allows_sessions() {
    for tier in tiers() {
        let mut p = policy();
        p.process.fork = true;
        p.process.lifetime = Lifetime::Tree;
        let (child, got) = start(&cage(&p, tier), "sessions");
        drop(child);
        assert_eq!(got, "ok ok", "{tier}");
    }
}

/// A systemd user unit cannot be planted in a writable home on T1; on T2
/// such a policy is refused unless waived.
#[test]
fn r23_a_user_unit_cannot_be_planted() {
    let home = scratch("r23-home");
    std::fs::create_dir_all(home.join(".config/systemd/user")).unwrap();
    let mut p = policy();
    p.fs.push(rule(Access::Write, &home));
    if t1("r23") {
        let c = Cage::with_options(&p, &options(Tier::T1).with_home(&home)).unwrap();
        let got = run_in(
            &c,
            &format!(
                "write:{0}/.config/systemd/user/canary.service;write:{0}/notes.txt",
                home.display()
            ),
            &Grants::new(),
        );
        assert_eq!(got, format!("{EROFS} ok"));
        assert!(!home.join(".config/systemd/user/canary.service").exists());
    }
    let err = Cage::with_options(&for_tier(p, Tier::T2), &options(Tier::T2).with_home(&home))
        .unwrap_err();
    assert!(err.to_string().contains("hd-persistence"), "{err}");
}

// ---- R-24 Secrets in the environment ----

/// Tokens, keys and agent sockets in the caller's environment reach the
/// child neither by default nor under passthrough; a variable the caller
/// sets explicitly does.
#[test]
fn r24_secret_variables_do_not_reach_the_child() {
    let mut cmd = child_command("outer-env");
    cmd.env("GITHUB_TOKEN", "t")
        .env("AWS_SECRET_ACCESS_KEY", "k")
        .env("SSH_AUTH_SOCK", "/tmp/agent.sock")
        .env("LD_PRELOAD", "/nonexistent.so");
    let got = result(&cmd.output().unwrap());
    for secret in [
        "GITHUB_TOKEN",
        "AWS_SECRET_ACCESS_KEY",
        "SSH_AUTH_SOCK",
        "LD_PRELOAD",
    ] {
        assert!(!got.contains(secret), "{secret} reached the child: {got}");
    }
    assert!(got.contains("PROCAGE_EXPLICIT"), "control: {got}");
}

// ---- R-25 Process introspection ----

/// The child cannot read the caller's environment or arguments through
/// `/proc`, trace it, or read its memory. Even with `/proc` readable, the
/// caller's environment stays out of reach (Landlock's ptrace scope); the
/// child's own stays readable.
#[test]
fn r25_other_processes_are_opaque() {
    for tier in tiers() {
        let got = in_child(
            "parent:environ;parent:cmdline;syscall:ptrace;syscall:process_vm_readv",
            &policy(),
            tier,
        );
        assert_eq!(got, format!("{EACCES} {EACCES} {EPERM} {EPERM}"), "{tier}");
        let mut p = policy();
        p.fs.push(rule(Access::Read, "/proc"));
        let got = in_child(
            "parent:environ;read:/proc/self/environ;parent:cmdline",
            &p,
            tier,
        );
        println!("{tier}: with /proc readable: {got}");
        let r: Vec<&str> = got.split(' ').collect();
        assert_eq!(r[..2], [EACCES.to_string().as_str(), "ok"], "{tier}: {got}");
    }
}

// ---- R-26 Helper replacement ----

/// procage runs no helper program in this release; this canary attacks the
/// helper once it does.
#[test]
#[ignore = "open: R-26 no helper exists in this release"]
fn r26_the_helper_cannot_be_replaced() {
    panic!("open: R-26: procage runs no helper in this release");
}

// ---- R-28 Filter-bypassing kernel interfaces ----

/// io_uring, netlink and VM sockets are refused with EPERM; with the
/// classes waived the kernel answers instead.
#[test]
fn r28_filter_bypassing_interfaces_are_refused() {
    let names = ["io_uring_setup", "socket_netlink", "socket_vsock"];
    let classes = [HardDenyClass::KernelSurface, HardDenyClass::SocketFamilies];
    for tier in tiers() {
        let informative = syscalls(&names, &[EPERM; 3], &classes, tier);
        if host_tier() == Tier::T1 {
            assert!(informative >= 2, "{tier}: {informative} informative calls");
        }
    }
}

// ---- R-29 Nested user namespaces ----

/// A nested user namespace cannot be created (EPERM; `clone3` reports
/// ENOSYS so callers fall back to the filtered `clone`), and a protected
/// mount can be neither unmounted nor remounted writable.
#[test]
fn r29_nested_user_namespaces_and_mount_changes_are_refused() {
    let names = ["unshare_user", "clone3", "setns"];
    for tier in tiers() {
        let informative = syscalls(
            &names,
            &[EPERM, ENOSYS, EPERM],
            &[HardDenyClass::Namespaces],
            tier,
        );
        if host_tier() == Tier::T1 {
            assert!(informative >= 2, "{tier}: {informative} informative calls");
        }
    }
    if t1("r29") {
        let w = scratch("r29");
        std::fs::create_dir_all(w.join("p")).unwrap();
        let mut p = policy();
        p.fs.push(rule(Access::Write, &w));
        p.fs.push(rule(Access::Protect, w.join("p")));
        let d = w.display();
        let got = in_child(
            &format!("umount:{d}/p;remount:{d}/p;write:{d}/p/f"),
            &p,
            Tier::T1,
        );
        assert_eq!(got, format!("{EPERM} {EPERM} {EROFS}"));
    }
}

// ---- R-31 Truncation without write access ----

/// Below Landlock ABI 3 the kernel cannot deny truncation, so the plan
/// refuses truncating by path and opening with `O_TRUNC` without write
/// access, on both tiers; files outside the writable paths keep their
/// content. Writing a workspace file and truncating it through a write
/// descriptor still work. From ABI 3 Landlock refuses the same calls
/// outside the writable paths (EACCES) and allows them inside.
#[test]
fn r31_files_outside_the_writable_paths_cannot_be_truncated() {
    let routes = ["truncate", "rdonly", "noaccess", "openat2", "open"];
    for tier in tiers() {
        for abi in [1, 2, 3] {
            let w = scratch(&format!("r31-w-{tier}-{abi}"));
            let o = scratch(&format!("r31-o-{tier}-{abi}"));
            let mut p = policy();
            p.fs.push(rule(Access::Write, &w));
            p.fs.push(rule(Access::Read, &o));
            let p = for_tier(p, tier);
            let c = Cage::with_options(&p, &options(tier).with_landlock_abi(abi))
                .unwrap_or_else(|e| panic!("{tier} ABI {abi}: {e}"));
            assert_eq!(c.landlock_abi(), abi);
            let mut ops = Vec::new();
            for route in routes {
                std::fs::write(o.join(route), "content").unwrap();
                ops.push(format!("trunc:{route}|{}", o.join(route).display()));
            }
            let wf = w.join("f");
            std::fs::write(&wf, "content").unwrap();
            ops.push(format!("write:{}", wf.display()));
            ops.push(format!("setlen:{}", wf.display()));
            ops.push(format!("trunc:truncate|{}", wf.display()));
            let got = run_in(&c, &ops.join(";"), &Grants::new());
            let open = if cfg!(target_arch = "x86_64") {
                "{e}"
            } else {
                "n/a"
            };
            let expected = if abi < 3 {
                format!(
                    "{EPERM} {EPERM} {EPERM} {ENOSYS} {} ok ok {EPERM}",
                    open.replace("{e}", &EPERM.to_string())
                )
            } else {
                let e = EACCES;
                format!(
                    "{e} {e} {e} {e} {} ok ok ok",
                    open.replace("{e}", &e.to_string())
                )
            };
            assert_eq!(got, expected, "{tier} ABI {abi}");
            for route in routes {
                let kept = std::fs::read_to_string(o.join(route)).unwrap();
                assert_eq!(kept, "content", "{tier} ABI {abi} {route}");
            }
        }
    }
}

// ---- R-30 Landlock rule loss ----

/// On T1 a protected file cannot be replaced by renaming another file over
/// it, nor written. A rule on a path that does not exist fails before any
/// child runs. On T2 protect is refused.
#[test]
fn r30_a_protected_file_cannot_be_replaced() {
    let w = scratch("r30");
    std::fs::write(w.join("f"), "original").unwrap();
    let mut p = policy();
    p.fs.push(rule(Access::Write, &w));
    p.fs.push(FsRule::new(
        Access::Protect,
        FsTarget::Literal(abs(w.join("f"))),
    ));
    if t1("r30") {
        let d = w.display();
        let got = in_child(
            &format!("write:{d}/tmp;rename:{d}/tmp|{d}/f;write:{d}/f"),
            &p,
            Tier::T1,
        );
        assert_eq!(got, format!("ok {EBUSY} {EROFS}"));
        assert_eq!(std::fs::read_to_string(w.join("f")).unwrap(), "original");
    }
    let gaps = refused(&for_tier(p, Tier::T2), &options(Tier::T2));
    assert!(gaps.iter().any(|g| g.0 == Construct::FsProtect), "{gaps:?}");
    let mut missing = policy();
    missing.fs.push(rule(Access::Read, w.join("absent")));
    let c = cage(&missing, host_tier());
    let err = c
        .spawn(&mut Command::new("/bin/true"), &Grants::new())
        .unwrap_err();
    assert!(matches!(err, SpawnError::Path { .. }), "{err}");
}
