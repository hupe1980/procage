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

#[path = "support/asynchronous.rs"]
mod asynchronous;
#[cfg(feature = "proxy")]
#[path = "support/proxied.rs"]
mod proxied;
#[path = "support/scratch.rs"]
mod scratch_support;
use scratch_support::Scratch;

use std::io::{BufRead, Read};
use std::net::TcpListener;
use std::os::fd::{AsFd, AsRawFd};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

use procage::linux::{Cage, CageOptions, Child, Grants, SpawnError, probe, testing};
use procage::policy::{
    AbsPath, Access, Base, Construct, EnvPolicy, FsRule, FsTarget, GapKind, Grant, GrantName,
    HardDenyClass, Lifetime, LowerError, LowerOptions, Network, Policy, Port, Ports, Tier, Tty,
};

const EPERM: i32 = 1;
const ECONNREFUSED: i32 = 111;
const EACCES: i32 = 13;
const EROFS: i32 = 30;
const EBUSY: i32 = 16;
const EXDEV: i32 = 18;
const ENOSYS: i32 = 38;

fn abs(p: impl AsRef<Path>) -> AbsPath {
    AbsPath::new(p.as_ref().to_str().unwrap()).unwrap()
}

/// A fresh directory for one canary.
fn scratch(name: &str) -> Scratch {
    Scratch::at(std::env::temp_dir().join(format!("procage-esc-{name}-{}", std::process::id())))
        .canonical()
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

/// The Landlock ABI cages use here: the kernel's, at most the backend's.
fn abi() -> u8 {
    probe().landlock_abi.min(procage::linux::BACKEND_MAX_ABI)
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

/// `p` with the network on, for canaries of other classes: the socket
/// classes are waived, since a host with a user bus or an engine (CI
/// runners) would otherwise make the cage a gap on tier T2 (R-34 has its own
/// canaries).
fn net_on(mut p: Policy) -> Policy {
    p.net = Network::All;
    p.waive.extend(SOCKET_CLASSES);
    p
}

const SOCKET_CLASSES: [HardDenyClass; 2] = [
    HardDenyClass::ServiceHandoff,
    HardDenyClass::ContainerEngines,
];

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
/// approximated. With `PROCAGE_ESCAPE_VIOLATIONS=1` cages report refused
/// calls, so the suite shows that reporting weakens nothing.
fn options(tier: Tier) -> CageOptions {
    let options = CageOptions::default().with_tier(tier).with_lower(
        LowerOptions::default()
            .allow(Construct::HdSecrets)
            .allow(Construct::HdTrustHandoff)
            .allow(Construct::HdPersistence)
            .allow(Construct::FsLiteral),
    );
    if std::env::var_os("PROCAGE_ESCAPE_VIOLATIONS").is_some_and(|v| v == "1") {
        options.with_violations()
    } else {
        options
    }
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
    if asynchronous::on() {
        let out = asynchronous::output(
            cage,
            child_command(action),
            grants,
            &[],
            Duration::from_secs(20),
        );
        return result(&out);
    }
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
        "listen" => errno_of(std::net::TcpListener::bind("127.0.0.1:0")),
        "udp-send" => errno_of(
            std::net::UdpSocket::bind("127.0.0.1:0")
                .and_then(|s| s.send_to(b"canary", ("127.0.0.1", arg.parse::<u16>().unwrap()))),
        ),
        "resolve" => errno_of(std::net::ToSocketAddrs::to_socket_addrs(&(arg, 80))),
        // Sends on a UDP socket the parent handed over: `fd|port`.
        "net" => {
            let (kind, port) = arg.split_once('|').unwrap();
            code(testing::net_errno(kind, port.parse().unwrap()))
        }
        "udp-fd" => {
            let (fd, port) = arg.split_once('|').unwrap();
            code(testing::udp_send_errno(
                fd.parse().unwrap(),
                port.parse().unwrap(),
            ))
        }
        "link" => {
            let (from, to) = arg.split_once('|').unwrap();
            errno_of(std::fs::hard_link(from, to))
        }
        // Connects after the parent had time to bind the socket.
        "delayed-unix" => {
            std::thread::sleep(Duration::from_millis(1500));
            errno_of(std::os::unix::net::UnixStream::connect(arg))
        }
        "unix-serve" => match std::os::unix::net::UnixListener::bind(arg) {
            Ok(listener) => match std::os::unix::net::UnixStream::connect(arg) {
                Ok(_) => errno_of(listener.accept()),
                Err(e) => format!("connect-{}", e.raw_os_error().unwrap_or(-1)),
            },
            Err(e) => format!("bind-{}", e.raw_os_error().unwrap_or(-1)),
        },
        // Writes a file in the run's `TMPDIR` and moves it to `arg`.
        "tmpdir-move" => {
            let from = Path::new(&std::env::var("TMPDIR").unwrap_or_default()).join("moved");
            match std::fs::write(&from, "canary") {
                Ok(()) => errno_of(std::fs::rename(&from, arg)),
                Err(e) => format!("write-{}", e.raw_os_error().unwrap_or(-1)),
            }
        }
        "abstract" => {
            use std::os::linux::net::SocketAddrExt;
            let addr = std::os::unix::net::SocketAddr::from_abstract_name(arg).unwrap();
            errno_of(std::os::unix::net::UnixStream::connect_addr(&addr))
        }
        "parent" => {
            let ppid = std::os::unix::process::parent_id();
            errno_of(std::fs::read(format!("/proc/{ppid}/{arg}")))
        }
        "tiocsti-own" => code(testing::tiocsti_errno(0, b'#')),
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
        other => {
            #[cfg(feature = "proxy")]
            if let Some(result) = proxied::op(other, arg) {
                return result;
            }
            format!("unknown-op-{other}")
        }
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
        listeners if listeners.starts_with("listeners:") => {
            // How many seccomp listeners this process holds, and what
            // reopening the parent's through /proc gives.
            let is_listener = |link: &Path| {
                std::fs::read_link(link)
                    .is_ok_and(|t| t.to_string_lossy().contains("seccomp notify"))
            };
            let own = std::fs::read_dir("/proc/self/fd")
                .map(|d| {
                    d.filter_map(Result::ok)
                        .filter(|e| is_listener(&e.path()))
                        .count()
                })
                .unwrap_or(0);
            let parent = &listeners["listeners:".len()..];
            let mut seen = 0;
            let mut reopened = 0;
            for fd in 3..64 {
                let link = PathBuf::from(format!("/proc/{parent}/fd/{fd}"));
                if is_listener(&link) {
                    seen += 1;
                    if std::fs::OpenOptions::new()
                        .read(true)
                        .write(true)
                        .open(&link)
                        .is_ok()
                    {
                        reopened += 1;
                    }
                }
            }
            format!("own={own} parent-seen={seen} reopened={reopened}")
        }
        "sleepers" => {
            let same = testing::spawn_sleeper(false).unwrap();
            let session = testing::spawn_sleeper(true).unwrap();
            println!("procage-result: {same} {session}");
            std::thread::sleep(Duration::from_secs(30));
            return;
        }
        "session-sleeper" => format!("{}", testing::spawn_sleeper(true).unwrap()),
        // A sleeper in a process group of its own, as test runners start
        // each test.
        "group-sleeper" => {
            use std::os::unix::process::CommandExt;
            match Command::new("/bin/sleep")
                .arg("30")
                .process_group(0)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .spawn()
            {
                Ok(c) => c.id().to_string(),
                Err(e) => code(e.raw_os_error().unwrap_or(-1)),
            }
        }
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
        // An intermediate starts a sleeper in its own session (or, with
        // `group-`, its own process group) and exits; the sleeper is
        // reparented away from this child. The sleeper inherits the pipe,
        // so read one line, not to EOF.
        "double-fork" | "group-double-fork" => {
            let mut cmd = child_command(if action == "group-double-fork" {
                "group-sleeper"
            } else {
                "session-sleeper"
            });
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
    let open = net_on(policy());
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

/// After renaming an ancestor of a protected directory, in its directory or
/// into another, the protected file is unwritable under every name. On T2
/// protect is refused.
#[test]
fn r04_a_protected_file_stays_protected_when_an_ancestor_is_renamed() {
    let w = scratch("r04");
    std::fs::create_dir_all(w.join("sub/p")).unwrap();
    std::fs::create_dir_all(w.join("elsewhere")).unwrap();
    std::fs::write(w.join("sub/p/c"), "original").unwrap();
    let mut p = policy();
    p.fs.push(rule(Access::Write, &w));
    p.fs.push(rule(Access::Protect, w.join("sub/p")));
    if t1("r04") {
        let d = w.display();
        let got = in_child(
            &format!(
                "write:{d}/other;rename:{d}/sub|{d}/moved;rename:{d}/moved|{d}/elsewhere/moved;\
                 write:{d}/sub/p/c;write:{d}/moved/p/c;write:{d}/elsewhere/moved/p/c"
            ),
            &p,
            Tier::T1,
        );
        let r: Vec<&str> = got.split(' ').collect();
        assert_eq!(r[0], "ok", "{got}");
        assert!(r[3..].iter().all(|r| *r != "ok"), "{got}");
        let content = ["sub", "moved", "elsewhere/moved"]
            .iter()
            .find_map(|a| std::fs::read_to_string(w.join(a).join("p/c")).ok())
            .unwrap();
        assert_eq!(content, "original");
    }
    let gaps = refused(&for_tier(p, Tier::T2), &options(Tier::T2));
    assert!(
        gaps.contains(&(Construct::FsProtect, GapKind::Unsupported)),
        "{gaps:?}"
    );
}

/// Files move and link between the directories of the writable trees and
/// the run's temporary directory, as compilers and package managers need
/// (Landlock ABI 2 and later; below, every move between directories is
/// refused). A move or link out of a read-only tree is refused, and so is
/// one that would give the file a right it lacks where it is (into an
/// executable directory).
#[test]
fn r04_files_move_between_writable_directories_and_gain_no_right() {
    let d = scratch("r04-move");
    for sub in ["ws/a", "ws/b", "ws/bin", "ro"] {
        std::fs::create_dir_all(d.join(sub)).unwrap();
    }
    std::fs::write(d.join("ro/f"), "read-only").unwrap();
    for tier in tiers() {
        for f in ["a/x", "a/y", "b/x", "b/y", "b/t", "bin/y", "f", "g"] {
            let _ = std::fs::remove_file(d.join("ws").join(f));
        }
        let mut p = policy();
        p.fs.push(rule(Access::Read, d.join("ro")));
        p.fs.push(rule(Access::Write, d.join("ws")));
        p.fs.push(rule(Access::Exec, d.join("ws/bin")));
        p.grants.push(Grant {
            name: GrantName::new("tmpdir").unwrap(),
            access: Access::Write,
        });
        let c = cage(&for_tier(p, tier), tier);
        let w = d.join("ws");
        let (w, r) = (w.display(), d.join("ro"));
        let r = r.display();
        let got = run_in(
            &c,
            &format!(
                "write:{w}/a/x;write:{w}/a/y;rename:{w}/a/x|{w}/b/x;link:{w}/a/y|{w}/b/y;\
                 tmpdir-move:{w}/b/t;rename:{w}/a/y|{w}/bin/y;rename:{r}/f|{w}/f;link:{r}/f|{w}/g"
            ),
            &Grants::new(),
        );
        let parts: Vec<&str> = got.split(' ').collect();
        let moved = if abi() >= 2 {
            "ok".to_string()
        } else {
            EXDEV.to_string()
        };
        let moved = moved.as_str();
        assert_eq!(
            parts[..5],
            ["ok", "ok", moved, moved, moved],
            "{tier}: {got}"
        );
        // A right gained (or, below ABI 2, any move between directories).
        assert_eq!(parts[5], EXDEV.to_string(), "{tier}: {got}");
        assert!(
            parts[6..].iter().all(|p| *p != "ok"),
            "{tier}: moved out of a read-only tree ({got})"
        );
        assert_eq!(
            std::fs::read_to_string(d.join("ro/f")).unwrap(),
            "read-only"
        );
    }
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

/// The findings of a spawn the link check refused.
fn link_refusal(cage: &Cage) -> Vec<procage::LinkFinding> {
    match cage.spawn(&mut child_command("read:/dev/null"), &Grants::new()) {
        Err(SpawnError::HardLinks(found)) => found,
        Err(e) => panic!("another error: {e}"),
        Ok(_) => panic!("the spawn was not refused"),
    }
}

/// Options for `tier` that accept the spawn-snapshot approximations (hiding
/// inside a readable tree on T2).
fn snapshot_options(tier: Tier) -> CageOptions {
    let options = options(tier);
    let lower = options.lower.clone().accept_spawn_snapshot();
    options.with_lower(lower)
}

/// A hard link made before the run gives a hidden file a second name: the
/// spawn is refused on every tier, naming the hidden file; in report mode the
/// run starts and the audit lists it.
#[test]
fn r08_a_hard_link_to_a_hidden_file_is_refused() {
    let d = scratch("r08");
    std::fs::create_dir_all(d.join("secret")).unwrap();
    std::fs::create_dir_all(d.join("ws")).unwrap();
    std::fs::write(d.join("secret/key"), "key").unwrap();
    std::fs::hard_link(d.join("secret/key"), d.join("ws/key")).unwrap();
    for tier in tiers() {
        let mut p = policy();
        p.fs.push(rule(Access::Read, &d));
        p.fs.push(rule(Access::Hide, d.join("secret")));
        let cage = Cage::with_options(&p, &snapshot_options(tier))
            .unwrap_or_else(|e| panic!("{tier}: {e}"));
        let found = link_refusal(&cage);
        assert_eq!(found.len(), 1, "{tier} {found:?}");
        assert_eq!(found[0].path, d.join("secret/key"), "{tier}");
        let report = Cage::with_options(
            &p,
            &snapshot_options(tier).with_link_audit(procage::LinkAudit::Report),
        )
        .unwrap();
        let mut child = report
            .spawn(&mut child_command("read:/dev/null"), &Grants::new())
            .unwrap();
        child.wait().unwrap();
        assert_eq!(child.audit().unwrap().links.len(), 1, "{tier}");
    }
    // A literal target that became a symbolic link refuses the spawn too.
    std::fs::remove_file(d.join("ws/key")).unwrap();
    std::fs::write(d.join("ws/.env"), "x").unwrap();
    for tier in tiers() {
        let mut p = policy();
        p.fs.push(rule(Access::Read, &d));
        p.fs.push(FsRule::new(
            Access::Hide,
            FsTarget::Literal(abs(d.join("ws/.env"))),
        ));
        let cage = Cage::with_options(&p, &snapshot_options(tier))
            .unwrap_or_else(|e| panic!("{tier}: {e}"));
        assert_eq!(
            run_in(&cage, "read:/dev/null", &Grants::new()),
            "ok",
            "{tier}: the control"
        );
        std::fs::remove_file(d.join("ws/.env")).unwrap();
        std::os::unix::fs::symlink(d.join("secret/key"), d.join("ws/.env")).unwrap();
        let found = link_refusal(&cage);
        assert!(found[0].symbolic, "{tier} {found:?}");
        std::fs::remove_file(d.join("ws/.env")).unwrap();
        std::fs::write(d.join("ws/.env"), "x").unwrap();
    }
}

/// A protected file with a second name in the writable tree refuses the
/// spawn on T1 (T2 cannot protect inside a writable tree).
#[test]
fn r08_a_hard_link_to_a_protected_file_is_refused() {
    if !t1("r08_a_hard_link_to_a_protected_file_is_refused") {
        return;
    }
    let d = scratch("r08-protect");
    std::fs::create_dir_all(d.join("ws/keep")).unwrap();
    std::fs::write(d.join("ws/keep/config"), "x").unwrap();
    let mut p = policy();
    p.fs.push(rule(Access::Write, d.join("ws")));
    p.fs.push(rule(Access::Protect, d.join("ws/keep")));
    let p = for_tier(p, Tier::T1);
    let cage = Cage::with_options(&p, &snapshot_options(Tier::T1)).unwrap();
    assert_eq!(
        run_in(&cage, "read:/dev/null", &Grants::new()),
        "ok",
        "the control"
    );
    std::fs::hard_link(d.join("ws/keep/config"), d.join("ws/notes")).unwrap();
    let found = link_refusal(&cage);
    assert_eq!(found[0].path, d.join("ws/keep/config"));
}

/// No second name can be made during the run for a hidden or protected file:
/// Landlock grants linking across directories only between writable trees,
/// and on T1 a protected path is a separate mount.
#[test]
fn r08_no_hard_link_can_be_made_during_the_run() {
    let d = scratch("r08-run");
    std::fs::create_dir_all(d.join("secret")).unwrap();
    std::fs::create_dir_all(d.join("ws/keep")).unwrap();
    std::fs::write(d.join("secret/key"), "key").unwrap();
    std::fs::write(d.join("ws/keep/config"), "x").unwrap();
    std::fs::create_dir_all(d.join("keep")).unwrap();
    std::fs::write(d.join("keep/config"), "x").unwrap();
    for tier in tiers() {
        let mut p = policy();
        p.fs.push(rule(Access::Read, &d));
        p.fs.push(rule(Access::Write, d.join("ws")));
        p.fs.push(rule(Access::Hide, d.join("secret")));
        if tier == Tier::T1 {
            // Protecting inside a writable tree needs a mount (T1 only).
            p.fs.push(rule(Access::Protect, d.join("ws/keep")));
        }
        // T2 cannot protect; a file in a read-only tree beside the writable
        // one stands in (Landlock refuses linking across directories).
        let p = for_tier(p, tier);
        let cage = Cage::with_options(&p, &snapshot_options(tier))
            .unwrap_or_else(|e| panic!("{tier}: {e}"));
        let attempt = format!(
            "link:{0}/secret/key|{0}/ws/a;link:{1}|{0}/ws/b;write:{0}/ws/c",
            d.display(),
            if tier == Tier::T1 {
                d.join("ws/keep/config")
            } else {
                d.join("keep/config")
            }
            .display()
        );
        let got = run_in(&cage, &attempt, &Grants::new());
        let parts: Vec<&str> = got.split(' ').collect();
        assert_ne!(parts[0], "ok", "{tier}: a hidden file was linked ({got})");
        assert_ne!(
            parts[1], "ok",
            "{tier}: a protected file was linked ({got})"
        );
        assert_eq!(parts[2], "ok", "{tier}: the control ({got})");
    }
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
        let mut p = net_on(p);
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
/// Below Landlock ABI 9, on T1 a daemon socket elsewhere (masked at spawn),
/// a host abstract socket (another network namespace) and TCP stay out, and
/// the setting needs the snapshot accepted; T2 refuses it. From ABI 9
/// Landlock keeps the daemon socket out on both tiers, exactly.
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
    // A socket path per tier: the one a tier binds stays behind.
    let attempt = |tier: Tier| {
        format!(
            "unix-serve:{};unix:{};abstract:{name};connect:{port}",
            ws.join(format!("s-{tier}.sock")).display(),
            sock.display()
        )
    };
    let abi = abi();
    for tier in tiers() {
        let mut p = policy();
        p.fs.push(rule(Access::Read, &d));
        p.fs.push(rule(Access::Write, &ws));
        p.ipc.unix_sockets = vec![abs(&ws)];
        if abi >= 9 {
            let got = run_in(
                &cage(&for_tier(p, tier), tier),
                &attempt(tier),
                &Grants::new(),
            );
            let abstract_out = if tier == Tier::T1 {
                ECONNREFUSED
            } else {
                EPERM
            };
            assert_eq!(
                got,
                format!("ok {EACCES} {abstract_out} {EPERM}"),
                "{tier} ABI {abi}"
            );
            continue;
        }
        let gaps = refused(&p, &options(tier));
        assert!(
            gaps.iter().any(|g| g.0 == Construct::IpcUnixSockets),
            "{tier} {gaps:?}"
        );
        if tier == Tier::T2 {
            continue;
        }
        let snapshot = CageOptions::default()
            .with_tier(tier)
            .with_lower(LowerOptions::default().accept_spawn_snapshot());
        let cage = Cage::with_options(&p, &snapshot).unwrap();
        let got = run_in(&cage, &attempt(tier), &Grants::new());
        assert_eq!(
            got,
            format!("ok {ECONNREFUSED} {ECONNREFUSED} {EPERM}"),
            "{tier}"
        );
    }
}

/// With the network off, a UDP socket the caller hands over cannot send
/// from Landlock ABI 10; below it, it can (a documented limit).
#[test]
fn r09_a_handed_udp_socket_cannot_send_with_the_network_off() {
    let target = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let port = target.local_addr().unwrap().port();
    let sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let action = format!("udp-fd:{}|{port}", sock.as_raw_fd());
    let abi = abi();
    for tier in tiers() {
        let c = cage(&policy(), tier);
        let child = c
            .spawn_with_fds(&mut child_command(&action), &Grants::new(), &[sock.as_fd()])
            .unwrap();
        let got = result(&finish(child, Duration::from_secs(20)));
        let want = if abi >= 10 {
            EACCES.to_string()
        } else {
            "ok".into()
        };
        assert_eq!(got, want, "{tier} ABI {abi}");
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
        // A descriptor as std opens it (close-on-exec) is handed over too.
        let fresh = std::fs::File::open(d.join("secret")).unwrap();
        let action = format!("fd:{}", fresh.as_raw_fd());
        let child = c
            .spawn_with_fds(
                &mut child_command(&action),
                &Grants::new(),
                &[fresh.as_fd()],
            )
            .unwrap();
        let handed = result(&finish(child, Duration::from_secs(20)));
        assert_eq!(handed, "open=true", "{tier}");
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

/// Runs `action` in a child of `policy` with a new terminal on `tier` (its
/// standard streams are the terminal); returns the result and everything
/// the controller side read.
fn in_terminal(action: &str, policy: &Policy, tier: Tier) -> (String, String) {
    let mut p = policy.clone();
    p.tty = Tty::NewPty;
    let mut child = cage(&p, tier)
        .spawn(&mut child_command(action), &Grants::new())
        .unwrap_or_else(|e| panic!("{tier} spawn: {e}"));
    let mut pty = child.take_pty().expect("a terminal");
    let reader = std::thread::spawn(move || {
        let mut out = Vec::new();
        // The read ends with end of file or EIO once the run is over.
        let _ = pty.read_to_end(&mut out);
        String::from_utf8_lossy(&out).into_owned()
    });
    let start = Instant::now();
    while child.try_wait().unwrap().is_none() {
        assert!(
            start.elapsed() < Duration::from_secs(20),
            "{tier}: child hung"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
    drop(child);
    let text = reader.join().unwrap();
    let result = text
        .lines()
        .find_map(|l| {
            l.split_once("procage-result: ")
                .map(|(_, r)| r.trim_end().to_string())
        })
        .unwrap_or_else(|| panic!("{tier}: no result in {text:?}"));
    (result, text)
}

/// With a new terminal (`Tty::NewPty`) the child pushes no input into its
/// own terminal either, and reaches no other terminal. Waived by name, the
/// pushed byte lands in the run's own terminal (echoed to its controller),
/// and another terminal stays out of reach.
#[test]
fn r22_a_new_terminal_keeps_input_injection_inside_the_run() {
    let (_other_controller, other) = testing::open_pty().unwrap();
    let other = format!("tiocsti:{}", other.display());
    for tier in tiers() {
        let p = for_tier(policy(), tier);
        assert_eq!(
            in_terminal("tiocsti-own", &p, tier).0,
            EPERM.to_string(),
            "{tier}"
        );
        let open = in_terminal(&other, &p, tier).0;
        assert!(open.starts_with("open-"), "{tier}: {open}");
        let w = waived(p, &[HardDenyClass::TerminalInjection]);
        let (own, text) = in_terminal("tiocsti-own", &w, tier);
        println!("{tier}: waived, own terminal: {own}");
        // Since Linux 6.2 TIOCSTI needs CAP_SYS_ADMIN unless the
        // `dev.tty.legacy_tiocsti` sysctl allows it.
        if own == "ok" {
            assert!(text.contains('#'), "{tier}: {text:?}");
        }
        let open = in_terminal(&other, &w, tier).0;
        assert!(open.starts_with("open-"), "{tier}: {open}");
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

/// By default no process of the run can start a session; it can start a
/// process group, which stays in the child's session.
#[test]
fn r23_sessions_are_locked() {
    for tier in tiers() {
        let mut p = policy();
        p.process.fork = true;
        let (child, got) = start(&cage(&p, tier), "sessions");
        drop(child);
        assert_eq!(got, format!("{EPERM} ok"), "{tier}");
    }
}

/// A descendant in a process group of its own (as test runners start each
/// test), reparented away from the child, is outside the child's group and
/// tree but not its session: it dies with the run.
#[test]
fn r23_a_descendant_in_a_group_of_its_own_dies_with_the_run() {
    for tier in tiers() {
        let mut p = policy();
        p.process.fork = true;
        let (child, pid) = start(&cage(&p, tier), "group-double-fork");
        let pid: u32 = pid
            .parse()
            .unwrap_or_else(|_| panic!("{tier}: no group: {pid}"));
        assert!(testing::alive(pid), "{tier}");
        drop(child);
        assert_dies(pid, &format!("{tier}: descendant"));
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
        // Reaching other processes' entries is an approximation by name.
        let gaps = refused(&p, &options(tier));
        assert!(
            gaps.contains(&(Construct::ProcOtherProcesses, GapKind::Approximation)),
            "{tier}: {gaps:?}"
        );
        let accepted = options(tier);
        let lower = accepted.lower.clone().allow(Construct::ProcOtherProcesses);
        let cage = Cage::with_options(&p, &accepted.with_lower(lower)).unwrap();
        assert!(
            cage.plan()
                .degradations
                .iter()
                .any(|d| d.construct == Construct::ProcOtherProcesses),
            "{tier}: listed in the plan"
        );
        let got = run_in(
            &cage,
            "parent:environ;read:/proc/self/environ;parent:cmdline",
            &Grants::new(),
        );
        println!("{tier}: with /proc readable: {got}");
        let r: Vec<&str> = got.split(' ').collect();
        // The residual the approximation names: arguments readable, the
        // environment not.
        assert_eq!(
            r,
            [EACCES.to_string().as_str(), "ok", "ok"],
            "{tier}: {got}"
        );
    }
}

/// `/proc` reached through a symbolic link in a rule, or through a grant
/// bound at spawn, is the same approximation as a rule on `/proc`: refused
/// unless accepted by name, then listed in the plan or the run's receipt.
#[test]
fn r25_proc_through_a_link_or_a_grant_is_an_approximation() {
    let dir = scratch("r25-link");
    let link = dir.join("proc");
    std::os::unix::fs::symlink("/proc", &link).unwrap();
    let accept = |tier| {
        let o = options(tier);
        let lower = o.lower.clone().allow(Construct::ProcOtherProcesses);
        o.with_lower(lower)
    };
    for tier in tiers() {
        let mut p = policy();
        p.fs.push(rule(Access::Read, &link));
        let gaps = refused(&p, &options(tier));
        assert_eq!(
            gaps,
            [(Construct::ProcOtherProcesses, GapKind::Approximation)],
            "{tier}"
        );
        let cage = Cage::with_options(&p, &accept(tier)).unwrap();
        assert!(
            cage.plan()
                .degradations
                .iter()
                .any(|d| d.construct == Construct::ProcOtherProcesses),
            "{tier}: listed in the plan"
        );

        let mut p = policy();
        p.grants.push(Grant {
            name: GrantName::new("procs").unwrap(),
            access: Access::Read,
        });
        let grants = Grants::new().bind("procs", &link);
        let cage = Cage::with_options(&p, &options(tier)).unwrap();
        match cage.spawn(&mut child_command("read:/proc/self/environ"), &grants) {
            Err(SpawnError::Lower(LowerError::Gaps(gaps))) => assert!(
                gaps.iter()
                    .all(|g| g.construct == Construct::ProcOtherProcesses),
                "{tier}: {gaps:?}"
            ),
            other => panic!("{tier}: the grant was bound: {:?}", other.map(|_| ())),
        }
        let cage = Cage::with_options(&p, &accept(tier)).unwrap();
        assert!(
            !cage
                .plan()
                .degradations
                .iter()
                .any(|d| d.construct == Construct::ProcOtherProcesses),
            "{tier}: nothing approximated before a grant is bound"
        );
        let mut child = cage
            .spawn(&mut child_command("read:/proc/self/environ"), &grants)
            .unwrap();
        child.wait().unwrap();
        let receipt = child.receipt().unwrap();
        assert!(
            receipt
                .approximations
                .iter()
                .any(|a| a.construct == Construct::ProcOtherProcesses),
            "{tier}: listed in the receipt"
        );
        assert!(!receipt.enforced_as_written, "{tier}");
    }
}

// ---- R-26 Helper replacement ----

/// procage installs no helper program; this canary attacks one once it
/// does.
#[test]
#[ignore = "open: R-26 procage installs no helper"]
fn r26_the_helper_cannot_be_replaced() {
    panic!("open: R-26: procage installs no helper");
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
        // A cap never raises the kernel's ABI.
        for abi in [1, 2, 3].into_iter().filter(|a| *a <= abi()) {
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
/// it, from its directory or another, nor written. A rule on a path that does not exist fails before any
/// child runs. On T2 protect is refused.
#[test]
fn r30_a_protected_file_cannot_be_replaced() {
    let w = scratch("r30");
    std::fs::create_dir_all(w.join("sub")).unwrap();
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
            &format!(
                "write:{d}/tmp;rename:{d}/tmp|{d}/f;write:{d}/f;write:{d}/sub/tmp;rename:{d}/sub/tmp|{d}/f"
            ),
            &p,
            Tier::T1,
        );
        let across = if abi() >= 2 { EBUSY } else { EXDEV };
        assert_eq!(got, format!("ok {EBUSY} {EROFS} ok {across}"));
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

// ---- R-32 Seccomp listener hijack ----

/// With violation reporting, no process of the run holds the seccomp
/// listener, and reopening the parent's through `/proc` (granted here) is
/// refused by the kernel: caged code cannot answer its own refused calls.
#[test]
fn r32_the_seccomp_listener_stays_out_of_reach() {
    for tier in tiers() {
        let mut p = policy();
        p.fs.push(rule(Access::Read, "/proc"));
        // Granting `/proc` reaches other processes: accepted by name here.
        let options = options(tier).with_violations();
        let lower = options.lower.clone().allow(Construct::ProcOtherProcesses);
        let c = Cage::with_options(&p, &options.with_lower(lower))
            .unwrap_or_else(|e| panic!("{tier}: {e}"));
        let mut child = c
            .spawn(
                &mut child_command(&format!("listeners:{}", std::process::id())),
                &Grants::new(),
            )
            .unwrap();
        let mut out = String::new();
        std::io::Read::read_to_string(child.stdout.as_mut().unwrap(), &mut out).unwrap();
        child.wait().unwrap();
        let line = first_result(out.as_bytes()).unwrap_or_else(|| panic!("{tier}: {out}"));
        assert!(line.starts_with("own=0 "), "{tier}: {line}");
        assert!(line.ends_with(" reopened=0"), "{tier}: {line}");
        assert_eq!(
            child.violations().coverage(),
            &procage::Coverage::SystemCalls
        );
    }
}

// ---- R-33 Setup that follows a planted link ----

/// What replaces a planned path between the plan and the child's mounts.
#[derive(Clone, Copy, Debug)]
enum Plant {
    /// A symbolic link to the decoy.
    Link,
    /// The decoy directory itself, renamed into place.
    Dir,
}

fn moved(p: &Path) -> PathBuf {
    let mut s = p.as_os_str().to_owned();
    s.push(".moved");
    PathBuf::from(s)
}

/// Spawns `action` under `cage`. In the child, before the cage's own steps
/// (the window between the parent's plan and the mounts), a hook renames
/// `planned` to `<planned>.moved` and puts `plant` of `decoy` in its place,
/// as another process with write access could.
fn planted(
    cage: &Cage,
    action: &str,
    planned: &Path,
    decoy: &Path,
    plant: Plant,
) -> Result<String, SpawnError> {
    let mut cmd = child_command(action);
    testing::plant_before_spawn(
        &mut cmd,
        planned,
        &moved(planned),
        decoy,
        matches!(plant, Plant::Link),
    )
    .unwrap();
    let child = cage.spawn(&mut cmd, &Grants::new())?;
    Ok(result(&finish(child, Duration::from_secs(20))))
}

/// The refusal a moved mount must get: the spawn fails, naming a planned
/// path at or under `planned`. Returns what went wrong otherwise.
fn moved_refusal(plant: Plant, planned: &Path, got: &Result<String, SpawnError>) -> Option<String> {
    match got {
        Err(SpawnError::MountMoved { path, link }) => {
            let link_ok = match plant {
                Plant::Link => link.as_deref() == Some(planned),
                Plant::Dir => link.is_none(),
            };
            (!path.starts_with(planned) || !link_ok).then(|| format!("named {path:?} {link:?}"))
        }
        other => Some(format!("{other:?}")),
    }
}

/// On T1 each kind of mount, with its planned path replaced by a link or by
/// another directory after the plan, fails the spawn: the protected,
/// hidden or covered object never stays reachable under its moved name,
/// and the decoy is not covered.
#[test]
fn r33_a_planted_link_or_directory_cannot_move_a_mount() {
    if !t1("r33") {
        return;
    }
    let mut wrong = Vec::new();
    for plant in [Plant::Link, Plant::Dir] {
        let w = scratch(&format!("r33-{plant:?}"));
        let ws = w.join("ws");
        for dir in [
            "p",
            "pdecoy",
            "h",
            "hdecoy",
            "f",
            "fdecoy",
            ".git/hooks",
            "gdecoy/hooks",
            "sub/.vscode",
            "sub/vdecoy",
        ] {
            std::fs::create_dir_all(ws.join(dir)).unwrap();
        }
        std::fs::write(ws.join("p/c"), "original").unwrap();
        std::fs::write(ws.join("h/secret"), "secret").unwrap();
        std::fs::write(ws.join("f/secret"), "secret").unwrap();
        std::fs::write(ws.join("fdecoy/secret"), "decoy").unwrap();
        let d = ws.display();
        let mut base = policy();
        base.fs.push(rule(Access::Write, &ws));
        let cases: [(&str, Policy, &str, &str, String); 5] = [
            (
                "protect",
                {
                    let mut p = base.clone();
                    p.fs.push(rule(Access::Protect, ws.join("p")));
                    p
                },
                "p",
                "pdecoy",
                format!("write:{d}/p.moved/c"),
            ),
            (
                "hide-dir",
                {
                    let mut p = base.clone();
                    p.fs.push(rule(Access::Hide, ws.join("h")));
                    p
                },
                "h",
                "hdecoy",
                format!("read:{d}/h.moved/secret"),
            ),
            (
                "hide-file",
                {
                    let mut p = base.clone();
                    p.fs.push(FsRule::new(
                        Access::Hide,
                        FsTarget::Literal(abs(ws.join("f/secret"))),
                    ));
                    p
                },
                "f",
                "fdecoy",
                format!("read:{d}/f.moved/secret"),
            ),
            (
                "cover-and-pin",
                base.clone(),
                ".git",
                "gdecoy",
                format!("write:{d}/.git.moved/hooks/x"),
            ),
            (
                "cover",
                base.clone(),
                "sub/.vscode",
                "sub/vdecoy",
                format!("write:{d}/sub/.vscode.moved/x"),
            ),
        ];
        for (kind, p, planned, decoy, action) in cases {
            let cage = cage(&p, Tier::T1);
            let got = planted(&cage, &action, &ws.join(planned), &ws.join(decoy), plant);
            println!("r33 {kind} {plant:?}: {got:?}");
            if let Some(w) = moved_refusal(plant, &ws.join(planned), &got) {
                wrong.push(format!("{kind} {plant:?}: {w}"));
            }
        }
        // A foreign socket's cover (Landlock ABI 9 refuses the connect by
        // itself, so below it the cover is what keeps the socket out).
        let s = w.join("s");
        std::fs::create_dir_all(&s).unwrap();
        std::fs::create_dir_all(w.join("sdecoy")).unwrap();
        let sock = s.join("daemon.sock");
        let _daemon = std::os::unix::net::UnixListener::bind(&sock).unwrap();
        let mut p = policy();
        p.fs.push(rule(Access::Read, &w));
        p.fs.push(rule(Access::Write, &ws));
        p.ipc.unix_sockets = vec![abs(&ws)];
        let snapshot = CageOptions::default()
            .with_tier(Tier::T1)
            .with_lower(LowerOptions::default().accept_spawn_snapshot());
        let cage = Cage::with_options(&for_tier(p, Tier::T1), &snapshot).unwrap();
        let action = format!("unix:{}", moved(&s).join("daemon.sock").display());
        let got = planted(&cage, &action, &s, &w.join("sdecoy"), plant);
        println!("r33 socket-cover {plant:?}: {got:?}");
        // Where Landlock refuses pathname connects itself (ABI 9 and later)
        // or the plan needs no cover, there is no cover to move: the
        // socket must stay out of reach either way.
        let refused_connect = matches!(&got, Ok(r) if r != "ok");
        if !refused_connect && let Some(w) = moved_refusal(plant, &s, &got) {
            wrong.push(format!("socket-cover {plant:?}: {w}"));
        }
    }
    assert!(wrong.is_empty(), "moved mounts not refused: {wrong:#?}");
}

/// A concurrent writer in the shared tree swaps the protected directory for
/// a symbolic link to a decoy during spawns (`PROCAGE_RACE_ATTEMPTS`,
/// default 1,000). The protected file (held by an fd opened before the
/// race, so renames cannot fool the check) keeps its contents: the cage
/// found the object when it was made and mounts only that, or refuses.
#[test]
fn r33_racing_a_planted_link_never_moves_a_mount() {
    use std::io::{Read, Seek};
    use std::sync::atomic::{AtomicBool, Ordering};
    if !t1("r33-race") {
        return;
    }
    let attempts: usize = std::env::var("PROCAGE_RACE_ATTEMPTS")
        .ok()
        .and_then(|n| n.parse().ok())
        .unwrap_or(1_000);
    let w = scratch("r33-race");
    let (p_dir, real, decoy) = (w.join("p"), w.join("p.moved"), w.join("decoy"));
    std::fs::create_dir_all(&p_dir).unwrap();
    std::fs::create_dir_all(&decoy).unwrap();
    std::fs::write(p_dir.join("c"), "original").unwrap();
    // A handle to the protected file itself: it follows the inode across
    // every rename, so reading it is immune to the swap the checker races.
    let mut guard = std::fs::File::open(p_dir.join("c")).unwrap();
    let mut p = policy();
    p.fs.push(rule(Access::Write, &w));
    p.fs.push(rule(Access::Protect, &p_dir));
    let cage = cage(&p, Tier::T1);
    let stop = std::sync::Arc::new(AtomicBool::new(false));
    let swapper = {
        let (stop, p_dir, real, decoy) = (stop.clone(), p_dir.clone(), real.clone(), decoy.clone());
        std::thread::spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                let _ = std::fs::rename(&p_dir, &real);
                let _ = std::os::unix::fs::symlink(&decoy, &p_dir);
                std::thread::yield_now();
                let _ = std::fs::remove_file(&p_dir);
                let _ = std::fs::rename(&real, &p_dir);
                std::thread::yield_now();
            }
        })
    };
    // The child writes the protected path and its renamed-away name; both
    // must leave the protected file untouched.
    let action = format!("write:{}/c;write:{}/c", p_dir.display(), real.display());
    let (mut ran, mut refused) = (0, 0);
    for _ in 0..attempts {
        match cage.spawn(&mut child_command(&action), &Grants::new()) {
            Ok(child) => {
                let _ = finish(child, Duration::from_secs(20));
                ran += 1;
            }
            Err(_) => refused += 1,
        }
    }
    stop.store(true, Ordering::Relaxed);
    swapper.join().unwrap();
    let mut content = String::new();
    guard.rewind().unwrap();
    guard.read_to_string(&mut content).unwrap();
    println!(
        "r33 race: {attempts} attempts, {ran} ran, {refused} refused, protected file {content:?}"
    );
    assert_eq!(
        content, "original",
        "a racing swap exposed the protected file"
    );
    assert!(ran > 0, "no spawn ran: the race left no window to test");
}

// ---- R-34 Service handoff over Unix sockets ----

/// A scratch runtime directory with the given sockets bound, and the
/// listeners that keep them alive.
fn runtime_with(name: &str, sockets: &[&str]) -> (Scratch, Vec<std::os::unix::net::UnixListener>) {
    let d = scratch(name);
    let listeners = sockets
        .iter()
        .map(|rel| {
            let path = d.join(rel);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::os::unix::net::UnixListener::bind(&path).unwrap()
        })
        .collect();
    (d, listeners)
}

/// Options for `tier` that search `runtime` and accept the spawn snapshot.
fn socket_options(tier: Tier, runtime: &Path, snapshot: bool) -> CageOptions {
    let lower = if snapshot {
        LowerOptions::default().accept_spawn_snapshot()
    } else {
        LowerOptions::default()
    };
    let options = options(tier).with_runtime_dir(runtime);
    let lower = options
        .lower
        .allow_degrade
        .iter()
        .fold(lower, |l, c| l.allow(*c));
    options.with_lower(lower)
}

/// Beside a host's own buses or service managers (a GitHub runner has the
/// system bus, systemd's socket and the runner user's bus; a container
/// usually has none), a T2 cage with `service-handoff` in force and the
/// network on cannot exist. Returns `true` when `p` is refused for that
/// reason alone, asserting that every gap is that class naming a socket
/// outside the test's scratch directories, so the canary's T2 part, which
/// needs such a cage, runs only on hosts without them.
fn refused_beside_the_host_bus(p: &Policy, opts: &CageOptions, canary: &str) -> bool {
    let gaps = match Cage::with_options(p, opts) {
        Ok(_) => return false,
        Err(SpawnError::Lower(LowerError::Gaps(gaps))) => gaps,
        Err(e) => panic!("{canary}: {e}"),
    };
    let scratch = std::env::temp_dir();
    for g in &gaps {
        assert!(
            g.construct == Construct::HdServiceHandoff
                && g.kind == GapKind::Unsupported
                && g.subject
                    .as_deref()
                    .is_some_and(|s| !Path::new(s).starts_with(&scratch)),
            "{canary}: refused for more than the host's buses: {gaps:?}"
        );
    }
    println!("{canary}: T2 refused beside the host's buses; its T2 part needs a host without them");
    true
}

fn refused_one(r: &str) -> bool {
    [EPERM, EACCES, ECONNREFUSED]
        .iter()
        .any(|e| r == e.to_string())
}

/// With the network on, the child reaches neither the user bus nor the
/// service manager nor a container engine: T1 covers them (an approximation
/// the caller accepts), T2 refuses the cage and names each socket. Waiving
/// the class lets the same connect through; a project's own socket in the
/// workspace stays reachable throughout.
#[test]
fn r34_service_and_engine_sockets_are_unreachable() {
    // Below ABI 6 the abstract bus another canary binds would make every
    // cage here a gap.
    let _turn = ABSTRACT.lock().unwrap_or_else(|e| e.into_inner());
    let cases: [(&[&str], HardDenyClass); 2] = [
        (&["bus", "systemd/private"], HardDenyClass::ServiceHandoff),
        (
            &["docker.sock", "podman/podman.sock"],
            HardDenyClass::ContainerEngines,
        ),
    ];
    for (sockets, class) in cases {
        let (d, _listeners) = runtime_with(&format!("r34-{class}"), sockets);
        let ws = d.join("ws");
        std::fs::create_dir_all(&ws).unwrap();
        let _app = std::os::unix::net::UnixListener::bind(ws.join("app.sock")).unwrap();
        std::os::unix::fs::symlink(d.join(sockets[0]), ws.join("link.sock")).unwrap();
        // Each listed socket, the first one through a link in the workspace,
        // a hard link to it (never possible: the cover hides the name on T1,
        // and Landlock never grants linking across directories), and the
        // project's own socket last.
        let attempt: Vec<String> = sockets
            .iter()
            .map(|rel| format!("unix:{}", d.join(rel).display()))
            .chain([
                format!("unix:{}", ws.join("link.sock").display()),
                format!(
                    "link:{}|{}",
                    d.join(sockets[0]).display(),
                    ws.join("hard.sock").display()
                ),
                format!("unix:{}", ws.join("app.sock").display()),
            ])
            .collect();
        let attempt = attempt.join(";");
        let construct = Construct::of_class(class);
        for tier in tiers() {
            let mut p = policy();
            p.net = Network::All;
            p.fs.push(rule(Access::Read, &d));
            p.fs.push(rule(Access::Write, &ws));
            let p = for_tier(p, tier);
            let other = SOCKET_CLASSES
                .into_iter()
                .filter(|c| *c != class)
                .collect::<Vec<_>>();
            let p = waived(p, &other);
            // Without accepting the snapshot (T1) or at all (T2): refused,
            // naming each socket.
            let plain = socket_options(tier, &d, false);
            let gaps = match Cage::with_options(&p, &plain) {
                Err(SpawnError::Lower(LowerError::Gaps(gaps))) => gaps,
                other => panic!("{tier} {class}: {:?}", other.map(|_| ())),
            };
            let kind = if tier == Tier::T1 {
                GapKind::Approximation
            } else {
                GapKind::Unsupported
            };
            for rel in sockets {
                let path = d.join(rel).display().to_string();
                assert!(
                    gaps.iter().any(|g| g.construct == construct
                        && g.kind == kind
                        && g.subject.as_deref() == Some(path.as_str())),
                    "{tier} {class}: {path} not named in {gaps:?}"
                );
            }
            if tier == Tier::T1 {
                let cage = Cage::with_options(&p, &socket_options(tier, &d, true)).unwrap();
                assert!(
                    cage.plan()
                        .degradations
                        .iter()
                        .any(|g| g.construct == construct),
                    "{class}: the approximation is recorded"
                );
                let got = run_in(&cage, &attempt, &Grants::new());
                let parts: Vec<&str> = got.split(' ').collect();
                assert_eq!(parts.len(), sockets.len() + 3, "{got}");
                for (what, r) in sockets.iter().chain(&["the link"]).zip(&parts) {
                    assert!(refused_one(r), "T1 {class}: {what} gave {r} ({got})");
                }
                assert_ne!(
                    parts[sockets.len() + 1],
                    "ok",
                    "T1: a hard link was made ({got})"
                );
                assert_eq!(
                    parts[sockets.len() + 2],
                    "ok",
                    "T1: the project socket ({got})"
                );
            }
            // The positive control: the class waived. Everything connects;
            // the hard link stays refused by Landlock.
            let open = waived(p.clone(), &[class]);
            let cage = Cage::with_options(&open, &socket_options(tier, &d, true)).unwrap();
            let got = run_in(&cage, &attempt, &Grants::new());
            for (i, r) in got.split(' ').enumerate() {
                if i == sockets.len() + 1 {
                    assert_ne!(r, "ok", "{tier}: a hard link across directories ({got})");
                } else {
                    assert_eq!(r, "ok", "{tier} {class} waived: {got}");
                }
            }
        }
    }
}

/// `fit` relaxes a socket class by name on tier T2.
#[test]
fn r34_fit_waives_by_name() {
    let (d, _listeners) = runtime_with("r34-fit", &["bus"]);
    let mut p = policy();
    p.net = Network::All;
    p.waive.insert(HardDenyClass::ContainerEngines);
    let opts = socket_options(Tier::T2, &d, false);
    let relax = procage::policy::Relax::new().waive(HardDenyClass::ServiceHandoff);
    let (cage, relaxed) = Cage::fit(&p, &opts, &relax).unwrap();
    let bus = relaxed
        .iter()
        .find(|r| r.gap.construct == Construct::HdServiceHandoff)
        .unwrap_or_else(|| panic!("{relaxed:?}"));
    assert!(bus.lift.tier1, "tier T1 lifts it: {bus}");
    assert_eq!(bus.lift.landlock_abi, None, "no ABI lifts it: {bus}");
    let got = run_in(
        &cage,
        &format!("unix:{}", d.join("bus").display()),
        &Grants::new(),
    );
    assert_eq!(got, "ok", "the relaxed cage reaches the bus");
}

/// With `Network::Ip` the child reaches IP addresses and no Unix socket:
/// neither the bus nor the engine nor an abstract bus, on either tier and
/// without a cover, so a T2 cage with the network on exists beside them.
#[test]
fn r34_the_ip_network_keeps_every_unix_socket_out() {
    let _turn = ABSTRACT.lock().unwrap_or_else(|e| e.into_inner());
    let (d, _listeners) = runtime_with("r34-ip", &["bus", "docker.sock"]);
    let name = format!("/tmp/dbus-procage-r34-ip-{}", std::process::id());
    let _bus = AbstractBus::bind(&name);
    let tcp = TcpListener::bind("127.0.0.1:0").unwrap();
    let udp = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let attempt = format!(
        "connect:{};udp-send:{};listen;resolve:localhost;unix:{};unix:{};abstract:{name}",
        tcp.local_addr().unwrap().port(),
        udp.local_addr().unwrap().port(),
        d.join("bus").display(),
        d.join("docker.sock").display(),
    );
    for tier in tiers() {
        let mut p = for_tier(policy(), tier);
        p.net = Network::Ip;
        let cage = Cage::with_options(&p, &socket_options(tier, &d, false))
            .unwrap_or_else(|e| panic!("{tier}: {e}"));
        assert!(cage.plan().degradations.is_empty(), "{tier}");
        assert_eq!(
            run_in(&cage, &attempt, &Grants::new()),
            format!("ok ok ok ok {EPERM} {EPERM} {EPERM}"),
            "{tier}"
        );
    }
    // With `ipc.unix_sockets`, the project's socket is reachable as with the
    // network off: T1 covers the others, ABI 9 refuses them, T2 below it is
    // a gap, and so is T1 below ABI 6 (no namespace keeps abstract sockets
    // in).
    let ws = d.join("ws");
    std::fs::create_dir_all(&ws).unwrap();
    let _app = std::os::unix::net::UnixListener::bind(ws.join("app.sock")).unwrap();
    let attempt = format!(
        "unix:{};unix:{}",
        ws.join("app.sock").display(),
        d.join("bus").display()
    );
    for tier in tiers() {
        let mut p = for_tier(policy(), tier);
        p.net = Network::Ip;
        p.ipc.unix_sockets.push(abs(&ws));
        let opts = socket_options(tier, &d, true);
        let floor = if tier == Tier::T2 { 9 } else { 6 };
        if probe().landlock_abi < floor {
            let gaps = match Cage::with_options(&p, &opts) {
                Err(SpawnError::Lower(LowerError::Gaps(gaps))) => gaps,
                other => panic!("{tier}: {:?}", other.map(|_| ())),
            };
            assert!(
                gaps.iter()
                    .any(|g| g.construct == Construct::IpcUnixSockets),
                "{gaps:?}"
            );
            continue;
        }
        let cage = Cage::with_options(&p, &opts).unwrap_or_else(|e| panic!("{tier}: {e}"));
        let got = run_in(&cage, &attempt, &Grants::new());
        let (app, bus) = got.split_once(' ').unwrap();
        assert_eq!(app, "ok", "{tier}: {got}");
        assert!(refused_one(bus), "{tier}: {got}");
    }
}

/// `fit` answers the socket classes of a networked policy with
/// `no_unix_sockets` on tier T2: the network becomes `Network::Ip`.
#[test]
fn r34_fit_keeps_unix_sockets_out_of_a_networked_command() {
    use procage::policy::{Relax, Relaxation};
    let (d, _listeners) = runtime_with("r34-fit-ip", &["bus", "docker.sock"]);
    let mut p = policy();
    p.net = Network::All;
    let opts = socket_options(Tier::T2, &d, false);
    assert!(matches!(
        Cage::fit(&p, &opts, &Relax::new()),
        Err(SpawnError::Lower(LowerError::Gaps(_)))
    ));
    let (cage, relaxed) = Cage::fit(&p, &opts, &Relax::new().no_unix_sockets()).unwrap();
    for construct in [Construct::HdServiceHandoff, Construct::HdContainerEngines] {
        let r = relaxed
            .iter()
            .find(|r| r.gap.construct == construct)
            .unwrap_or_else(|| panic!("{construct}: {relaxed:?}"));
        assert_eq!(r.relaxation, Relaxation::NoUnixSockets, "{r}");
        assert!(r.lift.tier1, "tier T1 lifts it: {r}");
    }
    let tcp = TcpListener::bind("127.0.0.1:0").unwrap();
    let got = run_in(
        &cage,
        &format!(
            "connect:{};unix:{};unix:{}",
            tcp.local_addr().unwrap().port(),
            d.join("bus").display(),
            d.join("docker.sock").display()
        ),
        &Grants::new(),
    );
    assert_eq!(got, format!("ok {EPERM} {EPERM}"));
}

/// An abstract bus is out of reach: from Landlock ABI 6 every plan scopes
/// abstract sockets; below it a bus found at spawn refuses the cage, and
/// only waiving the class lets the child reach it.
/// Abstract names are shared by every process of the network namespace:
/// the abstract-bus canaries take turns, so one's bus never refuses the
/// other's cage.
static ABSTRACT: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// An abstract listener that, when dropped, waits until its name has left
/// `/proc/net/unix`: a child another test forks meanwhile holds a copy
/// until its exec, and the next canary must not see the name.
struct AbstractBus {
    listener: Option<std::os::unix::net::UnixListener>,
    name: String,
}

impl AbstractBus {
    fn bind(name: &str) -> AbstractBus {
        use std::os::linux::net::SocketAddrExt;
        let addr = std::os::unix::net::SocketAddr::from_abstract_name(name).unwrap();
        AbstractBus {
            listener: Some(std::os::unix::net::UnixListener::bind_addr(&addr).unwrap()),
            name: name.to_owned(),
        }
    }
}

impl Drop for AbstractBus {
    fn drop(&mut self) {
        drop(self.listener.take());
        let entry = format!(" @{}", self.name);
        let start = Instant::now();
        while start.elapsed() < Duration::from_secs(5)
            && std::fs::read_to_string("/proc/net/unix")
                .is_ok_and(|t| t.lines().any(|l| l.ends_with(&entry)))
        {
            std::thread::sleep(Duration::from_millis(5));
        }
    }
}

#[test]
fn r34_an_abstract_bus_is_scoped() {
    let _turn = ABSTRACT.lock().unwrap_or_else(|e| e.into_inner());
    // Below ABI 6, with no bus, the class adds no scope of its own: an
    // unrelated abstract socket stays reachable.
    let other = format!("procage-r34-unrelated-{}", std::process::id());
    let unrelated = AbstractBus::bind(&other);
    let empty = scratch("r34-abstract-empty");
    for tier in tiers() {
        let mut p = for_tier(policy(), tier);
        p.net = Network::All;
        p.waive.insert(HardDenyClass::ContainerEngines);
        let opts = socket_options(tier, &empty, true).with_landlock_abi(5);
        if tier == Tier::T2
            && refused_beside_the_host_bus(&p, &opts, "r34_an_abstract_bus_is_scoped")
        {
            continue;
        }
        let cage = Cage::with_options(&p, &opts).unwrap_or_else(|e| panic!("{tier}: {e}"));
        let got = run_in(&cage, &format!("abstract:{other}"), &Grants::new());
        assert_eq!(
            got, "ok",
            "{tier}: an unrelated abstract socket below ABI 6"
        );
    }
    drop(unrelated);
    let name = format!("/tmp/dbus-procage-r34-{}", std::process::id());
    let _bus = AbstractBus::bind(&name);
    let d = scratch("r34-abstract");
    let attempt = format!("abstract:{name}");
    for tier in tiers() {
        let mut p = for_tier(policy(), tier);
        p.net = Network::All;
        p.waive.insert(HardDenyClass::ContainerEngines);
        let opts = socket_options(tier, &d, true);
        if tier == Tier::T2
            && refused_beside_the_host_bus(&p, &opts, "r34_an_abstract_bus_is_scoped")
        {
            continue;
        }
        if probe().landlock_abi >= 6 {
            let cage = Cage::with_options(&p, &opts).unwrap_or_else(|e| panic!("{tier}: {e}"));
            assert_eq!(
                run_in(&cage, &attempt, &Grants::new()),
                EPERM.to_string(),
                "{tier}"
            );
        }
        // Below ABI 6 nothing can scope it: the cage is refused, naming it.
        let old = opts.clone().with_landlock_abi(5);
        let gaps = match Cage::with_options(&p, &old) {
            Err(SpawnError::Lower(LowerError::Gaps(gaps))) => gaps,
            other => panic!("{tier} ABI 5: {:?}", other.map(|_| ())),
        };
        let subject = format!("@{name}");
        assert!(
            gaps.iter()
                .any(|g| g.construct == Construct::HdServiceHandoff
                    && g.subject.as_deref() == Some(subject.as_str())),
            "{tier} {gaps:?}"
        );
        // The positive control: waived, the child reaches the bus.
        let open = waived(p, &[HardDenyClass::ServiceHandoff]);
        let cage = Cage::with_options(&open, &old).unwrap();
        assert_eq!(run_in(&cage, &attempt, &Grants::new()), "ok", "{tier}");
    }
}

/// Each spawn looks again: on T2 a bus bound after the cage was made
/// refuses the spawn; on T1 a socket bound in a class directory after the
/// spawn is out of reach, because the directory is covered as a whole.
#[test]
fn r34_a_socket_bound_later_is_refused() {
    let d = scratch("r34-later");
    std::fs::create_dir_all(d.join("systemd")).unwrap();
    let mut p = policy();
    p.net = Network::All;
    p.waive.insert(HardDenyClass::ContainerEngines);
    p.fs.push(rule(Access::Read, &d));
    // T2: the cage is made while no socket exists, then one appears.
    let t2 = socket_options(Tier::T2, &d, false);
    if !refused_beside_the_host_bus(&p, &t2, "r34_a_socket_bound_later_is_refused") {
        let cage = Cage::with_options(&p, &t2).unwrap();
        let bus = std::os::unix::net::UnixListener::bind(d.join("bus")).unwrap();
        match cage.spawn(&mut child_command("unix:/"), &Grants::new()) {
            Err(SpawnError::Lower(LowerError::Gaps(gaps))) => assert!(
                gaps.iter()
                    .any(|g| g.construct == Construct::HdServiceHandoff),
                "{gaps:?}"
            ),
            other => panic!("T2 spawn: {:?}", other.map(|_| ())),
        }
        drop(bus);
        let _ = std::fs::remove_file(d.join("bus"));
    }
    if !t1("r34_a_socket_bound_later_is_refused") {
        return;
    }
    let cage = Cage::with_options(&p, &socket_options(Tier::T1, &d, true)).unwrap();
    let late = d.join("systemd/private");
    let child = cage
        .spawn(
            &mut child_command(&format!("delayed-unix:{}", late.display())),
            &Grants::new(),
        )
        .unwrap();
    let _private = std::os::unix::net::UnixListener::bind(&late).unwrap();
    let got = result(&finish(child, Duration::from_secs(20)));
    assert!(
        refused_one(&got),
        "T1: a socket bound later in systemd/ gave {got}"
    );
    // T1: an engine socket bound after the cage was made is covered at the
    // next spawn.
    let mut engines = policy();
    engines.net = Network::All;
    engines.waive.insert(HardDenyClass::ServiceHandoff);
    engines.fs.push(rule(Access::Read, &d));
    let cage = Cage::with_options(&engines, &socket_options(Tier::T1, &d, true)).unwrap();
    let _engine = std::os::unix::net::UnixListener::bind(d.join("docker.sock")).unwrap();
    let attempt = format!("unix:{}", d.join("docker.sock").display());
    let got = run_in(&cage, &attempt, &Grants::new());
    assert!(
        refused_one(&got),
        "T1: an engine bound after the cage gave {got}"
    );
}

/// Below Landlock ABI 6 an abstract bus that appears after the cage was
/// made refuses the spawn.
#[test]
fn r34_an_abstract_bus_bound_later_refuses_the_spawn() {
    let _turn = ABSTRACT.lock().unwrap_or_else(|e| e.into_inner());
    let d = scratch("r34-abstract-later");
    let mut p = policy();
    p.net = Network::All;
    p.waive.insert(HardDenyClass::ContainerEngines);
    let opts = socket_options(Tier::T2, &d, true).with_landlock_abi(5);
    if refused_beside_the_host_bus(
        &p,
        &opts,
        "r34_an_abstract_bus_bound_later_refuses_the_spawn",
    ) {
        return;
    }
    let cage = Cage::with_options(&p, &opts).unwrap();
    let name = format!("/tmp/dbus-procage-r34-later-{}", std::process::id());
    let _bus = AbstractBus::bind(&name);
    match cage.spawn(&mut child_command("unix:/"), &Grants::new()) {
        Err(SpawnError::Lower(LowerError::Gaps(gaps))) => assert!(
            gaps.iter()
                .any(|g| g.construct == Construct::HdServiceHandoff),
            "{gaps:?}"
        ),
        other => panic!("spawn: {:?}", other.map(|_| ())),
    }
}

// ---- R-35 Allowlist parser differential ----

/// A T1 cage of `policy` with the proxy `entries`, run once for `action`.
#[cfg(feature = "proxy")]
fn via_proxy(policy: &Policy, entries: &[&str], action: &str) -> String {
    let options = options(Tier::T1).with_proxy(proxied::proxy(entries));
    let cage = Cage::with_options(policy, &options).unwrap_or_else(|e| panic!("cage: {e}"));
    run_in(&cage, action, &Grants::new())
}

/// The proxy reads a host one way: what is checked is what is connected
/// to. Case and a trailing dot reach the allowed host; a NUL, percent
/// encoding and an address in any notation do not, nor an allowed name
/// that resolves to loopback. Proxy-only cages need tier T1.
#[cfg(feature = "proxy")]
#[test]
fn r35_a_host_is_read_one_way() {
    if !t1("r35_a_host_is_read_one_way") {
        return;
    }
    let port = proxied::echo();
    let p = proxied::through_proxy(policy());
    let reach = via_proxy(
        &p,
        &["allowed.test", "127.0.0.1"],
        &format!("via-http:ALLOWED.TEST.:{port}"),
    );
    assert_eq!(reach, "ok");
    let nul = proxied::hex(b"allowed.test\0.evil.test");
    let got = via_proxy(
        &p,
        &["allowed.test"],
        &format!(
            "via-http:allowed.test%00.evil.test:443;via-socks:{nul}|443;via-http:2130706433:{port};\
             via-http:0x7f.1:{port};via-http:[::ffff:127.0.0.1]:{port};via-http:allowed.test:{port}"
        ),
    );
    assert_eq!(got, "400 socks-2 403 403 403 403");
}

// ---- R-36 Direct egress around the proxy ----

/// A proxy-only child (tier T1) has no route but its own proxy: not TCP to
/// a host port, IPv6 or a public address, not TCP Fast Open, MPTCP or a raw
/// socket, not UDP (a datagram to the host's loopback does not arrive), not
/// DNS to a public resolver. Without a proxy of the cage's own the cage is
/// refused; tier T2 refuses it as a gap.
#[cfg(feature = "proxy")]
#[test]
fn r36_a_proxy_only_child_has_no_other_route() {
    let p = proxied::through_proxy(policy());
    let t2 = CageOptions::default()
        .with_tier(Tier::T2)
        .with_proxy(proxied::proxy(&["allowed.test"]));
    let gaps = match Cage::with_options(&p, &t2) {
        Err(SpawnError::Lower(LowerError::Gaps(gaps))) => gaps,
        other => panic!("T2: expected the proxy gap, got {other:?}"),
    };
    assert!(
        gaps.iter().any(|g| g.construct == Construct::NetProxy),
        "{gaps:?}"
    );
    if !t1("r36_a_proxy_only_child_has_no_other_route") {
        return;
    }
    assert!(Cage::with_options(&p, &options(Tier::T1)).is_err());
    let port = proxied::echo();
    let host_udp = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    host_udp
        .set_read_timeout(Some(Duration::from_millis(500)))
        .unwrap();
    let udp = host_udp.local_addr().unwrap().port();
    let attempts = format!(
        "tcp:127.0.0.1:{port};tcp:[::1]:{port};tcp:1.1.1.1:443;udp:8.8.8.8:53;\
         net:fastopen|{port};net:mptcp|{port};net:raw|{port};net:tcp6|{port}"
    );
    let entries = ["allowed.test", "127.0.0.1"];
    let got = via_proxy(&p, &entries, &attempts);
    assert!(got.split(' ').all(|r| r != "ok"), "{attempts}: {got}");
    let _ = via_proxy(&p, &entries, &format!("udp:127.0.0.1:{udp}"));
    let mut buf = [0u8; 8];
    assert!(host_udp.recv(&mut buf).is_err(), "a datagram left the run");
    let control = via_proxy(&p, &entries, &format!("via-http:allowed.test:{port}"));
    assert_eq!(control, "ok");
}
