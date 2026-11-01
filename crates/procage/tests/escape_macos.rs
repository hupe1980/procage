//! The escape suite on macOS: one or more canaries per escape class of the
//! published threat model.
//!
//! A canary is a test named after its class (`r21_…` for R-21). It spawns a
//! caged child that attempts the escape and asserts the specific refusal.
//! Next to the attempt it runs a positive control under the same cage: the
//! same operation on a target the policy allows, or the same attempt with
//! the class waived. The control shows that procage, not the host or a
//! missing file, refused.
//!
//! A variant this release does not handle is a canary marked
//! `#[ignore = "open: R-NN …"]`. It asserts the refusal like any other, so
//! `cargo test --test escape_macos -- --ignored` shows the escape.
//!
//! Run from a plain terminal: inside another Seatbelt sandbox spawning
//! returns `AlreadySandboxed` and every canary fails rather than skips.
//! Canaries write only to scratch directories, look Mach services up
//! without using them, and kill every process they learn of.

#![cfg(target_os = "macos")]

#[path = "support/scratch.rs"]
mod scratch_support;
use scratch_support::Scratch;

use std::io::{BufRead, Read};
use std::net::TcpListener;
use std::os::fd::{AsFd, AsRawFd};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use procage::macos::{Cage, CageOptions, Child, Grants, SpawnError, testing};
use procage::policy::seatbelt::{self, Effect, Filter, Operation};
use procage::policy::{
    AbsPath, Access, Base, EnvPolicy, FsRule, FsTarget, Grant, GrantName, HardDenyClass, Lifetime,
    Network, Policy, Port, Ports, Signals,
};

const EPERM: &str = "1";

static COUNTER: AtomicUsize = AtomicUsize::new(0);

/// A cage for `policy`; with `PROCAGE_ESCAPE_VIOLATIONS=1` it reports
/// violations, so the suite shows that reporting weakens nothing.
fn cage_for(policy: &Policy) -> Result<Cage, SpawnError> {
    let mut options = CageOptions::default();
    if std::env::var_os("PROCAGE_ESCAPE_VIOLATIONS").is_some_and(|v| v == "1") {
        options = options.with_violations();
    }
    Cage::with_options(policy, &options)
}

/// A fresh directory under the system temp dir, spelled as the system gives
/// it (`/var/folders/…`, through the `/var` symlink).
fn scratch(tag: &str) -> Scratch {
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    Scratch::at(std::env::temp_dir().join(format!("procage-esc-{}-{tag}-{n}", std::process::id())))
}

/// The spelling the kernel reports (`/private/var/folders/…`).
fn real(p: &Path) -> PathBuf {
    std::fs::canonicalize(p).unwrap()
}

fn abs(p: impl AsRef<Path>) -> AbsPath {
    AbsPath::new(p.as_ref().as_os_str().as_encoded_bytes()).unwrap()
}

fn rule(access: Access, p: impl AsRef<Path>) -> FsRule {
    FsRule::new(access, FsTarget::Subpath(abs(p)))
}

/// Base profile V1 plus exec of this test binary; with
/// `PROCAGE_ESCAPE_BASE=v3`, base V3 (the most permissive base), so the
/// suite shows that every canary holds there too.
fn policy() -> Policy {
    let mut p = Policy::default();
    p.base = match std::env::var("PROCAGE_ESCAPE_BASE").as_deref() {
        Ok("v3") => Base::V3,
        _ => Base::V1,
    };
    let exe = real(&std::env::current_exe().unwrap());
    p.fs.push(FsRule::new(Access::Exec, FsTarget::Literal(abs(exe))));
    p
}

fn waived(mut p: Policy, class: HardDenyClass) -> Policy {
    p.waive.insert(class);
    p
}

fn raw_allow(p: &mut Policy, op: Operation, filters: Vec<Filter>) {
    p.seatbelt
        .get_or_insert_with(Default::default)
        .rules
        .push(seatbelt::Rule {
            effect: Effect::Allow,
            ops: vec![op],
            filters,
        });
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

/// Runs `action` in a child caged by `policy`; returns its result line.
fn in_child(action: &str, policy: &Policy) -> String {
    in_child_with(action, policy, &Grants::new(), &[])
}

fn in_child_with(
    action: &str,
    policy: &Policy,
    grants: &Grants,
    fds: &[std::os::fd::BorrowedFd<'_>],
) -> String {
    let cage = cage_for(policy).unwrap_or_else(|e| panic!("cage: {e}"));
    let child = cage
        .spawn_with_fds(&mut child_command(action), grants, fds)
        .unwrap_or_else(|e| panic!("spawn: {e}"));
    result(&finish(child, Duration::from_secs(20)))
}

/// Spawns `action` and returns the handle and the first result line,
/// without waiting for the child to exit.
fn start(action: &str, policy: &Policy, grants: &Grants) -> (Child, String) {
    start_in(&cage_for(policy).unwrap(), action, grants)
}

fn start_in(cage: &Cage, action: &str, grants: &Grants) -> (Child, String) {
    let mut child = cage.spawn(&mut child_command(action), grants).unwrap();
    let stdout = child.stdout.take().unwrap();
    let line = std::io::BufReader::new(stdout).lines().find_map(|l| {
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
        "fcntl" => match std::fs::File::open(arg) {
            Ok(f) => {
                let fd = f.as_raw_fd();
                format!(
                    "{},{}",
                    code(testing::fcntl_errno(fd, 80)),
                    code(testing::fcntl_errno(fd, 110))
                )
            }
            Err(e) => format!("open-{}", e.raw_os_error().unwrap_or(-1)),
        },
        "mach" => code(testing::mach_lookup(arg)),
        "procargs" => {
            let pid = match arg {
                "parent" => std::os::unix::process::parent_id(),
                _ => std::process::id(),
            };
            code(testing::procargs_errno(pid))
        }
        "signal-parent" => code(testing::kill_errno(std::os::unix::process::parent_id(), 0)),
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
        "cat" => {
            let out = Command::new("/bin/cat")
                .arg(arg)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
            match out {
                Ok(s) if s.success() => "ok".into(),
                Ok(s) => format!("exit-{}", s.code().unwrap_or(-1)),
                Err(e) => format!("spawn-{}", e.raw_os_error().unwrap_or(-1)),
            }
        }
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
        "double-fork" => {
            // An intermediate starts a sleeper in its own session and exits;
            // the sleeper is reparented away from this child.
            // The sleeper inherits the pipe, so read one line, not to EOF.
            let mut cmd = child_command("session-sleeper");
            cmd.stderr(Stdio::null());
            let mut intermediate = cmd.spawn().unwrap();
            let stdout = intermediate.stdout.take().unwrap();
            let pid = std::io::BufReader::new(stdout)
                .lines()
                .find_map(|l| {
                    l.ok()?
                        .split_once("procage-result: ")
                        .map(|(_, r)| r.to_string())
                })
                .unwrap();
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
    let names = |p: &Policy, explicit: bool| {
        let cage = cage_for(p).unwrap();
        let mut cmd = child_command("env");
        if explicit {
            cmd.env("PROCAGE_EXPLICIT", "yes");
        }
        result(&finish(
            cage.spawn(&mut cmd, &Grants::new()).unwrap(),
            Duration::from_secs(20),
        ))
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
    let _ = Command::new("/bin/kill")
        .args(["-9", &pid.to_string()])
        .status();
}

// ---- R-02 Non-canonical path rules ----

/// A protect rule spelled through the `/var` symlink holds for the real
/// path.
#[test]
fn r02_a_protect_rule_spelled_through_a_symlink_holds() {
    let w = scratch("r02");
    std::fs::create_dir(w.join("p")).unwrap();
    assert!(
        w.starts_with("/var/"),
        "{w:?} is not the symlinked spelling"
    );
    let mut p = policy();
    p.fs.push(rule(Access::Write, &w));
    p.fs.push(rule(Access::Protect, w.join("p")));
    let r = real(&w);
    let got = in_child(&format!("write:{0}/q;write:{0}/p/f", r.display()), &p);
    assert_eq!(got, format!("ok {EPERM}"));
}

// ---- R-03 Pattern characters in paths ----

/// A rule on a directory named `a*` does not reach its sibling `ab`.
#[test]
fn r03_glob_characters_in_a_path_stay_literal() {
    let d = scratch("r03").canonical();
    std::fs::create_dir(d.join("a*")).unwrap();
    std::fs::create_dir(d.join("ab")).unwrap();
    let mut p = policy();
    p.fs.push(rule(Access::Write, d.join("a*")));
    let got = in_child(&format!("write:{0}/a*/f;write:{0}/ab/f", d.display()), &p);
    assert_eq!(got, format!("ok {EPERM}"));
}

// ---- R-04 Ancestor rename ----

/// Renaming an ancestor of a protected directory is refused, and the
/// protected file stays unwritable under any name.
#[test]
fn r04_a_protected_ancestor_cannot_be_renamed() {
    let w = scratch("r04").canonical();
    std::fs::create_dir_all(w.join("sub/p")).unwrap();
    std::fs::write(w.join("sub/p/c"), "original").unwrap();
    let mut p = policy();
    p.fs.push(rule(Access::Write, &w));
    p.fs.push(rule(Access::Protect, w.join("sub/p")));
    let got = in_child(
        &format!(
            "write:{0}/other;rename:{0}/sub|{0}/moved;write:{0}/sub/p/c;write:{0}/moved/p/c",
            w.display()
        ),
        &p,
    );
    let r: Vec<&str> = got.split(' ').collect();
    assert_eq!(r[..3], ["ok", EPERM, EPERM], "{got}");
    assert_ne!(r[3], "ok", "{got}");
    assert_eq!(
        std::fs::read_to_string(w.join("sub/p/c")).unwrap(),
        "original"
    );
}

// ---- R-05 Writes through read-only descriptors ----

/// `F_MAKECOMPRESSED` and `F_TRANSFEREXTENTS` on a read-only descriptor are
/// refused; with the class waived the sandbox no longer refuses them.
#[test]
fn r05_modifying_fcntl_commands_are_refused() {
    let d = scratch("r05").canonical();
    std::fs::write(d.join("f"), "content").unwrap();
    let mut p = policy();
    p.fs.push(rule(Access::Read, &d));
    let attempt = format!("fcntl:{}", d.join("f").display());
    assert_eq!(in_child(&attempt, &p), format!("{EPERM},{EPERM}"));
    let control = in_child(&attempt, &waived(p, HardDenyClass::FcntlModify));
    assert!(
        !control.split(',').any(|e| e == EPERM),
        "control: {control}"
    );
}

// ---- R-06 Work handed to unsandboxed services ----

const SERVICES: [&str; 3] = [
    "com.apple.coreservices.launchservicesd",
    "com.apple.coreservices.appleevents",
    "com.apple.pasteboard.1",
];

/// Launch Services, Apple events and the pasteboard cannot be looked up,
/// by default and even when the policy allows the lookups itself (the hard
/// deny comes last); with the class waived they can. A lookup sends nothing
/// to the service.
#[test]
fn r06_service_handoff_lookups_are_refused() {
    let attempt = SERVICES.map(|s| format!("mach:{s}")).join(";");
    let got = in_child(&attempt, &policy());
    assert!(got.split(' ').all(|r| r != "ok"), "{got}");
    let mut allowed = policy();
    raw_allow(
        &mut allowed,
        Operation::MachLookup,
        SERVICES
            .iter()
            .map(|s| Filter::GlobalName(procage::policy::name::Name::new(s).unwrap()))
            .collect(),
    );
    let got = in_child(&attempt, &allowed);
    assert!(got.split(' ').all(|r| r != "ok"), "{got}");
    let control = waived(allowed, HardDenyClass::ServiceHandoff);
    assert_eq!(in_child(&attempt, &control), "ok ok ok");
}

// ---- R-07 Trust handoff (the part procage handles) ----

/// Hooks, git config and shell startup files in a writable workspace are
/// refused; ordinary files are not.
#[test]
fn r07_trust_handoff_files_are_refused_in_a_writable_workspace() {
    let w = scratch("r07").canonical();
    std::fs::create_dir_all(w.join(".git/hooks")).unwrap();
    std::fs::create_dir_all(w.join("src")).unwrap();
    let mut p = policy();
    p.fs.push(rule(Access::Write, &w));
    let got = in_child(
        &format!(
            "write:{0}/src/main.rs;write:{0}/.git/hooks/pre-commit;write:{0}/.git/config;write:{0}/.zshrc",
            w.display()
        ),
        &p,
    );
    assert_eq!(got, format!("ok {EPERM} {EPERM} {EPERM}"));
}

// ---- R-08 Pre-existing hard links ----

/// A hard link made before the run gives a hidden file a second name.
#[test]
#[ignore = "open: R-08 a pre-existing hard link to a hidden file is neither reported nor refused"]
fn r08_a_hard_link_to_a_hidden_file_is_refused() {
    let d = scratch("r08").canonical();
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
    );
    assert_eq!(got, format!("{EPERM} {EPERM}"));
}

// ---- R-09 Local daemons ----

/// With loopback access to one port, another port and a unix-domain socket
/// in a readable directory stay unreachable.
#[test]
fn r09_other_ports_and_daemon_sockets_are_unreachable() {
    let allowed = TcpListener::bind("127.0.0.1:0").unwrap();
    let other = TcpListener::bind("127.0.0.1:0").unwrap();
    let d = scratch("r09").canonical();
    let sock = d.join("daemon.sock");
    let _daemon = std::os::unix::net::UnixListener::bind(&sock).unwrap();
    let a = allowed.local_addr().unwrap().port();
    let b = other.local_addr().unwrap().port();
    let attempt = format!("connect:{a};connect:{b};unix:{}", sock.display());
    let mut p = policy();
    p.fs.push(rule(Access::Read, &d));
    p.net = Network::Loopback(Ports::List([Port::new(a).unwrap()].into()));
    assert_eq!(in_child(&attempt, &p), format!("ok {EPERM} {EPERM}"));
    p.net = Network::None;
    assert_eq!(in_child(&attempt, &p), format!("{EPERM} {EPERM} {EPERM}"));
    p.ipc.unix_sockets = vec![abs(&d)];
    let control = in_child(&format!("unix:{}", sock.display()), &p);
    assert_eq!(control, "ok");
}

/// `ipc.unix_sockets` lets the child bind and connect under its paths only:
/// a daemon socket elsewhere, one under a hidden path and TCP stay out.
#[test]
fn r09_unix_sockets_reach_only_their_paths() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    // Unix socket addresses hold at most 104 bytes on macOS.
    let d = PathBuf::from(format!("/private/tmp/pc-r09-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    let ws = d.join("ws");
    std::fs::create_dir_all(ws.join("private")).unwrap();
    let sock = d.join("daemon.sock");
    let _daemon = std::os::unix::net::UnixListener::bind(&sock).unwrap();
    let hidden = ws.join("private/agent.sock");
    let _agent = std::os::unix::net::UnixListener::bind(&hidden).unwrap();
    let mut p = policy();
    p.fs.push(rule(Access::Read, &d));
    p.fs.push(rule(Access::Write, &ws));
    p.fs.push(rule(Access::Hide, ws.join("private")));
    p.ipc.unix_sockets = vec![abs(&ws)];
    let attempt = format!(
        "unix-serve:{};unix:{};unix:{};connect:{port}",
        ws.join("s.sock").display(),
        sock.display(),
        hidden.display()
    );
    let got = in_child(&attempt, &p);
    let _ = std::fs::remove_dir_all(&d);
    assert_eq!(got, format!("ok {EPERM} {EPERM} {EPERM}"));
}

// ---- R-10 Shared temporary directory ----

fn tmpdir_policy() -> Policy {
    let mut p = policy();
    p.grants.push(Grant {
        name: GrantName::new("tmpdir").unwrap(),
        access: Access::Write,
    });
    p
}

/// While one run holds its private temporary directory, another run can
/// neither read nor write it, nor write the shared temporary root.
#[test]
fn r10_runs_do_not_share_temporary_files() {
    let p = tmpdir_policy();
    let (holder, line) = start("hold-tmpdir", &p, &Grants::new());
    let (dir, wrote) = line.split_once(' ').unwrap();
    assert_eq!(wrote, "ok");
    let shared = real(&std::env::temp_dir());
    let got = in_child(
        &format!(
            "read:{dir}/f;write:{dir}/g;write:{}/procage-r10",
            shared.display()
        ),
        &p,
    );
    let own = in_child("own-tmpdir", &p);
    drop(holder);
    assert_eq!(got, format!("{EPERM} {EPERM} {EPERM}"));
    assert_eq!(own, "ok");
}

// ---- R-11 Unsandboxed exec modifier ----

/// A program the caged child executes is caged too: `(with no-sandbox)`
/// cannot be expressed, so no exec escapes the profile.
#[test]
fn r11_executed_programs_stay_caged() {
    let d = scratch("r11").canonical();
    std::fs::create_dir(d.join("in")).unwrap();
    std::fs::create_dir(d.join("out")).unwrap();
    std::fs::write(d.join("in/f"), "granted").unwrap();
    std::fs::write(d.join("out/f"), "outside").unwrap();
    let mut p = policy();
    p.process.fork = true;
    p.fs.push(rule(Access::Read, d.join("in")));
    let got = in_child(&format!("cat:{0}/in/f;cat:{0}/out/f", d.display()), &p);
    assert_eq!(got, "ok exit-1");
}

// ---- R-12 Firmlink spelling ----

/// A protect rule spelled with the data-volume path holds for the path
/// programs use.
#[test]
fn r12_a_data_volume_spelling_protects_the_visible_path() {
    let w = scratch("r12").canonical();
    std::fs::create_dir(w.join("p")).unwrap();
    let data = PathBuf::from(format!("/System/Volumes/Data{}", w.display()));
    assert!(data.exists(), "{data:?} does not exist");
    let mut p = policy();
    p.fs.push(rule(Access::Write, &w));
    p.fs.push(rule(Access::Protect, data.join("p")));
    let got = in_child(&format!("write:{0}/q;write:{0}/p/f", w.display()), &p);
    assert_eq!(got, format!("ok {EPERM}"));
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
    assert_eq!(in_child(&action, &policy()), "open=false");
    let control = in_child_with(&action, &policy(), &Grants::new(), &[file.as_fd()]);
    assert_eq!(control, "open=true");
}

// ---- R-22 Terminal input injection ----

/// A child that makes a terminal its own cannot push input into it. On
/// macOS 26.6.2 the sandbox checks TIOCSTI as `hid-control`, which no
/// policy allows; with `hid-control` allowed the hard deny still refuses it,
/// and only with the class waived as well does it work (injecting into
/// one's own terminal works sandboxed or not).
#[test]
fn r22_terminal_input_injection_is_refused() {
    let (_controller, device) = testing::open_pty().unwrap();
    let mut p = policy();
    p.fs.push(FsRule::new(Access::Write, FsTarget::Literal(abs(&device))));
    // Terminal ioctls on the device (TIOCSCTTY).
    raw_allow(
        &mut p,
        Operation::FileIoctl,
        vec![Filter::Literal(abs(&device))],
    );
    let attempt = format!("tiocsti:{}", device.display());
    assert_eq!(in_child(&attempt, &p), format!("ctty=ok sti={EPERM}"));
    raw_allow(&mut p, Operation::HidControl, vec![]);
    assert_eq!(in_child(&attempt, &p), format!("ctty=ok sti={EPERM}"));
    let control = in_child(&attempt, &waived(p, HardDenyClass::TerminalInjection));
    assert_eq!(control, "ctty=ok sti=ok");
}

// ---- R-23 Outliving the run ----

fn forking() -> Policy {
    let mut p = policy();
    p.process.fork = true;
    p
}

/// Dropping the handle kills a descendant in the child's group and one in a
/// session of its own.
#[test]
fn r23_descendants_die_with_the_run() {
    let (child, pids) = start("sleepers", &forking(), &Grants::new());
    let pids: Vec<u32> = pids.split(' ').map(|p| p.parse().unwrap()).collect();
    assert!(pids.iter().all(|&p| testing::alive(p)));
    drop(child);
    for pid in pids {
        let gone = gone_within(pid, Duration::from_secs(2));
        if !gone {
            kill_now(pid);
        }
        assert!(gone, "descendant {pid} survived");
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

/// A descendant whose parent exited before the run ended, in a session of
/// its own, is reparented to launchd, out of the child's tree and group; it
/// is found by the run's marker.
#[test]
fn r23_a_double_forked_descendant_dies_with_the_run() {
    let (child, pid) = start("double-fork", &forking(), &Grants::new());
    let pid: u32 = pid.parse().unwrap();
    assert!(testing::alive(pid));
    drop(child);
    assert_dies(pid, "descendant");
}

/// A descendant in a session of its own, left by a child that exited and was
/// waited for before the run ended, dies when the handle is dropped.
#[test]
fn r23_descendants_of_an_exited_child_die_with_the_run() {
    let (mut child, pid) = start("session-sleeper", &forking(), &Grants::new());
    let pid: u32 = pid.parse().unwrap();
    // Its exit status is not the point: the harness may write after the
    // result to the pipe the test already closed.
    child.wait().unwrap();
    assert!(testing::alive(pid), "the descendant must outlive the child");
    drop(child);
    assert_dies(pid, "descendant");
}

/// Two runs of one cage at the same time have different markers: ending one
/// leaves the other's escaped descendant alive.
#[test]
fn r23_concurrent_runs_are_separate() {
    let cage = cage_for(&forking()).unwrap();
    let (a, pa) = start_in(&cage, "double-fork", &Grants::new());
    let (b, pb) = start_in(&cage, "double-fork", &Grants::new());
    let (pa, pb): (u32, u32) = (pa.parse().unwrap(), pb.parse().unwrap());
    assert_ne!(testing::run_slot(&a), testing::run_slot(&b));
    drop(a);
    assert_dies(pa, "run A's descendant");
    let alive = testing::alive(pb);
    drop(b);
    assert!(alive, "ending run A killed run B's descendant {pb}");
    assert_dies(pb, "run B's descendant");
}

/// A detached run keeps its marker: a later run never gets it, so ending
/// that run leaves the detached run's processes alone.
#[test]
fn r23_a_detached_run_keeps_its_marker() {
    let cage = cage_for(&forking()).unwrap();
    let (a, pa) = start_in(&cage, "double-fork", &Grants::new());
    let pa: u32 = pa.parse().unwrap();
    let slot = testing::run_slot(&a);
    let mut detached = a.detach();
    let (b, pb) = start_in(&cage, "double-fork", &Grants::new());
    let pb: u32 = pb.parse().unwrap();
    assert_ne!(testing::run_slot(&b), slot);
    drop(b);
    assert_dies(pb, "run B's descendant");
    let alive = testing::alive(pa);
    kill_now(pa);
    let _ = detached.kill();
    let _ = detached.wait();
    assert!(
        alive,
        "ending run B killed the detached run's descendant {pa}"
    );
}

/// With `Lifetime::Tree`, macOS still finds escaped descendants by marker.
#[test]
fn r23_tree_lifetime_still_reaps() {
    let mut p = forking();
    p.process.lifetime = Lifetime::Tree;
    let (child, pid) = start("double-fork", &p, &Grants::new());
    let pid: u32 = pid.parse().unwrap();
    drop(child);
    assert_dies(pid, "descendant");
}

/// A launch agent cannot be planted even under a write rule for the launch
/// agents directory.
#[test]
fn r23_a_launch_agent_cannot_be_planted() {
    let agents = PathBuf::from(std::env::var("HOME").unwrap()).join("Library/LaunchAgents");
    assert!(agents.is_dir(), "this canary needs ~/Library/LaunchAgents");
    let plist = agents.join(format!("procage-canary-{}.plist", std::process::id()));
    let mut p = policy();
    p.fs.push(rule(Access::Write, &agents));
    let got = in_child(&format!("write:{}", plist.display()), &p);
    let planted = plist.exists();
    let _ = std::fs::remove_file(&plist);
    assert_eq!(got, EPERM);
    assert!(!planted);
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
        .env("SSH_AUTH_SOCK", "/tmp/agent.sock");
    let out = cmd.output().unwrap();
    let got = result(&out);
    for secret in ["GITHUB_TOKEN", "AWS_SECRET_ACCESS_KEY", "SSH_AUTH_SOCK"] {
        assert!(!got.contains(secret), "{secret} reached the child: {got}");
    }
    assert!(got.contains("PROCAGE_EXPLICIT"), "control: {got}");
}

// ---- R-25 Process introspection ----

/// The child cannot signal the caller, whatever the signal setting, while
/// the process-access class is in force. Waived, `SameUser` reaches the
/// caller and `SelfAndChildren` still does not.
#[test]
fn r25_other_processes_cannot_be_signalled() {
    let with = |signals: Signals| {
        let mut p = policy();
        p.process.fork = true;
        p.process.signals = signals;
        p
    };
    assert_eq!(in_child("signal-parent", &policy()), EPERM);
    for signals in [Signals::SelfAndChildren, Signals::SameUser] {
        assert_eq!(
            in_child("signal-parent", &with(signals)),
            EPERM,
            "{signals:?}"
        );
    }
    let waive = |signals| waived(with(signals), HardDenyClass::ProcessAccess);
    assert_eq!(in_child("signal-parent", &waive(Signals::SameUser)), "ok");
    assert_eq!(
        in_child("signal-parent", &waive(Signals::SelfAndChildren)),
        EPERM
    );
}

/// The child cannot read the caller's arguments and environment; it can
/// read its own. The sandbox does not mediate `KERN_PROCARGS2`, even under
/// `(deny sysctl-read)` (macOS 26.6.2).
#[test]
#[ignore = "open: R-25 KERN_PROCARGS2 gives any same-user process's arguments and environment on macOS"]
fn r25_other_processes_arguments_are_unreadable() {
    let got = in_child("procargs:parent;procargs:self", &policy());
    assert_eq!(got, format!("{EPERM} ok"));
}

// ---- R-26 Helper replacement ----

/// procage installs no helper program; this canary attacks one once it
/// does.
#[test]
#[ignore = "open: R-26 procage installs no helper"]
fn r26_the_helper_cannot_be_replaced() {
    panic!("open: R-26: procage installs no helper");
}
