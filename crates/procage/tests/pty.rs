//! A new pseudo-terminal (`Tty::NewPty`), observed on the kernel: an
//! interactive shell, a REPL and a full-screen program run caged through
//! it; the run's end closes it and kills its jobs; it starts at 80 by 24
//! under any base; `Cage::exec` refuses it; and concurrent runs from a busy
//! multithreaded parent each get their own terminal and nothing else.

#![cfg(any(target_os = "macos", target_os = "linux"))]

use std::io::{Read, Write};
use std::path::Path;
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use procage::Pty;
use procage::native::{Cage, CageOptions, Child, Grants, SpawnError, Unsupported};
use procage::policy::{
    AbsPath, Access, Base, Construct, FsRule, FsTarget, Grant, GrantName, LowerOptions, Policy, Tty,
};

fn abs(p: impl AsRef<Path>) -> AbsPath {
    AbsPath::new(p.as_ref().as_os_str().as_encoded_bytes()).unwrap()
}

fn rule(access: Access, p: impl AsRef<Path>) -> FsRule {
    FsRule::new(access, FsTarget::Subpath(abs(p)))
}

/// Base V3 with forking (the shell runs programs) and a private `TMPDIR`
/// (editors keep their swap files there).
fn interactive() -> Policy {
    let mut p = Policy::default();
    p.base = Base::V3;
    p.tty = Tty::NewPty;
    p.process.fork = true;
    p.grants.push(Grant {
        name: GrantName::new("tmpdir").unwrap(),
        access: Access::Write,
    });
    p
}

/// The cages to run `p` in: macOS, or each Linux tier the host gives (T2
/// waives the trust-handoff class, which it cannot keep beside a write
/// grant).
fn cages(p: &Policy) -> Vec<(String, Cage)> {
    let lower = LowerOptions::default()
        .allow(Construct::HdSecrets)
        .allow(Construct::HdTrustHandoff)
        .allow(Construct::HdPersistence)
        .allow(Construct::ProcOtherProcesses);
    #[cfg(target_os = "macos")]
    let variants = vec![("macOS".to_string(), p.clone(), CageOptions::default())];
    #[cfg(target_os = "linux")]
    let variants = {
        use procage::linux::probe;
        use procage::policy::{HardDenyClass, Tier};
        let tier = probe().tier.expect("a tier");
        if let Ok(expected) = std::env::var("PROCAGE_EXPECT_TIER") {
            assert_eq!(format!("{tier}"), expected, "TIER MISMATCH");
        }
        let tiers = match tier {
            Tier::T1 => vec![Tier::T1, Tier::T2],
            Tier::T2 => vec![Tier::T2],
        };
        tiers
            .into_iter()
            .map(|t| {
                let mut p = p.clone();
                if t == Tier::T2 {
                    p.waive.insert(HardDenyClass::TrustHandoff);
                }
                (format!("{t}"), p, CageOptions::default().with_tier(t))
            })
            .collect::<Vec<_>>()
    };
    variants
        .into_iter()
        .map(|(name, p, o)| {
            let cage = Cage::with_options(&p, &o.with_lower(lower.clone()))
                .unwrap_or_else(|e| panic!("{name}: {e}"));
            (name, cage)
        })
        .collect()
}

/// The controller side, read on a thread into a buffer.
struct Terminal {
    pty: Arc<Pty>,
    seen: Arc<Mutex<Vec<u8>>>,
    ended: Arc<AtomicBool>,
}

impl Terminal {
    fn of(child: &mut Child) -> Terminal {
        let pty = Arc::new(child.take_pty().expect("a terminal"));
        assert!(child.take_pty().is_none(), "taken once");
        let seen = Arc::new(Mutex::new(Vec::new()));
        let ended = Arc::new(AtomicBool::new(false));
        let (reader, buf, end) = (pty.clone(), seen.clone(), ended.clone());
        std::thread::spawn(move || {
            let mut chunk = [0u8; 4096];
            loop {
                match (&*reader).read(&mut chunk) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => buf.lock().unwrap().extend_from_slice(&chunk[..n]),
                }
            }
            end.store(true, Ordering::SeqCst);
        });
        Terminal { pty, seen, ended }
    }

    fn send(&self, text: &str) {
        (&*self.pty).write_all(text.as_bytes()).unwrap();
    }

    fn text(&self) -> String {
        String::from_utf8_lossy(&self.seen.lock().unwrap()).into_owned()
    }

    /// Waits until the output contains `needle`.
    fn expect(&self, needle: &str, what: &str) {
        let deadline = Instant::now() + Duration::from_secs(20);
        while Instant::now() < deadline {
            if self.text().contains(needle) {
                return;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        panic!("{what}: no {needle:?} in {:?}", self.text());
    }

    /// Waits until the controller reads end of file or fails.
    fn wait_ended(&self, what: &str) {
        let deadline = Instant::now() + Duration::from_secs(10);
        while !self.ended.load(Ordering::SeqCst) {
            assert!(
                Instant::now() < deadline,
                "{what}: the terminal stayed open"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}

fn spawn(cage: &Cage, program: &str, args: &[&str]) -> Child {
    let mut cmd = Command::new(program);
    cmd.args(args);
    cage.spawn(&mut cmd, &Grants::new())
        .unwrap_or_else(|e| panic!("spawn {program}: {e}"))
}

fn exits_ok(child: &mut Child, what: &str) {
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            assert!(status.success(), "{what}: {status}");
            return;
        }
        assert!(Instant::now() < deadline, "{what}: still running");
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// An interactive shell answers through its terminal: standard input is a
/// terminal, it is the device the handle names, and `/dev/tty` opens (the
/// terminal is the controlling one). Results are computed by the shell, so
/// the echo of the typed line does not match them.
#[test]
fn an_interactive_shell_runs_through_its_terminal() {
    for (name, cage) in cages(&interactive()) {
        let mut child = spawn(&cage, "/bin/sh", &["-i"]);
        let term = Terminal::of(&mut child);
        let device = term.pty.device().display().to_string();
        term.send("tty; test -t 0 && echo T0-$((1+1)); (exec 3</dev/tty) && echo CT-$((2+3))\n");
        term.expect(&device, &name);
        term.expect("T0-2", &name);
        term.expect("CT-5", &name);
        term.send("exit\n");
        exits_ok(&mut child, &name);
    }
}

/// A REPL evaluates an expression typed into the terminal.
#[test]
fn a_repl_runs_through_its_terminal() {
    for (name, cage) in cages(&interactive()) {
        let mut child = spawn(&cage, "/usr/bin/python3", &["-q", "-i"]);
        let term = Terminal::of(&mut child);
        term.send("print(6*7)\n");
        term.expect("42", &name);
        term.send("exit()\n");
        exits_ok(&mut child, &name);
    }
}

/// A full-screen program draws (escape sequences) and quits on its key:
/// `vi` where the system ships it, otherwise `top`.
#[test]
fn a_full_screen_program_runs_through_its_terminal() {
    let (program, quit): (&str, &str) = if Path::new("/usr/bin/vi").exists() {
        ("/usr/bin/vi", "\x1b:q!\r")
    } else {
        ("/usr/bin/top", "q")
    };
    println!("full-screen program: {program}");
    let mut p = interactive();
    if program.ends_with("top") {
        // `top` reads the process table.
        p.fs.push(rule(Access::Read, "/proc"));
    }
    for (name, cage) in cages(&p) {
        // A harness names the terminal type, as an emulator does.
        let mut cmd = Command::new(program);
        cmd.env("TERM", "xterm-256color");
        let mut child = cage
            .spawn(&mut cmd, &Grants::new())
            .unwrap_or_else(|e| panic!("{name}: spawn {program}: {e}"));
        let term = Terminal::of(&mut child);
        term.expect("\x1b[", &name);
        std::thread::sleep(Duration::from_millis(300));
        term.send(quit);
        exits_ok(&mut child, &format!("{name}: {program}"));
    }
}

/// Ending the run kills a job the shell started in the background, and the
/// controller then reads end of file (or fails) instead of blocking.
#[test]
fn the_run_end_closes_the_terminal_and_kills_its_jobs() {
    for (name, cage) in cages(&interactive()) {
        let mut child = spawn(&cage, "/bin/sh", &["-i"]);
        let term = Terminal::of(&mut child);
        term.send("set +H\nsleep 300 & echo JOB-$((0+$!))-$((6*7))\n");
        term.expect("-42", &name);
        let text = term.text();
        let start = text.rfind("JOB-").unwrap() + 4;
        let end = text[start..].find("-42").unwrap() + start;
        let pid: i32 = text[start..end].parse().unwrap();
        assert!(alive(pid), "{name}: job {pid}");
        drop(child);
        let deadline = Instant::now() + Duration::from_secs(5);
        while alive(pid) {
            assert!(Instant::now() < deadline, "{name}: job {pid} survived");
            std::thread::sleep(Duration::from_millis(20));
        }
        term.wait_ended(&name);
    }
}

fn alive(pid: i32) -> bool {
    Command::new("/bin/kill")
        .args(["-0", &pid.to_string()])
        .status()
        .is_ok_and(|s| s.success())
        && !zombie(pid)
}

fn zombie(pid: i32) -> bool {
    Command::new("/bin/ps")
        .args(["-o", "stat=", "-p", &pid.to_string()])
        .output()
        .is_ok_and(|o| {
            String::from_utf8_lossy(&o.stdout)
                .trim_start()
                .starts_with('Z')
        })
}

/// The terminal works without the base's help: it starts at 80 by 24, and
/// `set_size` changes what the child reads. On Linux there is no base; on
/// macOS a program cannot start without one, so base V1, which has no
/// terminal rule, stands in.
#[test]
fn without_a_base_the_terminal_works_and_resizes() {
    let mut p = Policy::default();
    #[cfg(target_os = "macos")]
    {
        p.base = Base::V1;
    }
    p.tty = Tty::NewPty;
    #[cfg(target_os = "macos")]
    let code = ["/bin", "/usr/lib", "/System", "/usr/bin"];
    #[cfg(target_os = "linux")]
    let code = ["/bin", "/lib", "/lib64", "/usr"];
    for dir in code {
        if Path::new(dir).exists() {
            p.fs.push(rule(Access::Exec, dir));
        }
    }
    p.process.fork = true;
    for (name, cage) in cages(&p) {
        let mut child = spawn(&cage, "/bin/sh", &["-c", "stty size; read x; stty size"]);
        let term = Terminal::of(&mut child);
        term.expect("24 80", &name);
        term.pty.set_size(50, 132).unwrap();
        term.send("go\n");
        term.expect("50 132", &name);
        exits_ok(&mut child, &name);
    }
}

/// `Cage::exec` and `Cage::exec_session` refuse a new terminal before the
/// process changes.
#[test]
fn exec_refuses_a_new_terminal() {
    for (name, cage) in cages(&interactive()) {
        let mut cmd = Command::new("/bin/true");
        let refused =
            |e: SpawnError| matches!(e, SpawnError::Unsupported(Unsupported::Setting { .. }));
        assert!(refused(cage.exec(&mut cmd, &Grants::new())), "{name}: exec");
        assert!(
            refused(cage.exec_session(&mut cmd, &Grants::new())),
            "{name}: exec_session"
        );
    }
}

/// Runs spawned at once from several threads, while other threads allocate
/// and lock: each child starts with its own terminal as controlling
/// terminal, and holds no descriptor but its three standard ones (no
/// controller, no other run's terminal).
#[test]
fn concurrent_runs_from_a_busy_parent_get_only_their_own_terminal() {
    let stop = Arc::new(AtomicBool::new(false));
    let churn: Vec<_> = (0..4)
        .map(|_| {
            let stop = stop.clone();
            let lock = Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));
            std::thread::spawn(move || {
                while !stop.load(Ordering::Relaxed) {
                    let mut held = lock.lock().unwrap();
                    held.push(vec![0u8; 4096]);
                    if held.len() > 64 {
                        held.clear();
                    }
                }
            })
        })
        .collect();
    let cages = Arc::new(cages(&interactive()));
    // `ls` lists its own open descriptors: 0, 1, 2 and the directory it
    // reads.
    let script = "(exec 3</dev/tty) && echo FDS $(ls /dev/fd | tr '\\n' ' ')END";
    let workers: Vec<_> = (0..4)
        .map(|w| {
            let cages = cages.clone();
            std::thread::spawn(move || {
                for i in 0..50 {
                    for (name, cage) in cages.iter() {
                        let what = format!("{name} worker {w} run {i}");
                        let mut child = spawn(cage, "/bin/sh", &["-c", script]);
                        let term = Terminal::of(&mut child);
                        let deadline = Instant::now() + Duration::from_secs(20);
                        while !term.text().contains("END") && Instant::now() < deadline {
                            std::thread::sleep(Duration::from_millis(20));
                        }
                        // A run killed by another run's end shows here.
                        assert!(
                            term.text().contains("END"),
                            "{what}: pid {}, exit {:?}, output {:?}",
                            child.id(),
                            child.try_wait(),
                            term.text()
                        );
                        let text = term.text();
                        let fds = text[text.find("FDS ").unwrap() + 4..text.find("END").unwrap()]
                            .split_whitespace()
                            .map(|f| f.parse::<u32>().unwrap())
                            .collect::<Vec<_>>();
                        assert!(
                            fds.len() <= 4 && fds.iter().all(|&f| f <= 3),
                            "{what}: {fds:?}"
                        );
                        exits_ok(&mut child, &what);
                    }
                }
            })
        })
        .collect();
    for w in workers {
        w.join().unwrap();
    }
    stop.store(true, Ordering::Relaxed);
    for c in churn {
        c.join().unwrap();
    }
}
