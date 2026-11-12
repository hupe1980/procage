//! The async handle (feature `tokio`) on both backends. The test binary
//! runs itself as the caged child (`child_entry`), selected by
//! `PROCAGE_CHILD`.

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, Instant};

use procage::native::{AsyncChild, Cage, CageOptions, Grants, SpawnError, testing};
use procage::policy::{AbsPath, Access, Base, Exec, FsRule, FsTarget, Grant, GrantName, Policy};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, BufReader};

fn abs(p: impl AsRef<Path>) -> AbsPath {
    AbsPath::new(p.as_ref().as_os_str().as_encoded_bytes()).unwrap()
}

/// This test binary's real path.
fn exe() -> PathBuf {
    std::fs::canonicalize(std::env::current_exe().unwrap()).unwrap()
}

/// A forking policy that runs this test binary and gives each run a
/// private `TMPDIR`.
#[cfg(target_os = "macos")]
fn policy() -> Policy {
    use procage::policy::seatbelt;
    let mut p = Policy::default();
    for dir in ["/usr/lib", "/System", "/bin", "/usr/bin"] {
        p.fs.push(FsRule::new(Access::Exec, FsTarget::Subpath(abs(dir))));
    }
    p.fs.push(FsRule::new(Access::Read, FsTarget::Literal(abs("/"))));
    p.fs.push(FsRule::new(Access::Exec, FsTarget::Literal(abs(exe()))));
    // The Rust runtime reads sysctls (the page size) when it starts.
    p.seatbelt
        .get_or_insert_with(Default::default)
        .rules
        .push(seatbelt::Rule {
            effect: seatbelt::Effect::Allow,
            ops: vec![seatbelt::Operation::SysctlRead],
            filters: vec![],
        });
    p.process.fork = true;
    with_tmpdir(p)
}

#[cfg(target_os = "linux")]
fn policy() -> Policy {
    let mut p = Policy::default();
    p.base = procage::policy::Base::V1;
    p.fs.push(FsRule::new(
        Access::Exec,
        FsTarget::Subpath(abs(exe().parent().unwrap())),
    ));
    p.process.fork = true;
    p.net = procage::policy::Network::None;
    // The tmpdir grant reaches trust-handoff names, which tier T2 lets
    // through only waived; the classes have their own canaries.
    p.waive.insert(procage::policy::HardDenyClass::TrustHandoff);
    with_tmpdir(p)
}

fn with_tmpdir(mut p: Policy) -> Policy {
    p.grants.push(Grant {
        name: GrantName::new("tmpdir").unwrap(),
        access: Access::Write,
    });
    p
}

/// The cage options to test: the default on macOS, each tier the host
/// gives on Linux (data classes masked on T1).
#[cfg(target_os = "macos")]
fn variants() -> Vec<(String, CageOptions)> {
    vec![("macos".into(), CageOptions::default())]
}

#[cfg(target_os = "linux")]
fn variants() -> Vec<(String, CageOptions)> {
    use procage::linux::probe;
    use procage::policy::{Construct, LowerOptions, Tier};
    let lower = LowerOptions::default()
        .allow(Construct::HdSecrets)
        .allow(Construct::HdTrustHandoff)
        .allow(Construct::HdPersistence);
    let tiers = match probe().tier.expect("a tier: these tests need Landlock") {
        Tier::T1 => vec![Tier::T1, Tier::T2],
        Tier::T2 => vec![Tier::T2],
    };
    tiers
        .into_iter()
        .map(|t| {
            let options = CageOptions::default()
                .with_tier(t)
                .with_lower(lower.clone());
            (format!("{t}"), options)
        })
        .collect()
}

fn cages(reporting: bool) -> Vec<(String, Cage)> {
    variants()
        .into_iter()
        .map(|(name, options)| {
            let options = if reporting {
                options.with_violations()
            } else {
                options
            };
            let cage = Cage::with_options(&policy(), &options)
                .unwrap_or_else(|e| panic!("{name}: cage: {e}"));
            (name, cage)
        })
        .collect()
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .unwrap()
}

fn child_command(action: &str) -> tokio::process::Command {
    let mut cmd = tokio::process::Command::new(exe());
    cmd.args(["--exact", "child_entry", "--nocapture", "--test-threads=1"])
        .env("PROCAGE_CHILD", action)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    cmd
}

/// The first result line of a running child, read asynchronously.
async fn first_result(child: &mut AsyncChild) -> String {
    let stdout = child.stdout.take().unwrap();
    let mut lines = BufReader::new(stdout).lines();
    while let Some(line) = lines.next_line().await.unwrap() {
        if let Some((_, r)) = line.split_once("procage-result: ") {
            return r.to_string();
        }
    }
    let mut err = String::new();
    let _ = child.stderr.take().unwrap().read_to_string(&mut err).await;
    panic!("no result from the child: {err}");
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

/// A file outside the policy for run `n` (macOS denies reading it).
#[cfg(target_os = "macos")]
fn denied_file(n: usize) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("procage-tokio-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let file = std::fs::canonicalize(&dir)
        .unwrap()
        .join(format!("deny-{n}"));
    std::fs::write(&file, "x").unwrap();
    file
}

/// The denial run `n` makes: a file read on macOS, a refused system call
/// on Linux (two kinds, by parity).
#[cfg(target_os = "macos")]
fn denial(n: usize) -> (String, String) {
    let file = denied_file(n);
    (
        format!("read:{}", file.display()),
        file.display().to_string(),
    )
}

#[cfg(target_os = "linux")]
fn denial(n: usize) -> (String, String) {
    let call = if n.is_multiple_of(2) {
        "ptrace"
    } else {
        "setsid"
    };
    (format!("syscall:{call}"), call.to_string())
}

/// Whether `v` is the denial `what` stands for.
fn is(v: &procage::Violation, what: &str) -> bool {
    if cfg!(target_os = "macos") {
        v.target.as_deref() == Some(what)
    } else {
        v.operation == what
    }
}

#[test]
fn child_entry() {
    let Ok(action) = std::env::var("PROCAGE_CHILD") else {
        return;
    };
    for step in action.split(';') {
        let result = match step.split_once(':') {
            Some(("echo", text)) => text.to_string(),
            Some(("read", path)) => format!("read={}", std::fs::read(path).is_ok()),
            #[cfg(target_os = "linux")]
            Some(("syscall", name)) => format!("errno={:?}", testing::syscall_errno(name)),
            Some(("sleep", secs)) => {
                std::thread::sleep(Duration::from_secs(secs.parse().unwrap()));
                continue;
            }
            _ if step == "tmpdir" => std::env::var("TMPDIR").unwrap_or_default(),
            _ if step == "sleepers" => {
                let same = testing::spawn_sleeper(false).unwrap();
                let session = testing::spawn_sleeper(true).unwrap();
                format!("{same} {session}")
            }
            _ => format!("unknown action {step}"),
        };
        println!("procage-result: {result}");
    }
}

#[test]
fn output_is_read_and_the_exit_awaited() {
    let rt = runtime();
    for (name, cage) in cages(false) {
        rt.block_on(async {
            let mut child = cage
                .spawn_async(&mut child_command("echo:hello"), &Grants::new())
                .unwrap_or_else(|e| panic!("{name}: {e}"));
            let mut out = String::new();
            let mut stdout = child.stdout.take().unwrap();
            stdout.read_to_string(&mut out).await.unwrap();
            assert!(out.contains("procage-result: hello\n"), "{name}: {out}");
            let status = child.wait().await.unwrap();
            assert!(status.success(), "{name}: {status}");
            let receipt = child.receipt().expect("the child exited");
            assert!(!receipt.exit.ended_by_caller, "{name}");
        });
    }
}

#[test]
fn dropping_the_handle_kills_every_descendant() {
    let rt = runtime();
    for (name, cage) in cages(false) {
        let (leader, pids) = rt.block_on(async {
            let mut child = cage
                .spawn_async(&mut child_command("sleepers;sleep:30"), &Grants::new())
                .unwrap();
            let line = first_result(&mut child).await;
            let pids: Vec<u32> = line.split(' ').map(|p| p.parse().unwrap()).collect();
            assert!(pids.iter().all(|&p| testing::alive(p)), "{name}");
            let leader = child.id().unwrap();
            drop(child);
            (leader, pids)
        });
        assert!(gone_within(leader, Duration::from_secs(2)), "{name}");
        for pid in pids {
            assert!(
                gone_within(pid, Duration::from_secs(2)),
                "{name}: {pid} survived"
            );
        }
    }
}

#[test]
fn a_handle_dropped_outside_the_runtime_still_ends_the_run() {
    let rt = runtime();
    for (name, cage) in cages(false) {
        let mut child = rt.block_on(async {
            cage.spawn_async(&mut child_command("sleepers;sleep:30"), &Grants::new())
                .unwrap()
        });
        let line = rt.block_on(first_result(&mut child));
        let pids: Vec<u32> = line.split(' ').map(|p| p.parse().unwrap()).collect();
        drop(child);
        for pid in pids {
            assert!(
                gone_within(pid, Duration::from_secs(2)),
                "{name}: {pid} survived"
            );
        }
    }
}

#[test]
fn kill_all_ends_the_run_and_the_receipt_says_so() {
    let rt = runtime();
    for (name, cage) in cages(false) {
        rt.block_on(async {
            let mut child = cage
                .spawn_async(&mut child_command("sleepers;sleep:30"), &Grants::new())
                .unwrap();
            let pids: Vec<u32> = first_result(&mut child)
                .await
                .split(' ')
                .map(|p| p.parse().unwrap())
                .collect();
            child.kill_all().await.unwrap();
            for pid in pids {
                assert!(
                    gone_within(pid, Duration::from_secs(2)),
                    "{name}: {pid} survived"
                );
            }
            let tmp = child.tmpdir().unwrap().to_path_buf();
            let receipt = child.receipt().expect("reaped");
            assert!(receipt.exit.ended_by_caller, "{name}: {receipt:?}");
            drop(child);
            assert!(!tmp.exists(), "{name}: the private TMPDIR stayed");
        });
    }
}

#[test]
fn concurrent_runs_stay_apart() {
    let rt = runtime();
    for (name, cage) in cages(true) {
        let cage = std::sync::Arc::new(cage);
        let runs: Vec<_> = (0..32)
            .map(|n| {
                let cage = cage.clone();
                rt.spawn(async move {
                    let (action, what) = denial(n);
                    let action = format!("tmpdir;{action};echo:{n}");
                    let mut child = cage
                        .spawn_async(&mut child_command(&action), &Grants::new())
                        .unwrap();
                    let mut out = String::new();
                    child
                        .stdout
                        .take()
                        .unwrap()
                        .read_to_string(&mut out)
                        .await
                        .unwrap();
                    child.wait().await.unwrap();
                    let record = child.violations();
                    (n, what, out, record)
                })
            })
            .collect();
        let mut tmpdirs = std::collections::BTreeSet::new();
        let mut seen = 0;
        for run in runs {
            let (n, what, out, record) = rt.block_on(run).unwrap();
            let results: Vec<&str> = out
                .lines()
                .filter_map(|l| l.split_once("procage-result: ").map(|(_, r)| r))
                .collect();
            assert_eq!(
                results.last(),
                Some(&n.to_string().as_str()),
                "{name}: {out}"
            );
            assert!(
                tmpdirs.insert(results[0].to_string()),
                "{name}: shared TMPDIR {out}"
            );
            // Linux records every refused call; macOS drops reports under
            // this load (best effort), so only isolation is exact there.
            let own = record.iter().any(|v| is(v, &what));
            seen += usize::from(own);
            assert!(
                own || cfg!(target_os = "macos"),
                "{name}: run {n} lacks its denial: {record:#?}"
            );
            for v in record.iter() {
                let other = (0..32)
                    .filter(|&m| m != n)
                    .map(denial)
                    .any(|(_, w)| w != what && is(v, &w));
                assert!(!other, "{name}: run {n} has another run's denial: {v:?}");
            }
        }
        assert_eq!(tmpdirs.len(), 32, "{name}");
        assert!(seen > 0, "{name}: no run saw its own denial");
    }
}

#[test]
fn violations_stream_while_the_child_runs() {
    let rt = runtime();
    for (name, cage) in cages(true) {
        rt.block_on(async {
            let (action, what) = denial(0);
            let mut child = cage
                .spawn_async(
                    &mut child_command(&format!("{action};sleep:30")),
                    &Grants::new(),
                )
                .unwrap();
            let mut stream = child.violation_stream().expect("reporting is on");
            assert!(child.violation_stream().is_none() && child.violation_receiver().is_none());
            let first = tokio::time::timeout(Duration::from_secs(10), async {
                loop {
                    match stream.next().await {
                        Some(v) if is(&v, &what) => return v,
                        Some(_) => {}
                        None => panic!("{name}: the stream ended early"),
                    }
                }
            })
            .await
            .unwrap_or_else(|_| panic!("{name}: no violation within 10 s"));
            assert!(
                child.try_wait().unwrap().is_none(),
                "{name}: {first:?} came after the exit"
            );
            child.kill_all().await.unwrap();
            let ended = tokio::time::timeout(Duration::from_secs(5), async {
                while stream.next().await.is_some() {}
            })
            .await;
            assert!(ended.is_ok(), "{name}: the stream did not end with the run");
        });
    }
}

#[test]
fn spawn_async_needs_a_runtime() {
    for (name, cage) in cages(false) {
        // A tokio command can be built anywhere; spawning needs the runtime.
        let err = cage
            .spawn_async(&mut child_command("echo:never"), &Grants::new())
            .unwrap_err();
        assert!(matches!(err, SpawnError::NoRuntime), "{name}: {err:?}");
    }
}

/// `Exec::Never` starts the program on the async path too (on Linux the
/// supervisor answers the exec while tokio's `spawn` waits for it).
#[test]
fn exec_never_starts_the_program_async() {
    let rt = runtime();
    for (name, options) in variants() {
        let mut p = Policy::default();
        p.base = Base::V1;
        p.process.exec = Exec::Never;
        for options in [options.clone(), options.with_violations()] {
            let cage =
                Cage::with_options(&p, &options).unwrap_or_else(|e| panic!("{name}: cage: {e}"));
            rt.block_on(async {
                let mut c = tokio::process::Command::new("/bin/echo");
                c.arg("async-never").stdout(Stdio::piped());
                let mut child = cage
                    .spawn_async(&mut c, &Grants::new())
                    .unwrap_or_else(|e| panic!("{name}: {e}"));
                let mut out = String::new();
                child
                    .stdout
                    .take()
                    .unwrap()
                    .read_to_string(&mut out)
                    .await
                    .unwrap();
                assert_eq!(out, "async-never\n", "{name}");
                assert!(child.wait().await.unwrap().success(), "{name}");
            });
        }
    }
}
