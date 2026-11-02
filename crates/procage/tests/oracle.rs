//! The differential oracle: `Cage::explain` against the kernel.
//!
//! For every preset and a policy with every rule kind, a generated tree of
//! files is asked about twice: once of the cage's explainer, once of the
//! kernel, by a caged child that opens every file for reading and for
//! writing (nothing is written) and by caged spawns of copies of `true`.
//! Any disagreement, and any kernel result that is neither success nor a
//! refusal, fails the suite with the question.
//!
//! The policy under test is the preset plus exec of this test binary, and
//! that is the policy explained. Run inside another sandbox, the cages
//! cannot be prepared and the suite fails.

#![cfg(any(target_os = "macos", target_os = "linux"))]

#[path = "support/scratch.rs"]
mod scratch;

use std::collections::BTreeSet;
use std::io::{BufRead, Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use procage::native::{Cage, CageOptions, Grants, SpawnError};
use procage::policy::explain::{Answer, Decider, Decision, MODELLED, Op};
use procage::policy::{
    AbsPath, Access, Base, FsRule, FsTarget, Grant, GrantName, HardDenyClass, Policy, presets,
};
use scratch::Scratch;

#[cfg(target_os = "macos")]
const TRUE: &str = "/usr/bin/true";
#[cfg(target_os = "linux")]
const TRUE: &str = "/bin/true";

/// The minimum number of read and write questions per policy and target.
const MIN_QUESTIONS: usize = 1000;

fn abs(p: impl AsRef<Path>) -> AbsPath {
    use std::os::unix::ffi::OsStrExt;
    AbsPath::new(p.as_ref().as_os_str().as_bytes()).unwrap()
}

fn exe() -> PathBuf {
    std::fs::canonicalize(std::env::current_exe().unwrap()).unwrap()
}

/// The caged child: reads `R path` and `W path` lines from stdin and prints
/// the errno of opening each (0 for success).
#[test]
fn oracle_child() {
    if std::env::var_os("PROCAGE_ORACLE_CHILD").is_none() {
        return;
    }
    let stdin = std::io::stdin();
    let mut out = std::io::stdout().lock();
    for line in stdin.lock().lines() {
        let line = line.unwrap();
        let (op, path) = line.split_at(2);
        let mut options = std::fs::OpenOptions::new();
        if op == "W " {
            options.write(true);
        } else {
            options.read(true);
        }
        let errno = match options.open(path) {
            Ok(_) => 0,
            Err(e) => e.raw_os_error().unwrap_or(-1),
        };
        writeln!(out, "\nprocage-errno: {errno}").unwrap();
    }
}

/// The files of the generated tree.
struct Tree {
    _dir: Scratch,
    base: PathBuf,
    work: PathBuf,
    granted: PathBuf,
    home: PathBuf,
    data: PathBuf,
    /// Files asked about for reading and writing.
    files: Vec<PathBuf>,
    /// Executables asked about for exec.
    programs: Vec<PathBuf>,
}

fn file(path: &Path) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, b"x").unwrap();
}

fn tree(name: &str) -> Tree {
    let dir = Scratch::at(
        std::env::temp_dir().join(format!("procage-oracle-{name}-{}", std::process::id())),
    );
    let base = std::fs::canonicalize(&*dir).unwrap();
    let (work, outside, granted, home, data) = (
        base.join("work"),
        base.join("outside"),
        base.join("granted"),
        base.join("home"),
        base.join("data"),
    );
    let mut files = Vec::new();
    let mut add = |p: PathBuf| {
        file(&p);
        files.push(p);
    };
    for i in 0..200 {
        add(work.join(format!("src/m{}/f{i}.rs", i % 7)));
        add(outside.join(format!("d{}/f{i}", i % 5)));
    }
    for i in 0..40 {
        add(work.join(format!("ro/f{i}")));
        add(work.join(format!("secret/f{i}")));
        add(granted.join(format!("f{i}")));
        add(data.join(format!("pub/f{i}")));
        add(data.join(format!("secret/f{i}")));
    }
    for i in 0..10 {
        add(work.join(format!(".git/hooks/h{i}")));
        add(work.join(format!(".git/objects/o{i}")));
    }
    for name in [
        ".git/config",
        ".envrc",
        ".vscode/settings.json",
        ".cargo/config.toml",
        "a*[b",
    ] {
        add(work.join(name));
    }
    for rel in [
        ".ssh/id_ed25519",
        ".ssh/config",
        ".aws/credentials",
        ".bashrc",
        ".config/autostart/x.desktop",
        ".config/systemd/user/x.service",
        "notes.txt",
    ] {
        add(home.join(rel));
    }
    let mut programs = Vec::new();
    for p in [
        work.join("bin/tool"),
        work.join("bin/suid"),
        work.join(".git/hooks/pre-commit"),
        work.join("secret/tool"),
        outside.join("tool"),
        granted.join("tool"),
    ] {
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::copy(TRUE, &p).unwrap();
        let mode = if p.ends_with("suid") { 0o4755 } else { 0o755 };
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(mode)).unwrap();
        programs.push(p);
    }
    programs.push(PathBuf::from(TRUE));
    Tree {
        _dir: dir,
        base,
        work,
        granted,
        home,
        data,
        files,
        programs,
    }
}

/// Paths of the system, read only.
fn system_files() -> Vec<PathBuf> {
    let list: &[&str] = if cfg!(target_os = "macos") {
        &[
            "/usr/bin/true",
            "/usr/lib/dyld",
            "/bin/sh",
            "/private/etc/hosts",
            "/System/Library/CoreServices/SystemVersion.plist",
            "/Library/Preferences/.GlobalPreferences.plist",
        ]
    } else {
        &[
            "/bin/true",
            "/bin/sh",
            "/etc/hosts",
            "/etc/passwd",
            "/usr/lib/os-release",
        ]
    };
    list.iter()
        .map(PathBuf::from)
        .filter(|p| std::fs::metadata(p).is_ok())
        .map(|p| std::fs::canonicalize(p).unwrap())
        .collect()
}

/// A target this lane can run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
enum Lane {
    MacOs,
    Linux(procage::policy::Tier),
}

impl std::fmt::Display for Lane {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Lane::MacOs => f.write_str("macOS"),
            Lane::Linux(t) => write!(f, "Linux {t}"),
        }
    }
}

fn lanes() -> Vec<Lane> {
    #[cfg(target_os = "macos")]
    {
        vec![Lane::MacOs]
    }
    #[cfg(target_os = "linux")]
    {
        use procage::policy::Tier;
        match procage::linux::probe().tier {
            Some(Tier::T1) => vec![Lane::Linux(Tier::T1), Lane::Linux(Tier::T2)],
            Some(Tier::T2) => vec![Lane::Linux(Tier::T2)],
            None => panic!("this host cannot confine a child"),
        }
    }
}

fn options(lane: Lane, tree: &Tree) -> CageOptions {
    let options = CageOptions::default();
    match lane {
        Lane::MacOs => {
            let _ = tree;
            options
        }
        #[cfg(target_os = "linux")]
        Lane::Linux(tier) => options.with_tier(tier).with_home(&tree.home),
        #[cfg(not(target_os = "linux"))]
        Lane::Linux(_) => unreachable!(),
    }
}

/// `p` with exec of this test binary.
fn runnable(mut p: Policy) -> Policy {
    let exe = exe();
    let target = if cfg!(target_os = "macos") {
        FsTarget::Literal(abs(&exe))
    } else {
        FsTarget::Subpath(abs(exe.parent().unwrap()))
    };
    p.fs.push(FsRule::new(Access::Exec, target));
    p
}

/// A policy with every rule kind the lane can express.
fn kinds(lane: Lane, tree: &Tree) -> Policy {
    let mut p = Policy::default();
    p.base = Base::V3;
    p.fs.push(FsRule::new(
        Access::Write,
        FsTarget::Subpath(abs(&tree.work)),
    ));
    p.fs.push(FsRule::new(
        Access::Exec,
        FsTarget::Subpath(abs(tree.work.join("bin"))),
    ));
    let t2 = matches!(lane, Lane::Linux(procage::policy::Tier::T2));
    if t2 {
        // T2 cannot cover names under a writable tree; it reaches the
        // secrets class through a readable home, and hides piecewise.
        p.waive.insert(HardDenyClass::TrustHandoff);
        p.fs.push(FsRule::new(
            Access::Read,
            FsTarget::Subpath(abs(&tree.home)),
        ));
        p.fs.push(FsRule::new(
            Access::Read,
            FsTarget::Subpath(abs(&tree.data)),
        ));
        p.fs.push(FsRule::new(
            Access::Hide,
            FsTarget::Subpath(abs(tree.data.join("secret"))),
        ));
    } else {
        p.fs.push(FsRule::new(
            Access::Protect,
            FsTarget::Subpath(abs(tree.work.join("ro"))),
        ));
        p.fs.push(FsRule::new(
            Access::Hide,
            FsTarget::Subpath(abs(tree.work.join("secret"))),
        ));
        p.fs.push(FsRule::new(
            Access::Read,
            FsTarget::Subpath(abs(&tree.home)),
        ));
    }
    p.grants.push(Grant {
        name: GrantName::new("out").unwrap(),
        access: Access::Write,
    });
    runnable(p)
}

fn policies(lane: Lane, tree: &Tree) -> Vec<(String, Policy)> {
    use presets::*;
    let w = abs(&tree.work);
    let mut out: Vec<(String, Policy)> = vec![
        ("minimal v1".into(), minimal::v1()),
        ("minimal v2".into(), minimal::v2()),
        ("minimal v3".into(), minimal::v3()),
        ("agent_readonly v1".into(), agent_readonly::v1(&w)),
        ("agent_readonly v2".into(), agent_readonly::v2(&w)),
        ("agent_readonly v3".into(), agent_readonly::v3(&w)),
        ("agent_workspace v1".into(), agent_workspace::v1(&w)),
        ("agent_workspace v2".into(), agent_workspace::v2(&w)),
        ("agent_workspace v3".into(), agent_workspace::v3(&w)),
        ("build v1".into(), build::v1(&w)),
        ("build v2".into(), build::v2(&w)),
        ("build v3".into(), build::v3(&w)),
    ];
    out = out.into_iter().map(|(n, p)| (n, runnable(p))).collect();
    out.push(("rule kinds".into(), kinds(lane, tree)));
    out
}

/// The cage for `policy` as a user would fit it: approximations accepted
/// by name, hard-deny classes the target cannot express waived; `None` when
/// anything else is missing (loopback networking on Linux).
fn fitted(lane: Lane, tree: &Tree, name: &str, mut policy: Policy) -> Option<(Cage, Policy)> {
    let mut options = options(lane, tree);
    for _ in 0..4 {
        let gaps = match Cage::with_options(&policy, &options) {
            Ok(cage) => return Some((cage, policy)),
            Err(SpawnError::Lower(procage::policy::LowerError::Gaps(gaps))) => gaps,
            Err(e) => panic!("{lane} {name}: {e}"),
        };
        for gap in gaps {
            match (
                gap.kind,
                HardDenyClass::ALL
                    .iter()
                    .find(|c| procage::policy::Construct::of_class(**c) == gap.construct),
            ) {
                (procage::policy::GapKind::Approximation, _) => {
                    options.lower.allow_degrade.insert(gap.construct);
                }
                (_, Some(class)) => {
                    policy.waive.insert(*class);
                }
                _ => {
                    eprintln!("{lane} {name}: not expressible ({})", gap.construct);
                    return None;
                }
            }
        }
    }
    panic!("{lane} {name}: did not fit");
}

/// The kernel's answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kernel {
    Allowed,
    Denied,
    Unresolved(i32),
}

fn classify(errno: i32) -> Kernel {
    match errno {
        0 => Kernel::Allowed,
        libc::EACCES | libc::EPERM | libc::EROFS => Kernel::Denied,
        other => Kernel::Unresolved(other),
    }
}

/// The rule kinds of an answer, for coverage: on T1 a class decides
/// through its cover, which is both.
fn kinds_of(answer: &Answer) -> Vec<&'static str> {
    let mut out = vec![kind(answer)];
    if answer.caveat == Some(procage::policy::explain::SPAWN_COVER) {
        out.push("T1 cover");
    }
    out
}

fn kind(answer: &Answer) -> &'static str {
    match &answer.by {
        Decider::Rule(r) if r.access == Access::Protect => "protect",
        Decider::Rule(r) if r.access == Access::Hide => "hide",
        Decider::Rule(_) => "allow",
        Decider::Grant(_) => "grant",
        Decider::HardDeny(_) => "hard-deny class",
        Decider::Base(_) => "base",
        Decider::Default => "default",
        Decider::Layer => "layer",
        Decider::Setting(_) => "setting",
        Decider::Unhandled => "unhandled",
        Decider::None => "none",
    }
}

struct Asked {
    question: String,
    answer: Answer,
    kernel: Kernel,
}

/// The disagreements among `asked`, each naming the question.
fn disagreements(asked: &[Asked]) -> Vec<String> {
    asked
        .iter()
        .filter_map(|a| {
            let agree = matches!(
                (a.answer.decision, a.kernel),
                (Decision::Allowed, Kernel::Allowed) | (Decision::Denied, Kernel::Denied)
            );
            (!agree).then(|| {
                format!(
                    "{} [{}]: explain {:?} by {:?}, kernel {:?}",
                    a.question,
                    kinds_of(&a.answer).join("] ["),
                    a.answer.decision,
                    a.answer.by,
                    a.kernel
                )
            })
        })
        .collect()
}

/// Asks the kernel through one caged child.
fn open_all(cage: &Cage, grants: &Grants, questions: &[(Op, PathBuf)]) -> Vec<Kernel> {
    let mut cmd = Command::new(exe());
    cmd.args(["--exact", "oracle_child", "--nocapture", "--test-threads=1"])
        .env("PROCAGE_ORACLE_CHILD", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = cage
        .spawn(&mut cmd, grants)
        .expect("spawn the oracle child");
    let mut input = String::new();
    for (op, path) in questions {
        let tag = if *op == Op::Write { "W" } else { "R" };
        input.push_str(&format!("{tag} {}\n", path.display()));
    }
    let mut stdin = child.stdin.take().unwrap();
    let writer = std::thread::spawn(move || stdin.write_all(input.as_bytes()));
    let mut out = String::new();
    child
        .stdout
        .take()
        .unwrap()
        .read_to_string(&mut out)
        .unwrap();
    let mut err = String::new();
    child
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut err)
        .unwrap();
    writer.join().unwrap().unwrap();
    let status = child.wait().unwrap();
    let errnos: Vec<i32> = out
        .lines()
        .filter_map(|l| l.split("procage-errno: ").nth(1))
        .map(|n| n.trim().parse().unwrap())
        .collect();
    assert_eq!(
        errnos.len(),
        questions.len(),
        "oracle child ({status:?}): {err}"
    );
    errnos.into_iter().map(classify).collect()
}

/// Asks the kernel to execute `program` in a cage.
fn exec(cage: &Cage, grants: &Grants, program: &Path) -> Kernel {
    let mut cmd = Command::new(program);
    cmd.stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    match cage.spawn(&mut cmd, grants) {
        Ok(mut child) => match child.wait() {
            Ok(s) if s.success() => Kernel::Allowed,
            Ok(s) => Kernel::Unresolved(s.code().unwrap_or(-1)),
            Err(e) => Kernel::Unresolved(e.raw_os_error().unwrap_or(-1)),
        },
        Err(SpawnError::Io(e)) => classify(e.raw_os_error().unwrap_or(-1)),
        Err(SpawnError::Apply { errno, .. }) => classify(errno),
        Err(e) => panic!("spawning {}: {e}", program.display()),
    }
}

fn required_kinds(lane: Lane) -> &'static [&'static str] {
    match lane {
        Lane::MacOs => &[
            "allow",
            "protect",
            "hide",
            "hard-deny class",
            "base",
            "default",
            "grant",
        ],
        Lane::Linux(procage::policy::Tier::T1) => &[
            "allow",
            "protect",
            "hide",
            "hard-deny class",
            "base",
            "default",
            "grant",
            "T1 cover",
        ],
        Lane::Linux(_) => &[
            "allow",
            "hide",
            "hard-deny class",
            "base",
            "default",
            "grant",
        ],
    }
}

#[test]
fn explain_agrees_with_the_kernel() {
    let tree = tree("agree");
    let system = system_files();
    let mut failures = Vec::new();
    for lane in lanes() {
        let mut reached: BTreeSet<&'static str> = BTreeSet::new();
        let mut ops: BTreeSet<Op> = BTreeSet::new();
        let mut all: Vec<Asked> = Vec::new();
        for (name, policy) in policies(lane, &tree) {
            let Some((cage, policy)) = fitted(lane, &tree, &name, policy) else {
                continue;
            };
            let grants = if policy.grants.iter().any(|g| g.name.as_str() == "out") {
                Grants::new().bind("out", &tree.granted)
            } else {
                Grants::new()
            };
            let mut questions: Vec<(Op, PathBuf)> = Vec::new();
            for f in &tree.files {
                questions.push((Op::Read, f.clone()));
                questions.push((Op::Write, f.clone()));
            }
            for f in &system {
                questions.push((Op::Read, f.clone()));
            }
            questions.push((Op::Write, PathBuf::from("/dev/null")));
            assert!(questions.len() >= MIN_QUESTIONS, "{}", questions.len());
            let kernel = open_all(&cage, &grants, &questions);
            let mut asked: Vec<Asked> = Vec::new();
            for ((op, path), k) in questions.iter().zip(kernel) {
                let answer = cage.explain(op.clone(), path, &grants).unwrap();
                asked.push(Asked {
                    question: format!("{lane} {name}: {op} {}", path.display()),
                    answer,
                    kernel: k,
                });
            }
            for program in &tree.programs {
                let answer = cage.explain(Op::Exec, program, &grants).unwrap();
                asked.push(Asked {
                    question: format!("{lane} {name}: exec {}", program.display()),
                    answer,
                    kernel: exec(&cage, &grants, program),
                });
            }
            for a in &asked {
                reached.extend(kinds_of(&a.answer));
            }
            ops.extend(questions.iter().map(|(op, _)| op.clone()));
            ops.insert(Op::Exec);
            eprintln!("{lane} {name}: {} questions", asked.len());
            failures.extend(disagreements(&asked));
            all.extend(asked);
        }
        for k in required_kinds(lane) {
            if !reached.contains(k) {
                failures.push(format!("{lane}: no question reached {k}"));
            }
        }
        assert_eq!(
            ops,
            MODELLED.iter().cloned().collect(),
            "{lane}: covered operations"
        );
        // A wrong evaluator is caught: flipping the answers of any one kind
        // leaves disagreements that name it.
        for k in &reached {
            let flipped: Vec<Asked> = all
                .iter()
                .filter(|a| kinds_of(&a.answer).contains(k))
                .map(|a| Asked {
                    question: a.question.clone(),
                    answer: Answer {
                        decision: match a.answer.decision {
                            Decision::Allowed => Decision::Denied,
                            _ => Decision::Allowed,
                        },
                        ..a.answer.clone()
                    },
                    kernel: a.kernel,
                })
                .collect();
            let found = disagreements(&flipped);
            assert!(
                found.iter().any(|d| d.contains(&format!("[{k}]"))),
                "{lane}: flipping {k} went unnoticed"
            );
        }
    }
    let _ = &tree.base;
    assert!(
        failures.is_empty(),
        "{} disagreements:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

/// The proven operations the explain page lists are exactly the modelled
/// ones.
#[test]
fn the_docs_list_the_proven_operations() {
    let page = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../site/content/docs/explain.md"),
    )
    .unwrap();
    let listed: Vec<String> = page
        .lines()
        .filter_map(|l| l.strip_prefix("| `"))
        .filter_map(|l| l.split('`').next())
        .map(String::from)
        .collect();
    let modelled: Vec<String> = MODELLED.iter().map(|op| op.to_string()).collect();
    assert_eq!(listed, modelled);
    for l in page.lines().filter(|l| l.starts_with("| `")) {
        assert_eq!(l.matches("proven").count(), 3, "{l}");
    }
}

/// A question through a symbolic link is about the file it resolves to.
#[test]
fn explain_follows_links() {
    let tree = tree("links");
    let lane = lanes()[0];
    let (cage, _) = fitted(lane, &tree, "rule kinds", kinds(lane, &tree)).unwrap();
    let hidden = if matches!(lane, Lane::Linux(procage::policy::Tier::T2)) {
        tree.data.join("secret/f0")
    } else {
        tree.work.join("secret/f0")
    };
    let link = tree.work.join("src/link");
    std::os::unix::fs::symlink(&hidden, &link).unwrap();
    let grants = Grants::new().bind("out", &tree.granted);
    let through = cage.explain(Op::Read, &link, &grants).unwrap();
    let direct = cage.explain(Op::Read, &hidden, &grants).unwrap();
    assert_eq!(through, direct);
    assert_eq!(through.decision, Decision::Denied);
    assert!(
        matches!(&through.by, Decider::Rule(r) if r.access == Access::Hide),
        "{through:?}"
    );
}
