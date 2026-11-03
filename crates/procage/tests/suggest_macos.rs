//! From a denial to a grant on macOS, observed on the kernel: each kind of
//! denial gives the narrowest suggestion (or none by rule); applied, the
//! next spawn performs the operation, a neighbouring one stays denied, and
//! the diff of the two policies shows only the change.

#![cfg(target_os = "macos")]

#[path = "support/scratch.rs"]
mod scratch_support;
use scratch_support::Scratch;

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

use procage::macos::{Cage, CageOptions, Grants};
use procage::policy::explain::{Decider, Direction, PathSet, diff};
use procage::policy::{
    AbsPath, Access, Base, FsRule, FsTarget, HardDenyClass, LowerOptions, Policy, Target,
};
use procage::{DeniedBy, Suggestion, Violations, suggest};

static COUNTER: AtomicUsize = AtomicUsize::new(0);
/// The violation monitor is shared; cases take turns.
static TURN: Mutex<()> = Mutex::new(());

fn scratch(tag: &str) -> Scratch {
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    Scratch::at(std::env::temp_dir().join(format!("procage-sg-{}-{tag}-{n}", std::process::id())))
        .canonical()
}

fn abs(p: impl AsRef<Path>) -> AbsPath {
    AbsPath::new(p.as_ref().as_os_str().as_encoded_bytes()).unwrap()
}

/// A workspace `work` (writable, with `.git/hooks` and a `.env`) and a
/// sibling `outside` with two files.
struct Workspace {
    _root: Scratch,
    work: PathBuf,
    outside: PathBuf,
}

fn workspace(tag: &str) -> Workspace {
    let root = scratch(tag);
    let work = root.join("work");
    let outside = root.join("outside");
    std::fs::create_dir_all(work.join(".git/hooks")).unwrap();
    std::fs::create_dir_all(&outside).unwrap();
    std::fs::write(work.join(".env"), "SECRET=1").unwrap();
    std::fs::write(outside.join("f"), "f").unwrap();
    std::fs::write(outside.join("g"), "g").unwrap();
    Workspace {
        _root: root,
        work,
        outside,
    }
}

fn policy(ws: &Workspace) -> Policy {
    let mut p = Policy::default();
    p.base = Base::V3;
    p.process.fork = true;
    p.fs.push(FsRule::new(Access::Write, FsTarget::Subpath(abs(&ws.work))));
    p
}

/// Whether `script` succeeds under `/bin/sh` in `work`, and the record.
fn run(p: &Policy, ws: &Workspace, script: &str) -> (bool, Violations) {
    let cage = Cage::with_options(p, &CageOptions::default().with_violations())
        .unwrap_or_else(|e| panic!("{e}"));
    let mut cmd = Command::new("/bin/sh");
    cmd.args(["-c", script])
        .current_dir(&ws.work)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let mut child = cage.spawn(&mut cmd, &Grants::new()).unwrap();
    let ok = child.wait().unwrap().success();
    (ok, child.violations())
}

/// Denies `script`, takes the suggestion for the denial of `operation` on
/// `target`, checks it is `want`, applies it, and checks that `script`
/// then succeeds, that `neighbour` (if any) still fails, and that the diff
/// loosens and names only the change. Returns the new policy.
fn case(
    p: &Policy,
    ws: &Workspace,
    script: &str,
    operation: &str,
    target: &Path,
    want: &Suggestion,
    neighbour: Option<&str>,
) -> Policy {
    let (ok, record) = run(p, ws, script);
    assert!(!ok, "{script}: not denied");
    assert!(record.complete(), "{script}: lossy record {record:#?}");
    let target = target.to_str().unwrap();
    let denial = record
        .iter()
        .find(|v| v.operation.starts_with(operation) && v.target.as_deref() == Some(target))
        .unwrap_or_else(|| panic!("{script}: no {operation} {target} in {record:#?}"));
    let got = suggest(p, denial).unwrap_or_else(|| panic!("{script}: no suggestion"));
    assert_eq!(&got, want, "{script}");
    let new = got.apply(p);
    let (ok, _) = run(&new, ws, script);
    assert!(ok, "{script}: still denied after {got}");
    // The old policy still denies it: nothing changed a cage in place.
    assert!(!run(p, ws, script).0, "{script}: the old policy changed");
    if let Some(n) = neighbour {
        assert!(!run(&new, ws, n).0, "{n}: allowed after {got}");
    }
    let d = diff(p, &new, &[Target::MacOs], &LowerOptions::default()).unwrap();
    assert!(!d.is_empty(), "{got}: no difference");
    assert!(
        d.entries.iter().all(|e| e.direction == Direction::Loosens),
        "{got}: {d:#?}"
    );
    match &got {
        Suggestion::Allow(rule) | Suggestion::LeaveOut(rule) => {
            // The rule itself, and what comes with its path: the base's
            // metadata reads on the way to it (V2 and V3) and, for a
            // protect rule, the rename-anchors deny on its ancestors.
            let path = match &rule.target {
                FsTarget::Literal(p) | FsTarget::Subpath(p) => p.as_bytes().to_vec(),
                FsTarget::Glob(_) => unreachable!("suggestions are literal"),
            };
            let on_the_way = |e: &procage::policy::explain::DiffEntry| {
                matches!(
                    e.by,
                    Decider::Base(_) | Decider::HardDeny(HardDenyClass::RenameAnchors)
                ) && matches!(&e.paths, PathSet::Literal(b) | PathSet::Ancestors(b) if path.starts_with(b))
            };
            assert!(
                d.entries
                    .iter()
                    .all(|e| e.by == Decider::Rule(rule.clone()) || on_the_way(e)),
                "{got}: {d:#?}"
            );
            assert!(d.settings.is_empty(), "{got}: {d:#?}");
        }
        Suggestion::Waive(class) => {
            assert!(
                d.entries.iter().all(|e| e.by == Decider::HardDeny(*class)),
                "{got}: {d:#?}"
            );
        }
        _ => {}
    }
    new
}

/// Reading, writing (creating) and executing outside the policy give a
/// literal rule with that access; the sibling stays denied.
#[test]
fn a_denied_file_operation_suggests_exactly_that_path() {
    let _turn = TURN.lock().unwrap_or_else(|e| e.into_inner());
    let ws = workspace("files");
    let p = policy(&ws);
    let (f, g) = (ws.outside.join("f"), ws.outside.join("g"));
    let literal =
        |access, path: &Path| Suggestion::Allow(FsRule::new(access, FsTarget::Literal(abs(path))));
    case(
        &p,
        &ws,
        &format!("cat '{}'", f.display()),
        "file-read",
        &f,
        &literal(Access::Read, &f),
        Some(&format!("cat '{}'", g.display())),
    );
    let new = ws.outside.join("new");
    case(
        &p,
        &ws,
        &format!("echo x > '{}'", new.display()),
        "file-write",
        &new,
        &literal(Access::Write, &new),
        Some(&format!("echo x > '{}'", g.display())),
    );
    // A script: a copied system program may not launch outside its
    // location at all (launch constraints).
    let prog = ws.outside.join("prog");
    std::fs::write(&prog, "#!/bin/sh\necho hi\n").unwrap();
    std::fs::set_permissions(
        &prog,
        <std::fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o755),
    )
    .unwrap();
    case(
        &p,
        &ws,
        &format!("'{}' hi", prog.display()),
        "process-exec",
        &prog,
        &literal(Access::Exec, &prog),
        None,
    );
}

/// A denied connect to a Unix socket suggests that socket's path.
#[test]
fn a_denied_socket_connect_suggests_the_socket() {
    let _turn = TURN.lock().unwrap_or_else(|e| e.into_inner());
    let ws = workspace("socket");
    let socket = ws.outside.join("s.sock");
    let listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            drop(stream);
        }
    });
    case(
        &policy(&ws),
        &ws,
        &format!("/usr/bin/nc -U '{}' </dev/null", socket.display()),
        "network-outbound",
        &socket,
        &Suggestion::UnixSocket(abs(&socket)),
        None,
    );
}

/// A protect or hide rule, and a hard-deny class, give their removal or
/// waiver, marked as weakening; the new run's receipt lists the waiver.
#[test]
fn a_protection_suggests_its_removal_marked_as_weakening() {
    let _turn = TURN.lock().unwrap_or_else(|e| e.into_inner());
    let ws = workspace("weaken");
    let mut p = policy(&ws);
    let locked = ws.work.join("locked");
    std::fs::create_dir_all(&locked).unwrap();
    let protect = FsRule::new(Access::Protect, FsTarget::Subpath(abs(&locked)));
    let hidden = ws.work.join("hidden");
    std::fs::write(&hidden, "h").unwrap();
    let hide = FsRule::new(Access::Hide, FsTarget::Literal(abs(&hidden)));
    p.fs.extend([protect.clone(), hide.clone()]);

    let target = locked.join("f");
    let s = Suggestion::LeaveOut(protect);
    assert!(s.weakens());
    case(
        &p,
        &ws,
        &format!("echo x > '{}'", target.display()),
        "file-write",
        &target,
        &s,
        None,
    );

    let s = Suggestion::LeaveOut(hide);
    case(
        &p,
        &ws,
        &format!("cat '{}'", hidden.display()),
        "file-read",
        &hidden,
        &s,
        None,
    );

    let hook = ws.work.join(".git/hooks/pre-commit");
    let s = Suggestion::Waive(HardDenyClass::TrustHandoff);
    assert!(s.weakens());
    let new = case(
        &p,
        &ws,
        &format!("echo x > '{}'", hook.display()),
        "file-write",
        &hook,
        &s,
        None,
    );
    let cage = Cage::new(&new).unwrap();
    let mut child = cage
        .spawn(
            Command::new("/usr/bin/true").stdin(Stdio::null()),
            &Grants::new(),
        )
        .unwrap();
    child.wait().unwrap();
    let receipt = child.receipt().unwrap();
    assert!(
        receipt.waivers.contains(&HardDenyClass::TrustHandoff),
        "{:?}",
        receipt.waivers
    );
}

/// A secret is never suggested: listing `~/Library/Keychains` (which every
/// account has; nothing is read or changed) gives nothing.
#[test]
fn a_secret_suggests_nothing() {
    let _turn = TURN.lock().unwrap_or_else(|e| e.into_inner());
    let ws = workspace("secret");
    let p = policy(&ws);
    let home = std::fs::canonicalize(std::env::var_os("HOME").expect("HOME")).unwrap();
    let key = home.join("Library/Keychains");
    assert!(key.is_dir(), "this case needs {}", key.display());
    let (ok, record) = run(&p, &ws, &format!("ls '{}'", key.display()));
    assert!(!ok);
    let target = key.to_str().unwrap();
    let denial = record
        .iter()
        .find(|v| v.target.as_deref() == Some(target))
        .unwrap_or_else(|| panic!("no denial of {target}: {record:#?}"));
    assert_eq!(denial.denied_by, DeniedBy::HardDeny(HardDenyClass::Secrets));
    assert_eq!(suggest(&p, denial), None);
}
