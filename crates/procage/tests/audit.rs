//! The handoff audit: what a run left behind in its writable trees. The same
//! tests run on macOS and on Linux.

#![cfg(any(target_os = "macos", target_os = "linux"))]

#[path = "support/scratch.rs"]
mod scratch_support;
use scratch_support::Scratch;

use std::os::unix::ffi::OsStringExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use procage::native::{Cage, CageOptions, Grants};
use procage::policy::{AbsPath, Access, FsRule, FsTarget, HardDenyClass, Policy, presets};
use procage::{HandoffKind, LinkAudit};

fn workspace(name: &str) -> Scratch {
    let d = Scratch::at(
        std::env::temp_dir().join(format!("procage-audit-{name}-{}", std::process::id())),
    )
    .canonical();
    std::fs::create_dir_all(d.join(".git")).unwrap();
    std::fs::write(d.join(".git/config"), "[core]\n").unwrap();
    d
}

/// Writes `ws`; the trust-handoff class is waived so the run can leave
/// what the audit must find.
fn policy(ws: &Path) -> Policy {
    let mut p = presets::minimal::v3();
    p.process.fork = true;
    p.fs.push(FsRule::new(
        Access::Write,
        FsTarget::Subpath(AbsPath::new(ws.to_str().unwrap()).unwrap()),
    ));
    p.waive.insert(HardDenyClass::TrustHandoff);
    p
}

fn sh(ws: &Path, script: &str) -> Command {
    let mut c = Command::new("/bin/sh");
    c.args(["-c", script])
        .current_dir(ws)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    c
}

#[test]
fn what_a_run_left_behind_is_listed_once() {
    let ws = workspace("left");
    let options = CageOptions::default().with_handoff_audit();
    let cage = Cage::with_options(&policy(&ws), &options).unwrap();
    let script = "mkdir -p .vscode && echo '{}' > .vscode/settings.json && \
        echo '[hooks]' >> .git/config && ln -s /etc/passwd build && \
        mkdir -p sub/.git && echo x > plain.txt && printf x > \"$(printf '.vscode/a\\nb')\"";
    let mut child = cage.spawn(&mut sh(&ws, script), &Grants::new()).unwrap();
    assert!(child.audit().is_none() || child.try_wait().unwrap().is_some());
    assert!(child.wait().unwrap().success());
    let audit = child.audit().unwrap();
    assert!(audit.handoff_complete);
    let found = audit.handoff.expect("the handoff audit ran");
    let has = |p: &str, kind: &HandoffKind| {
        found
            .iter()
            .filter(|f| f.path == ws.join(p) && &f.kind == kind)
            .count()
    };
    assert_eq!(
        has(".vscode/settings.json", &HandoffKind::Created),
        1,
        "{found:?}"
    );
    assert_eq!(has(".git/config", &HandoffKind::Modified), 1, "{found:?}");
    assert_eq!(has("sub/.git", &HandoffKind::Repository), 1, "{found:?}");
    assert_eq!(
        has(
            "build",
            &HandoffKind::Link {
                target: PathBuf::from("/etc/passwd")
            }
        ),
        1,
        "{found:?}"
    );
    assert!(
        !found.iter().any(|f| f.path == ws.join("plain.txt")),
        "{found:?}"
    );
    let odd = found
        .iter()
        .find(|f| f.path == ws.join(".vscode/a\nb"))
        .expect("a name with a newline, as bytes");
    assert!(odd.to_string().contains("a\\nb"), "{odd}");
}

#[test]
fn a_quiet_run_is_complete_and_empty() {
    let ws = workspace("quiet");
    let options = CageOptions::default().with_handoff_audit();
    let cage = Cage::with_options(&policy(&ws), &options).unwrap();
    let mut child = cage
        .spawn(&mut sh(&ws, "echo x > plain.txt"), &Grants::new())
        .unwrap();
    child.wait().unwrap();
    let audit = child.audit().unwrap();
    assert_eq!(audit.mode, LinkAudit::Refuse);
    assert!(audit.links.is_empty() && audit.links_complete);
    assert_eq!(audit.handoff, Some(vec![]));
    assert!(audit.handoff_complete);
}

#[test]
fn past_the_walk_limit_the_audit_is_incomplete() {
    let ws = workspace("limit");
    for i in 0..20 {
        std::fs::write(ws.join(format!("f{i}")), "x").unwrap();
    }
    let options = CageOptions::default()
        .with_handoff_audit()
        .with_walk_limit(5);
    let cage = Cage::with_options(&policy(&ws), &options).unwrap();
    let mut child = cage.spawn(&mut sh(&ws, "true"), &Grants::new()).unwrap();
    child.wait().unwrap();
    assert!(!child.audit().unwrap().handoff_complete);
}

#[test]
fn without_the_option_nothing_is_walked() {
    let ws = workspace("off");
    let cage = Cage::new(&policy(&ws)).unwrap();
    let mut child = cage
        .spawn(
            &mut sh(&ws, "mkdir -p .vscode && echo x > .vscode/x"),
            &Grants::new(),
        )
        .unwrap();
    child.wait().unwrap();
    assert_eq!(child.audit().unwrap().handoff, None);
}

/// The receipt carries the audit's counts; its paths only with the policy.
#[test]
fn the_receipt_counts_the_findings() {
    let ws = workspace("receipt");
    let script = "mkdir -p .vscode && echo x > .vscode/x";
    for include in [false, true] {
        let mut options = CageOptions::default().with_handoff_audit();
        if include {
            options = options.with_policy_in_receipt();
        }
        let _ = std::fs::remove_dir_all(ws.join(".vscode"));
        let cage = Cage::with_options(&policy(&ws), &options).unwrap();
        let mut child = cage.spawn(&mut sh(&ws, script), &Grants::new()).unwrap();
        child.wait().unwrap();
        let receipt = child.receipt().unwrap();
        assert_eq!(receipt.audit.links_mode, "refuse");
        // The `.vscode` directory and the file in it, both created.
        assert_eq!(receipt.audit.handoff, Some(2));
        assert_eq!(receipt.audit.paths.is_some(), include);
        let json = receipt.to_json();
        let mut value: serde_json::Value = serde_json::from_str(&json).unwrap();
        value.as_object_mut().unwrap().remove("policy");
        value["audit"].as_object_mut().unwrap().remove("paths");
        assert!(!value.to_string().contains(".vscode"), "{value}");
    }
}

/// The receipt says the link check's mode: report lists, off is not
/// complete.
#[test]
fn the_receipt_says_the_link_check_mode() {
    let ws = workspace("modes");
    // A hidden file in a readable tree beside the workspace (tier T2 cannot
    // hide inside a writable tree), with a second name next to it.
    let other = ws
        .join("../")
        .canonicalize()
        .unwrap()
        .join(format!("procage-audit-modes-other-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&other);
    std::fs::create_dir_all(&other).unwrap();
    std::fs::write(other.join(".env"), "x").unwrap();
    std::fs::hard_link(other.join(".env"), other.join("alias")).unwrap();
    let mut p = policy(&ws);
    let abs = |p: &Path| AbsPath::new(p.to_str().unwrap()).unwrap();
    p.fs.push(FsRule::new(Access::Read, FsTarget::Subpath(abs(&other))));
    p.fs.push(FsRule::new(
        Access::Hide,
        FsTarget::Literal(abs(&other.join(".env"))),
    ));
    for (mode, name, links, complete) in [
        (LinkAudit::Report, "report", 1, true),
        (LinkAudit::Off, "off", 0, false),
    ] {
        let lower = procage::policy::LowerOptions::default()
            .accept_spawn_snapshot()
            .allow(procage::policy::Construct::FsLiteral);
        let options = CageOptions::default()
            .with_link_audit(mode)
            .with_lower(lower);
        let cage = Cage::with_options(&p, &options).unwrap();
        let mut child = cage.spawn(&mut sh(&ws, "true"), &Grants::new()).unwrap();
        child.wait().unwrap();
        let receipt = child.receipt().unwrap();
        assert_eq!(receipt.audit.links_mode, name);
        assert_eq!(receipt.audit.links, links, "{name}");
        assert_eq!(receipt.audit.links_complete, complete, "{name}");
    }
    let _ = std::fs::remove_dir_all(&other);
}

/// Paths keep their exact bytes through a receipt: an escape character
/// everywhere, and on Linux a name that is not UTF-8.
#[test]
fn paths_round_trip_exactly() {
    use std::os::unix::ffi::OsStrExt;
    let ws = workspace("bytes");
    let options = CageOptions::default()
        .with_handoff_audit()
        .with_policy_in_receipt();
    let cage = Cage::with_options(&policy(&ws), &options).unwrap();
    let mut script =
        String::from("mkdir -p .vscode && printf x > \"$(printf '.vscode/esc\\033x')\"");
    if cfg!(target_os = "linux") {
        script.push_str(" && printf x > \"$(printf '.vscode/raw\\377')\"");
    }
    let mut child = cage.spawn(&mut sh(&ws, &script), &Grants::new()).unwrap();
    child.wait().unwrap();
    let receipt = child.receipt().unwrap();
    let back = procage::Receipt::from_json(&receipt.to_json()).unwrap();
    assert_eq!(back, receipt);
    let paths = receipt.audit.paths.clone().unwrap();
    let esc = ws.join(".vscode/esc\u{1b}x");
    assert!(
        paths.contains(&procage::ReceiptPath::from(esc.as_path())),
        "{paths:?}"
    );
    if cfg!(target_os = "linux") {
        let mut raw = ws.join(".vscode").into_os_string().into_vec();
        raw.extend_from_slice(b"/raw\xff");
        let raw = PathBuf::from(std::ffi::OsString::from_vec(raw));
        assert!(
            paths.contains(&procage::ReceiptPath::Bytes(
                raw.as_os_str().as_bytes().to_vec()
            )),
            "{paths:?}"
        );
    }
}
