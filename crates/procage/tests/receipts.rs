//! Receipts: what a run's receipt holds, how it reads back, and what it never
//! holds. The same tests run on macOS and on Linux (each tier the host gives).

#![cfg(any(target_os = "macos", target_os = "linux"))]

#[path = "support/scratch.rs"]
mod scratch_support;
use scratch_support::Scratch;

use std::process::{Command, Stdio};
use std::time::Duration;

use procage::native::{Cage, CageOptions, Grants};
use procage::policy::{
    AbsPath, Access, FsRule, FsTarget, Grant, GrantName, HardDenyClass, Policy, presets,
};
use procage::{Receipt, ReceiptBackend, ReceiptCoverage, ReceiptError, policy_digest};

fn scratch(name: &str) -> Scratch {
    Scratch::at(std::env::temp_dir().join(format!("procage-rcpt-{name}-{}", std::process::id())))
        .canonical()
}

fn sh(script: &str) -> Command {
    let mut c = Command::new("/bin/sh");
    c.args(["-c", script])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    c
}

fn run(policy: &Policy, options: &CageOptions, command: &mut Command, grants: &Grants) -> Receipt {
    let cage = Cage::with_options(policy, options).unwrap_or_else(|e| panic!("cage: {e}"));
    let mut child = cage.spawn(command, grants).unwrap();
    child.wait().unwrap();
    child.receipt().expect("a receipt once the child exited")
}

#[test]
fn a_receipt_names_the_cage_and_the_exit() {
    let policy = presets::minimal::v3();
    let receipt = run(
        &policy,
        &CageOptions::default(),
        &mut sh("exit 3"),
        &Grants::new(),
    );
    assert_eq!(receipt.version, 1);
    assert_eq!(receipt.procage, env!("CARGO_PKG_VERSION"));
    assert_eq!(receipt.policy_digest, policy_digest(&policy));
    assert!(receipt.policy_digest.starts_with("sha256:"));
    assert_eq!(receipt.policy_digest.len(), "sha256:".len() + 64);
    assert_eq!(receipt.preset, policy.preset);
    assert_eq!(receipt.base, policy.base);
    assert_eq!(receipt.exit.code, Some(3));
    assert_eq!(receipt.exit.signal, None);
    assert!(!receipt.exit.ended_by_caller);
    assert!(receipt.enforced_as_written, "{receipt:?}");
    assert_eq!(receipt.violations.coverage, ReceiptCoverage::Off);
    assert_eq!(receipt.violations.count, None);
    match &receipt.backend {
        #[cfg(target_os = "macos")]
        ReceiptBackend::MacOs {
            apply,
            os_release,
            os_build,
        } => {
            assert_eq!(apply, "path-a");
            assert!(os_release.contains('.'), "{os_release}");
            assert!(!os_build.is_empty());
        }
        #[cfg(target_os = "linux")]
        ReceiptBackend::Linux {
            tier,
            landlock_abi,
            kernel,
            ..
        } => {
            assert!(tier == "T1" || tier == "T2", "{tier}");
            assert!(*landlock_abi >= 1);
            assert!(!kernel.is_empty() && kernel != "unknown");
        }
        other => panic!("another system's backend: {other:?}"),
    }
}

#[test]
fn no_receipt_while_the_run_is_alive() {
    let cage = Cage::new(&presets::minimal::v3()).unwrap();
    let mut child = cage.spawn(&mut sh("exec sleep 2"), &Grants::new()).unwrap();
    assert!(child.receipt().is_none());
    child.wait().unwrap();
    assert!(child.receipt().is_some());
}

#[test]
fn a_run_the_caller_ended_says_so() {
    let mut policy = presets::minimal::v3();
    policy.process.fork = true;
    let cage = Cage::new(&policy).unwrap();
    let mut child = cage.spawn(&mut sh("sleep 30"), &Grants::new()).unwrap();
    std::thread::sleep(Duration::from_millis(100));
    child.kill_all().unwrap();
    let receipt = child.receipt().unwrap();
    assert!(receipt.exit.ended_by_caller);
    assert_eq!(receipt.exit.code, None);
    assert_eq!(receipt.exit.signal, Some(libc_sigkill()));
}

fn libc_sigkill() -> i32 {
    9
}

#[test]
fn grant_names_are_listed_sorted_never_their_paths() {
    let d = scratch("grants");
    let mut policy = presets::minimal::v3();
    for name in ["zeta", "alpha"] {
        policy.grants.push(Grant {
            name: GrantName::new(name).unwrap(),
            access: Access::Read,
        });
    }
    let grants = Grants::new().bind("zeta", &*d).bind("alpha", &*d);
    let receipt = run(&policy, &CageOptions::default(), &mut sh("true"), &grants);
    assert_eq!(receipt.grants, ["alpha", "zeta"]);
    assert!(!receipt.to_json().contains(d.to_str().unwrap()));
}

#[test]
fn the_digest_is_canonical() {
    let a = AbsPath::new("/work/a").unwrap();
    let b = AbsPath::new("/work/b").unwrap();
    let mut one = Policy::default();
    one.fs
        .push(FsRule::new(Access::Read, FsTarget::Subpath(a.clone())));
    one.fs
        .push(FsRule::new(Access::Write, FsTarget::Subpath(b.clone())));
    let mut two = Policy::default();
    two.fs
        .push(FsRule::new(Access::Write, FsTarget::Subpath(b)));
    two.fs.push(FsRule::new(Access::Read, FsTarget::Subpath(a)));
    assert_eq!(policy_digest(&one), policy_digest(&two), "order of rules");
    let mut three = one.clone();
    three.waive.insert(HardDenyClass::TrustHandoff);
    assert_ne!(policy_digest(&one), policy_digest(&three), "a waiver");
    let mut four = one.clone();
    four.fs[0].access = Access::Write;
    assert_ne!(policy_digest(&one), policy_digest(&four), "an access");
    // The same on every system and in every release of this format.
    assert_eq!(
        policy_digest(&Policy::default()),
        include_str!("fixtures/default-policy.digest").trim()
    );
}

#[test]
fn anything_accepted_short_of_the_policy_is_listed() {
    let mut waived = presets::minimal::v3();
    waived.waive.insert(HardDenyClass::Persistence);
    let receipt = run(
        &waived,
        &CageOptions::default(),
        &mut sh("true"),
        &Grants::new(),
    );
    assert!(!receipt.enforced_as_written);
    assert_eq!(receipt.waivers, [HardDenyClass::Persistence]);

    // The other system's raw layer is ignored only when the caller accepts
    // that approximation.
    let mut approximated = presets::minimal::v3();
    #[cfg(target_os = "macos")]
    let construct = {
        approximated.linux = Some(Default::default());
        procage::policy::Construct::LinuxLayer
    };
    #[cfg(target_os = "linux")]
    let construct = {
        approximated.seatbelt = Some(Default::default());
        procage::policy::Construct::SeatbeltLayer
    };
    let options = CageOptions::default()
        .with_lower(procage::policy::LowerOptions::default().allow(construct));
    let receipt = run(&approximated, &options, &mut sh("true"), &Grants::new());
    assert!(!receipt.enforced_as_written);
    assert_eq!(receipt.approximations.len(), 1, "{receipt:?}");
    assert_eq!(receipt.approximations[0].construct, construct);
    assert!(!receipt.approximations[0].note.is_empty());
    assert!(receipt.relaxations.is_empty() && receipt.waivers.is_empty());
}

/// On Linux tier T2 a protected path inside a writable tree is a gap that
/// `fit` relaxes; the receipt lists the relaxation and what lifts it.
#[cfg(target_os = "linux")]
#[test]
fn a_fit_relaxation_is_listed_with_its_lift() {
    use procage::policy::{Relax, Tier};
    let d = scratch("fit");
    std::fs::create_dir_all(d.join("keep")).unwrap();
    let mut policy = presets::minimal::v3();
    policy.fs.push(FsRule::new(
        Access::Write,
        FsTarget::Subpath(AbsPath::new(d.to_str().unwrap()).unwrap()),
    ));
    policy.fs.push(FsRule::new(
        Access::Protect,
        FsTarget::Subpath(AbsPath::new(d.join("keep").to_str().unwrap()).unwrap()),
    ));
    policy.waive.insert(HardDenyClass::TrustHandoff);
    for include in [false, true] {
        let mut options = CageOptions::default().with_tier(Tier::T2);
        if include {
            options = options.with_policy_in_receipt();
        }
        let (cage, relaxed) =
            Cage::fit(&policy, &options, &Relax::new().leave_out_protect()).unwrap();
        assert!(!relaxed.is_empty());
        let mut child = cage.spawn(&mut sh("true"), &Grants::new()).unwrap();
        child.wait().unwrap();
        let receipt = child.receipt().unwrap();
        assert!(!receipt.enforced_as_written);
        let r = &receipt.relaxations[0];
        assert_eq!(r.construct, procage::policy::Construct::FsProtect);
        assert_eq!(
            r.lift,
            procage::ReceiptLift {
                tier1: true,
                landlock_abi: None
            }
        );
        assert_eq!(r.subject.is_some(), include, "{r:?}");
        assert_eq!(receipt.policy.is_some(), include);
    }
}

#[test]
fn a_receipt_reads_back_and_refuses_what_it_does_not_know() {
    let receipt = run(
        &presets::minimal::v3(),
        &CageOptions::default(),
        &mut sh("true"),
        &Grants::new(),
    );
    let json = receipt.to_json();
    assert_eq!(Receipt::from_json(&json).unwrap(), receipt);
    let newer = json.replacen("\"version\":1", "\"version\":2", 1);
    assert!(
        matches!(
            Receipt::from_json(&newer),
            Err(ReceiptError::UnsupportedVersion(2))
        ),
        "a newer version"
    );
    // An unknown field or value in every nested map.
    for (from, to) in [
        ("\"system\":", "\"vm\":true,\"system\":"),
        ("\"complete\":", "\"sampled\":true,\"complete\":"),
        ("\"coverage\":\"off\"", "\"coverage\":\"partial\""),
        ("\"base\":\"v3\"", "\"base\":\"v9\""),
    ] {
        assert!(json.contains(from), "{from} in {json}");
        let changed = json.replacen(from, to, 1);
        assert!(Receipt::from_json(&changed).is_err(), "{to}");
    }
    let extra = json.replacen('{', "{\"signed\":true,", 1);
    assert!(Receipt::from_json(&extra).is_err(), "an unknown field");
    let nested = json.replacen(
        "\"ended_by_caller\":",
        "\"retried\":false,\"ended_by_caller\":",
        1,
    );
    assert!(
        Receipt::from_json(&nested).is_err(),
        "an unknown nested field"
    );
}

/// A receipt holds no environment value, argument or path unless the
/// policy is requested; with it, the policy's paths are there.
#[test]
fn a_receipt_keeps_the_run_private() {
    let d = scratch("private-canary-path");
    let mut policy = presets::minimal::v3();
    policy.fs.push(FsRule::new(
        Access::Read,
        FsTarget::Subpath(AbsPath::new(d.to_str().unwrap()).unwrap()),
    ));
    let mut command = sh("echo argument-canary-7f3a >/dev/null");
    command.env("PROCAGE_RECEIPT_CANARY", "environment-canary-91c2");
    let plain = run(
        &policy,
        &CageOptions::default(),
        &mut command,
        &Grants::new(),
    )
    .to_json();
    for canary in [
        "argument-canary-7f3a",
        "environment-canary-91c2",
        "private-canary-path",
    ] {
        assert!(!plain.contains(canary), "{canary} in {plain}");
    }
    let mut command = sh("true");
    let with = run(
        &policy,
        &CageOptions::default().with_policy_in_receipt(),
        &mut command,
        &Grants::new(),
    );
    assert_eq!(with.policy.as_ref(), Some(&policy));
    assert!(with.to_json().contains("private-canary-path"));
}

/// Every part of the policy is in the digest; the order of what has no
/// order is not, and a round trip through the policy format keeps it.
#[test]
fn every_part_of_the_policy_is_in_the_digest() {
    let mut p = presets::agent_workspace::v3(&AbsPath::new("/work").unwrap());
    p.grants.push(Grant {
        name: GrantName::new("cache").unwrap(),
        access: Access::Read,
    });
    let base = policy_digest(&p);
    let mut reordered = p.clone();
    reordered.grants.reverse();
    if let procage::policy::EnvPolicy::Allowlist(names) = &mut reordered.env {
        names.reverse();
    }
    assert_eq!(
        policy_digest(&reordered),
        base,
        "order of grants and variables"
    );
    let json = serde_json::to_string(&p).unwrap();
    let back: Policy = serde_json::from_str(&json).unwrap();
    assert_eq!(policy_digest(&back), base, "a round trip");
    let mut changes: Vec<Policy> = Vec::new();
    let mut c = p.clone();
    c.base = procage::policy::Base::V2;
    changes.push(c);
    let mut c = p.clone();
    c.preset = None;
    changes.push(c);
    let mut c = p.clone();
    c.fs.push(FsRule::new(
        Access::Read,
        FsTarget::Subpath(AbsPath::new("/work2").unwrap()),
    ));
    changes.push(c);
    let mut c = p.clone();
    c.fs[0] = FsRule::new(
        c.fs[0].access,
        FsTarget::Subpath(AbsPath::new("/worl").unwrap()),
    );
    changes.push(c);
    for (i, c) in changes.iter().enumerate() {
        assert_ne!(policy_digest(c), base, "change {i}");
    }
}

/// A signal the caller did not send is the child's own end; `kill_all` on a
/// run that already ended does not make it the caller's.
#[test]
fn only_the_caller_ending_a_live_run_counts() {
    let mut policy = presets::minimal::v3();
    policy.process.signals = procage::policy::Signals::SameUser;
    let receipt = run(
        &policy,
        &CageOptions::default(),
        &mut sh("kill -9 $$"),
        &Grants::new(),
    );
    assert_eq!(receipt.exit.signal, Some(9));
    assert_eq!(receipt.exit.code, None);
    assert!(!receipt.exit.ended_by_caller);
    let cage = Cage::new(&presets::minimal::v3()).unwrap();
    let mut child = cage.spawn(&mut sh("exit 0"), &Grants::new()).unwrap();
    child.wait().unwrap();
    child.kill_all().unwrap();
    let receipt = child.receipt().unwrap();
    assert_eq!(receipt.exit.code, Some(0));
    assert!(!receipt.exit.ended_by_caller);
}

/// With reporting on, the summary carries the coverage and a count; the
/// denied path itself never appears.
#[test]
fn an_observed_run_has_a_count_and_no_paths() {
    let d = scratch("observed-denied-canary");
    std::fs::write(d.join("secret-canary-3b1e"), "content-canary-55aa").unwrap();
    let policy = presets::minimal::v3();
    let options = CageOptions::default().with_violations();
    let script = format!("cat {}/secret-canary-3b1e", d.display());
    let receipt = run(&policy, &options, &mut sh(&script), &Grants::new());
    assert!(
        matches!(
            receipt.violations.coverage,
            ReceiptCoverage::Observed | ReceiptCoverage::SystemCalls | ReceiptCoverage::Unavailable
        ),
        "{receipt:?}"
    );
    if receipt.violations.coverage == ReceiptCoverage::Unavailable {
        assert_eq!(receipt.violations.count, None);
        assert!(receipt.violations.reason.is_some());
    } else {
        assert!(receipt.violations.count.is_some());
    }
    let json = receipt.to_json();
    for canary in [
        "observed-denied-canary",
        "secret-canary-3b1e",
        "content-canary-55aa",
    ] {
        assert!(!json.contains(canary), "{canary} in {json}");
    }
}

/// With the policy requested, its paths appear only inside the policy and
/// the relaxations' subjects; whatever the child prints or names leaves the
/// receipt readable.
#[test]
fn requested_paths_stay_in_the_policy() {
    let d = scratch("requested-path-canary");
    let mut policy = presets::minimal::v3();
    policy.fs.push(FsRule::new(
        Access::Write,
        FsTarget::Subpath(AbsPath::new(d.to_str().unwrap()).unwrap()),
    ));
    // A write rule reaches trust-handoff names on Linux.
    policy.waive.insert(HardDenyClass::TrustHandoff);
    let options = CageOptions::default().with_policy_in_receipt();
    let script = format!("printf '\"}}{{\\n'; touch '{}/\"}}{{x'", d.display());
    let receipt = run(&policy, &options, &mut sh(&script), &Grants::new());
    let json = receipt.to_json();
    assert_eq!(Receipt::from_json(&json).unwrap(), receipt);
    let mut value: serde_json::Value = serde_json::from_str(&json).unwrap();
    value.as_object_mut().unwrap().remove("policy");
    for r in value["relaxations"].as_array_mut().unwrap() {
        r.as_object_mut().unwrap().remove("subject");
    }
    assert!(
        !value.to_string().contains("requested-path-canary"),
        "{value}"
    );
}

/// A relaxation entry is read as strictly as the rest: an unknown construct
/// or field in it refuses the receipt, a known one reads back.
#[test]
fn relaxations_are_read_strictly() {
    let receipt = run(
        &presets::minimal::v3(),
        &CageOptions::default(),
        &mut sh("true"),
        &Grants::new(),
    );
    let json = receipt.to_json();
    assert!(json.contains("\"relaxations\":[]"), "{json}");
    let with = |entry: &str| {
        json.replacen(
            "\"relaxations\":[]",
            &format!("\"relaxations\":[{entry}]"),
            1,
        )
    };
    let known = with(r#"{"construct":"fs-protect","relaxation":"left out","lift":{"tier1":true}}"#);
    let read = Receipt::from_json(&known).unwrap();
    assert_eq!(
        read.relaxations[0].construct,
        procage::policy::Construct::FsProtect
    );
    for bad in [
        r#"{"construct":"fs-unheard-of","relaxation":"x","lift":{"tier1":true}}"#,
        r#"{"construct":"fs-protect","relaxation":"x","lift":{"tier1":true},"approved":true}"#,
        r#"{"construct":"fs-protect","relaxation":"x","lift":{"tier1":true,"tier0":true}}"#,
    ] {
        assert!(Receipt::from_json(&with(bad)).is_err(), "{bad}");
    }
}
