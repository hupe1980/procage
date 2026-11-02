//! Fitting: only named relaxations of unsupported gaps, each with its
//! effect, and what would lift each gap.

mod common;

use common::*;
use procage_policy::*;

fn t2(abi: u8) -> Target {
    Target::Linux {
        tier: Tier::T2,
        landlock_abi: abi,
    }
}

/// A harness that reads everything accepts the spawn snapshot and, on
/// Linux, that other processes' command lines are readable under `/proc`.
fn options() -> LowerOptions {
    LowerOptions::default()
        .accept_spawn_snapshot()
        .allow(Construct::ProcOtherProcesses)
}

/// The shape of an agent harness's policy: read everything, write a
/// workspace with `.git` protected and `.env` hidden inside it, Unix
/// sockets in the workspace, signals to the command's own processes.
fn harness() -> Policy {
    let mut p = Policy::default();
    p.fs.push(subpath(Access::Read, "/"));
    p.fs.push(subpath(Access::Write, "/w"));
    p.fs.push(subpath(Access::Protect, "/w/.git"));
    p.fs.push(subpath(Access::Hide, "/w/.env"));
    p.ipc.unix_sockets = vec![path("/w")];
    p.process.fork = true;
    p.process.signals = Signals::SelfAndChildren;
    p
}

fn gaps(p: &Policy, target: Target) -> Vec<CapabilityGap> {
    match lower(p, target, &options()) {
        Err(LowerError::Gaps(gaps)) => gaps,
        other => panic!("expected gaps, got {other:?}"),
    }
}

fn all() -> Relax {
    Relax::new()
        .leave_out_protect()
        .leave_out_hide()
        .waive(HardDenyClass::TrustHandoff)
        .no_unix_sockets()
        .signals_same_user()
}

#[test]
fn the_harness_gets_exactly_these_gaps_on_an_old_t2() {
    let got: Vec<(Construct, Option<String>)> = gaps(&harness(), t2(5))
        .into_iter()
        .map(|g| (g.construct, g.subject))
        .collect();
    println!("{got:?}");
    let has = |c: Construct| got.iter().any(|g| g.0 == c);
    for c in [
        Construct::FsProtect,
        Construct::FsHide,
        Construct::HdTrustHandoff,
        Construct::IpcUnixSockets,
        Construct::SignalsSelfAndChildren,
    ] {
        assert!(has(c), "{c} missing from {got:?}");
    }
}

#[test]
fn all_named_relaxations_fit_and_each_has_its_effect() {
    let mut p = harness();
    let relaxed = all().apply(&mut p, &gaps(&harness(), t2(5))).unwrap();
    assert_eq!(relaxed.len(), 5, "{relaxed:?}");
    assert!(
        !p.fs
            .iter()
            .any(|r| matches!(r.access, Access::Protect | Access::Hide))
    );
    assert!(p.waive.contains(&HardDenyClass::TrustHandoff));
    assert!(p.ipc.unix_sockets.is_empty());
    assert_eq!(p.process.signals, Signals::SameUser);
    // What was not relaxed is untouched.
    assert!(p.fs.contains(&subpath(Access::Write, "/w")));
    assert_eq!(p.net, Network::None);
    assert!(lower(&p, t2(5), &options()).is_ok());
}

#[test]
fn a_gap_without_a_named_relaxation_changes_nothing() {
    let mut p = harness();
    let relax = Relax::new().leave_out_protect().leave_out_hide();
    let rest = relax.apply(&mut p, &gaps(&harness(), t2(5))).unwrap_err();
    let constructs: Vec<Construct> = rest.iter().map(|g| g.construct).collect();
    assert!(
        constructs.contains(&Construct::SignalsSelfAndChildren),
        "{constructs:?}"
    );
    assert!(!constructs.contains(&Construct::FsProtect));
    assert_eq!(p, harness());
}

#[test]
fn approximations_are_never_relaxed() {
    let mut p = harness();
    let gap = CapabilityGap {
        construct: Construct::FsHide,
        target: t2(8),
        kind: GapKind::Approximation,
        subject: Some("/w/.env".into()),
    };
    assert_eq!(
        all().apply(&mut p, std::slice::from_ref(&gap)),
        Err(vec![gap])
    );
    assert_eq!(p, harness());
}

#[test]
fn only_the_rule_the_gap_names_is_left_out() {
    let mut p = harness();
    p.fs.push(subpath(Access::Protect, "/other"));
    let gap = CapabilityGap {
        construct: Construct::FsProtect,
        target: t2(8),
        kind: GapKind::Unsupported,
        subject: Some("/w/.git".into()),
    };
    all().apply(&mut p, &[gap]).unwrap();
    assert!(p.fs.contains(&subpath(Access::Protect, "/other")));
    assert!(!p.fs.contains(&subpath(Access::Protect, "/w/.git")));
    // A gap that names no rule of the policy relaxes nothing.
    let stray = CapabilityGap {
        construct: Construct::FsProtect,
        target: t2(8),
        kind: GapKind::Unsupported,
        subject: Some("/nowhere".into()),
    };
    let before = p.clone();
    assert_eq!(
        all().apply(&mut p, std::slice::from_ref(&stray)),
        Err(vec![stray])
    );
    assert_eq!(p, before);
}

#[test]
fn loopback_becomes_no_network_when_named() {
    let mut p = Policy::default();
    p.net = Network::Loopback(Ports::Any);
    let g = gaps(&p, t2(8));
    assert!(Relax::new().apply(&mut p.clone(), &g).is_err());
    let relaxed = Relax::new().no_loopback().apply(&mut p, &g).unwrap();
    assert_eq!(relaxed[0].1, Relaxation::NoLoopback);
    assert_eq!(p.net, Network::None);
}

#[test]
fn lifts_come_from_lowering() {
    let p = harness();
    let at5 = gaps(&p, t2(5));
    let lift_of = |c: Construct| {
        let g = at5.iter().find(|g| g.construct == c).unwrap();
        lift(&p, g, &options(), 8)
    };
    assert_eq!(
        lift_of(Construct::SignalsSelfAndChildren),
        Lift {
            tier1: false,
            landlock_abi: Some(6)
        }
    );
    assert_eq!(
        lift_of(Construct::FsProtect),
        Lift {
            tier1: true,
            landlock_abi: None
        }
    );
    // ABI 9 would do on T2, but procage's backend stops at 8 here.
    assert_eq!(
        lift_of(Construct::IpcUnixSockets),
        Lift {
            tier1: true,
            landlock_abi: None
        }
    );
    let g = at5
        .iter()
        .find(|g| g.construct == Construct::IpcUnixSockets)
        .unwrap();
    assert_eq!(lift(&p, g, &options(), 12).landlock_abi, Some(9));
    // On macOS, or for a gap lowering does not report, nothing is known.
    let mac = CapabilityGap {
        construct: Construct::FsProtect,
        target: Target::MacOs,
        kind: GapKind::Unsupported,
        subject: None,
    };
    assert!(!lift(&p, &mac, &options(), 8).is_known());
    let unreported = CapabilityGap {
        construct: Construct::HdPersistence,
        target: t2(8),
        kind: GapKind::Unsupported,
        subject: None,
    };
    assert!(!lift(&p, &unreported, &options(), 8).is_known());
}

#[test]
fn a_relaxed_gap_reads_as_one_sentence() {
    let p = harness();
    let g = gaps(&p, t2(5))
        .into_iter()
        .find(|g| g.construct == Construct::SignalsSelfAndChildren)
        .unwrap();
    let r = Relaxed {
        lift: lift(&p, &g, &options(), 8),
        gap: g,
        relaxation: Relaxation::SignalsSameUser,
    };
    assert_eq!(
        r.to_string(),
        "signals-self-and-children on Linux T2 (Landlock ABI 5): signals reach every process of \
         the user; Landlock ABI 6 would enforce it"
    );
}
