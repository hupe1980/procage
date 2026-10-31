//! Capability gaps are complete and typed; approximations need permission
//! and are recorded; tiers below their minimum are refused.

mod common;

use common::*;
use procage_policy::*;

const T2: Target = Target::Linux {
    tier: Tier::T2,
    landlock_abi: 6,
};

#[test]
fn every_gap_is_listed_and_no_plan_is_returned() {
    let mut p = Policy::default();
    p.fs.push(subpath(Access::Write, "/work"));
    p.fs.push(subpath(Access::Protect, "/work/.git"));
    p.fs.push(FsRule::new(
        Access::Read,
        FsTarget::Glob(glob("/src/**/*.rs")),
    ));
    p.net = Network::Loopback(Ports::Any);
    let Err(LowerError::Gaps(gaps)) = lower(&p, T2, &LowerOptions::default()) else {
        panic!("expected gaps");
    };
    let found: Vec<_> = gaps.iter().map(|g| (g.construct, g.kind.clone())).collect();
    assert_eq!(
        found,
        [
            (Construct::FsGlob, GapKind::Unsupported),
            (Construct::FsProtect, GapKind::Unsupported),
            (Construct::NetLoopback, GapKind::Unsupported),
            // A glob read rule is taken to reach anything.
            (Construct::HdSecrets, GapKind::Unsupported),
            // A write rule reaches `.git/hooks` and the other names, which
            // T2 cannot deny inside it.
            (Construct::HdTrustHandoff, GapKind::Unsupported),
        ]
    );
    assert!(gaps.iter().all(|g| g.target == T2));
    assert_eq!(gaps[1].subject.as_deref(), Some("/work/.git"));
    let mut sorted = gaps.clone();
    sorted.sort();
    assert_eq!(gaps, sorted);
}

#[test]
fn an_allowed_approximation_is_recorded_once() {
    let mut p = Policy::default();
    p.fs.push(FsRule::new(
        Access::Read,
        FsTarget::Literal(path("/etc/hosts")),
    ));
    p.fs.push(FsRule::new(
        Access::Read,
        FsTarget::Literal(path("/etc/resolv.conf")),
    ));
    let options = LowerOptions::default().allow(Construct::FsLiteral);
    let plan = lower(&p, T2, &options).unwrap();
    assert_eq!(plan.degradations().len(), 1);
    assert_eq!(plan.degradations()[0].construct, Construct::FsLiteral);
    assert_eq!(plan.degradations()[0].target, T2);
    // Unsupported stays a gap even when allowed.
    let mut q = p.clone();
    q.fs.push(subpath(Access::Protect, "/etc/ssh"));
    let options = options.allow(Construct::FsProtect);
    assert!(matches!(lower(&q, T2, &options), Err(LowerError::Gaps(_))));
}

#[test]
fn tiers_below_their_minimum_are_refused() {
    let p = read_only();
    let options = LowerOptions::default();
    for (tier, abi, min) in [(Tier::T2, 3, 4), (Tier::T2, 0, 4), (Tier::T1, 0, 1)] {
        let target = Target::Linux {
            tier,
            landlock_abi: abi,
        };
        assert_eq!(
            lower(&p, target, &options),
            Err(LowerError::Target(TargetError::LandlockTooOld {
                tier,
                abi,
                min
            }))
        );
    }
    // A plan is for exactly the tier asked for.
    let Ok(Plan::Linux(plan)) = lower(
        &p,
        Target::Linux {
            tier: Tier::T2,
            landlock_abi: 4,
        },
        &options,
    ) else {
        panic!("expected a Linux plan");
    };
    assert_eq!((plan.tier, plan.landlock_abi), (Tier::T2, 4));
    assert!(plan.namespaces.is_none());
}

#[test]
fn contradictions_are_reported_together() {
    let mut p = Policy::default();
    p.process.exec = Exec::Never;
    p.fs.push(subpath(Access::Exec, "/usr/bin"));
    p.net = Network::Proxy {
        http: None,
        socks: None,
    };
    p.grants.push(grant("bad", Access::Protect));
    p.grants.push(grant("twice", Access::Read));
    p.grants.push(grant("twice", Access::Write));
    let Err(LowerError::Invalid(errors)) = lower(&p, Target::MacOs, &LowerOptions::default())
    else {
        panic!("expected invalid");
    };
    assert!(errors.contains(&PolicyError::ExecConflict));
    assert!(errors.contains(&PolicyError::EmptyProxy));
    assert!(errors.contains(&PolicyError::GrantAccess {
        name: GrantName::new("bad").unwrap()
    }));
    assert!(errors.contains(&PolicyError::DuplicateGrant {
        name: GrantName::new("twice").unwrap()
    }));
    let mut q = Policy::default();
    q.net = Network::Loopback(Ports::List(Default::default()));
    assert_eq!(q.validate(), Err(vec![PolicyError::EmptyPorts]));
    q.net = Network::UnixSockets(vec![]);
    assert_eq!(q.validate(), Err(vec![PolicyError::EmptyUnixSockets]));
}

#[test]
fn the_empty_policy_denies_everything_on_every_target() {
    let p = Policy::default();
    for target in targets() {
        let plan =
            lower(&p, target, &LowerOptions::default()).unwrap_or_else(|e| panic!("{target}: {e}"));
        assert!(plan.degradations().is_empty());
        match plan {
            Plan::Seatbelt(s) => {
                assert!(s.profile.starts_with("(version 1)\n(deny default)\n"));
                assert!(!s.profile.contains("(allow"), "{}", s.profile);
                assert!(s.profile.contains("(deny system-fcntl"));
            }
            Plan::Linux(l) => {
                assert!(l.landlock.rules.is_empty());
                assert!(l.landlock.handled_fs.0 != 0);
                assert!(l.no_new_privs);
                assert!(
                    l.seccomp
                        .iter()
                        .any(|r| r.syscall == linux::Syscall::Socket)
                );
            }
        }
    }
}

#[test]
fn a_control_character_is_unrepresentable_on_macos() {
    let mut p = Policy::default();
    p.fs.push(FsRule::new(
        Access::Read,
        FsTarget::Subpath(path("/tmp/a\nb")),
    ));
    p.fs.push(FsRule::new(
        Access::Write,
        FsTarget::Subpath(AbsPath::new(&b"/tmp/\xff"[..]).unwrap()),
    ));
    let Err(LowerError::Gaps(gaps)) = lower(&p, Target::MacOs, &LowerOptions::default()) else {
        panic!("expected gaps");
    };
    assert_eq!(gaps.len(), 2);
    assert!(gaps.iter().any(|g| g.kind
        == GapKind::Unrepresentable(EscapeError::ControlCharacter { at: 6, byte: b'\n' })));
    assert!(
        gaps.iter()
            .any(|g| g.kind == GapKind::Unrepresentable(EscapeError::NotUtf8 { at: 5 }))
    );
    // Linux carries the bytes unchanged.
    let t1 = Target::Linux {
        tier: Tier::T1,
        landlock_abi: 8,
    };
    let options = LowerOptions::default().allow(Construct::HdTrustHandoff);
    assert!(lower(&p, t1, &options).is_ok());
}

#[test]
fn protect_and_hide_by_glob_are_unsupported_on_linux() {
    let mut p = Policy::default();
    p.fs.push(subpath(Access::Write, "/work"));
    p.fs.push(FsRule::new(
        Access::Protect,
        FsTarget::Glob(glob("/work/**/.git")),
    ));
    let t1 = Target::Linux {
        tier: Tier::T1,
        landlock_abi: 8,
    };
    let Err(LowerError::Gaps(gaps)) = lower(&p, t1, &allow_all()) else {
        panic!("expected gaps");
    };
    assert_eq!(gaps[0].construct, Construct::FsGlob);
    assert_eq!(gaps[0].kind, GapKind::Unsupported);
    assert!(lower(&p, Target::MacOs, &LowerOptions::default()).is_ok());
}

#[test]
fn malformed_backend_layers_are_invalid_on_every_target() {
    use procage_policy::seatbelt::{Effect, Layer, Rule};
    let mut p = Policy::default();
    p.seatbelt = Some(Layer {
        rules: vec![Rule {
            effect: Effect::Allow,
            ops: vec![],
            filters: vec![],
        }],
    });
    p.linux = Some(linux::Layer {
        syscalls_deny: vec![],
        landlock_extra: vec![(path("/work"), Access::Protect)],
    });
    for target in targets() {
        assert_eq!(
            lower(&p, target, &allow_all()),
            Err(LowerError::Invalid(vec![
                PolicyError::EmptyOperations { index: 0 },
                PolicyError::LandlockExtraAccess {
                    path: path("/work")
                },
            ])),
            "{target}"
        );
    }
}

#[test]
fn the_linux_lifetime_lock_follows_the_setting() {
    let locked = |p: &Policy| -> (bool, bool) {
        let Ok(Plan::Linux(plan)) = lower(p, T2, &LowerOptions::default()) else {
            panic!("no Linux plan");
        };
        let has = |s: linux::Syscall| plan.seccomp.iter().any(|r| r.syscall == s);
        (has(linux::Syscall::Setsid), has(linux::Syscall::Setpgid))
    };
    let mut p = Policy::default();
    // Without fork there is nothing to keep in the run.
    assert_eq!(locked(&p), (false, false));
    p.process.fork = true;
    assert_eq!(p.process.lifetime, Lifetime::Run);
    assert_eq!(locked(&p), (true, true));
    p.process.lifetime = Lifetime::Tree;
    assert_eq!(locked(&p), (false, false));
}

#[test]
fn reading_everything_on_t1_needs_exactly_the_spawn_masks() {
    let t1 = Target::Linux {
        tier: Tier::T1,
        landlock_abi: 6,
    };
    let mut p = Policy::default();
    p.fs.push(subpath(Access::Read, "/"));
    let Err(LowerError::Gaps(gaps)) = lower(&p, t1, &LowerOptions::default()) else {
        panic!("reading / on T1 must need an acceptance");
    };
    let named: Vec<Construct> = gaps.iter().map(|g| g.construct).collect();
    assert!(named.contains(&Construct::HdSecrets), "{named:?}");
    let options = LowerOptions::default().accept_spawn_masks();
    assert_eq!(
        options.allow_degrade.iter().copied().collect::<Vec<_>>(),
        [
            Construct::HdSecrets,
            Construct::HdTrustHandoff,
            Construct::HdPersistence
        ]
    );
    let plan = lower(&p, t1, &options).unwrap();
    let accepted: Vec<Construct> = plan.degradations().iter().map(|d| d.construct).collect();
    assert!(accepted.contains(&Construct::HdSecrets), "{accepted:?}");
    assert!(accepted.iter().all(|c| options.allow_degrade.contains(c)));
    // Any other approximation is still refused.
    p.fs.push(FsRule::new(
        Access::Read,
        FsTarget::Glob(glob("/src/**/*.rs")),
    ));
    assert!(lower(&p, t1, &options).is_err());
}
