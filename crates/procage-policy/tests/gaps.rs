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
            // A glob read rule is taken to reach anything; no write rule
            // reaches the secrets, so T2 hides them piecewise (approximated).
            (Construct::HdSecrets, GapKind::Approximation),
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
    for (tier, abi, min) in [(Tier::T2, 0, 1), (Tier::T1, 0, 1)] {
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
fn reading_everything_needs_exactly_the_spawn_snapshot() {
    let mut p = Policy::default();
    p.fs.push(subpath(Access::Read, "/"));
    let options = LowerOptions::default().accept_spawn_snapshot();
    let mut accepted: Vec<Construct> = options.allow_degrade.iter().copied().collect();
    accepted.sort();
    let mut snapshot = Construct::SPAWN_SNAPSHOT.to_vec();
    snapshot.sort();
    assert_eq!(accepted, snapshot);
    assert_eq!(snapshot.len(), 5);
    for tier in [Tier::T1, Tier::T2] {
        let target = Target::Linux {
            tier,
            landlock_abi: 6,
        };
        let Err(LowerError::Gaps(gaps)) = lower(&p, target, &LowerOptions::default()) else {
            panic!("{tier}: reading / must need an acceptance");
        };
        let secrets = gaps
            .iter()
            .find(|g| g.construct == Construct::HdSecrets)
            .unwrap_or_else(|| panic!("{tier}: {gaps:?}"));
        assert!(
            secrets.to_string().contains("accept_spawn_snapshot"),
            "{secrets}"
        );
        let plan = lower(&p, target, &options).unwrap();
        let degraded: Vec<Construct> = plan.degradations().iter().map(|d| d.construct).collect();
        assert!(
            degraded.contains(&Construct::HdSecrets),
            "{tier}: {degraded:?}"
        );
        assert!(degraded.iter().all(|c| snapshot.contains(c)));
    }
    // Any other approximation is still refused.
    p.fs.push(FsRule::new(
        Access::Read,
        FsTarget::Glob(glob("/src/**/*.rs")),
    ));
    assert!(lower(&p, T2, &options).is_err());
}

fn linux_plan(p: &Policy, target: Target) -> Result<LinuxPlan, LowerError> {
    match lower(p, target, &LowerOptions::default().accept_spawn_snapshot())? {
        Plan::Linux(plan) => Ok(plan),
        Plan::Seatbelt(_) => unreachable!(),
    }
}

fn refused_construct(result: Result<LinuxPlan, LowerError>) -> Vec<Construct> {
    match result {
        Err(LowerError::Gaps(gaps)) => gaps.iter().map(|g| g.construct).collect(),
        other => panic!("expected gaps, got {other:?}"),
    }
}

#[test]
fn hiding_on_t2_is_piecewise_unless_written_around() {
    let mut p = Policy::default();
    p.fs.push(subpath(Access::Read, "/data"));
    p.fs.push(subpath(Access::Hide, "/data/secret"));
    let plan = linux_plan(&p, T2).unwrap();
    assert_eq!(plan.hide_by_siblings, [path("/data/secret")]);
    assert!(
        plan.degradations
            .iter()
            .any(|d| d.construct == Construct::FsHide)
    );
    // A write rule around the hidden path, or on it, cannot be kept out.
    for writable in ["/data", "/data/secret"] {
        let mut q = p.clone();
        q.fs.push(subpath(Access::Write, writable));
        assert!(refused_construct(linux_plan(&q, T2)).contains(&Construct::FsHide));
    }
    // A write rule elsewhere, or below the hidden path, is fine (the
    // trust-handoff class, which any write rule reaches on T2, is waived).
    let mut q = p.clone();
    q.waive.insert(HardDenyClass::TrustHandoff);
    q.fs.push(subpath(Access::Write, "/data/secret/inner"));
    q.fs.push(subpath(Access::Write, "/work"));
    assert!(linux_plan(&q, T2).is_ok());
    // T1 masks.
    let t1 = Target::Linux {
        tier: Tier::T1,
        landlock_abi: 6,
    };
    assert!(linux_plan(&p, t1).unwrap().hide_by_siblings.is_empty());
}

#[test]
fn secrets_on_t2_are_hidden_unless_a_write_rule_reaches_them() {
    let mut p = Policy::default();
    p.fs.push(subpath(Access::Read, "/"));
    let plan = linux_plan(&p, T2).unwrap();
    assert!(
        plan.classes
            .iter()
            .any(|c| c.class == HardDenyClass::Secrets)
    );
    p.fs.push(subpath(Access::Write, "/home"));
    assert!(refused_construct(linux_plan(&p, T2)).contains(&Construct::HdSecrets));
}

#[test]
fn unix_sockets_by_tier_and_abi() {
    let mut p = Policy::default();
    p.ipc.unix_sockets = vec![path("/work/b"), path("/work/a")];
    let target = |tier, landlock_abi| Target::Linux { tier, landlock_abi };
    // T1 below ABI 9: AF_UNIX only, masks at spawn.
    let plan = linux_plan(&p, target(Tier::T1, 8)).unwrap();
    assert!(plan.mask_unix_sockets);
    assert_eq!(plan.unix_socket_paths, [path("/work/a"), path("/work/b")]);
    assert!(
        plan.seccomp
            .iter()
            .any(|r| r.syscall == linux::Syscall::Socket
                && r.condition == linux::Condition::SocketFamilyExcept(vec![1]))
    );
    assert!(!plan.seccomp.iter().any(|r| r.syscall == linux::Syscall::Socket
        && r.condition == linux::Condition::Always));
    assert!(plan.landlock.scopes.0 & linux::Scopes::ABSTRACT_UNIX_SOCKET.0 != 0);
    // T2 below ABI 9: refused, with a message that says why.
    let Err(LowerError::Gaps(gaps)) = lower(&p, target(Tier::T2, 8), &LowerOptions::default())
    else {
        panic!("T2 must refuse");
    };
    assert_eq!(gaps[0].construct, Construct::IpcUnixSockets);
    assert_eq!(gaps[0].kind, GapKind::Unsupported);
    // ABI 9: Landlock's right, on both tiers.
    for tier in [Tier::T1, Tier::T2] {
        let plan = linux_plan(&p, target(tier, 9)).unwrap();
        assert!(!plan.mask_unix_sockets);
        assert!(
            plan.landlock
                .rules
                .iter()
                .any(|r| r.access == linux::AccessFs::RESOLVE_UNIX)
        );
    }
    // With every network, nothing to restrict.
    p.net = Network::All;
    let plan = linux_plan(&p, target(Tier::T2, 8)).unwrap();
    assert!(!plan.mask_unix_sockets);
    // Without the setting, no socket at all.
    let plan = linux_plan(&Policy::default(), target(Tier::T1, 8)).unwrap();
    assert!(plan.seccomp.iter().any(|r| r.syscall == linux::Syscall::Socket
        && r.condition == linux::Condition::Always));
}

#[test]
fn unix_sockets_on_macos_are_path_filtered_and_respect_hide() {
    let mut p = Policy::default();
    p.fs.push(subpath(Access::Write, "/work"));
    p.fs.push(subpath(Access::Hide, "/work/private"));
    p.ipc.unix_sockets = vec![path("/work")];
    let plan = seatbelt_plan(&p, &LowerOptions::default());
    let profile = plan.profile;
    assert!(profile.contains("(allow system-socket)"), "{profile}");
    assert!(
        profile
            .contains("(allow network-bind network-inbound network-outbound (subpath \"/work\"))"),
        "{profile}"
    );
    assert!(
        profile.contains(
            "(deny network-bind network-inbound network-outbound (subpath \"/work/private\"))"
        ),
        "{profile}"
    );
}

#[test]
fn truncation_is_guarded_below_abi_3_on_both_tiers() {
    use linux::{Action, Condition, Syscall};
    let guard = |plan: &LinuxPlan| -> Vec<(Syscall, Condition, Action)> {
        plan.seccomp
            .iter()
            .filter(|r| {
                matches!(
                    r.syscall,
                    Syscall::Truncate | Syscall::Open | Syscall::Openat | Syscall::Openat2
                )
            })
            .map(|r| (r.syscall.clone(), r.condition.clone(), r.action))
            .collect()
    };
    let p = read_only();
    for tier in [Tier::T1, Tier::T2] {
        for abi in [1, 2] {
            let plan = linux_plan(
                &p,
                Target::Linux {
                    tier,
                    landlock_abi: abi,
                },
            )
            .unwrap();
            assert_eq!(
                guard(&plan),
                [
                    (
                        Syscall::Open,
                        Condition::TruncWithoutWrite { flags_arg: 1 },
                        Action::Eperm
                    ),
                    (
                        Syscall::Openat,
                        Condition::TruncWithoutWrite { flags_arg: 2 },
                        Action::Eperm
                    ),
                    (Syscall::Openat2, Condition::Always, Action::Enosys),
                    (Syscall::Truncate, Condition::Always, Action::Eperm),
                ],
                "{tier} ABI {abi}"
            );
        }
        for abi in [3, 8] {
            let plan = linux_plan(
                &p,
                Target::Linux {
                    tier,
                    landlock_abi: abi,
                },
            )
            .unwrap();
            assert!(guard(&plan).is_empty(), "{tier} ABI {abi}");
        }
    }
}

#[test]
fn signals_need_abi_6_unless_the_caller_chooses_same_user() {
    let mut p = read_only();
    p.process.fork = true;
    p.process.signals = Signals::SelfAndChildren;
    for tier in [Tier::T1, Tier::T2] {
        let target = |abi| Target::Linux {
            tier,
            landlock_abi: abi,
        };
        assert_eq!(
            refused_construct(linux_plan(&p, target(5))),
            [Construct::SignalsSelfAndChildren]
        );
        assert!(
            linux_plan(&p, target(6)).unwrap().landlock.scopes.0 & linux::Scopes::SIGNAL.0 != 0
        );
        let mut q = p.clone();
        q.process.signals = Signals::SameUser;
        for abi in [1, 5, 8] {
            let plan = linux_plan(&q, target(abi)).unwrap();
            assert_eq!(plan.landlock.scopes.0 & linux::Scopes::SIGNAL.0, 0);
            assert!(
                !plan
                    .seccomp
                    .iter()
                    .any(|r| r.syscall == linux::Syscall::Kill)
            );
        }
    }
}
