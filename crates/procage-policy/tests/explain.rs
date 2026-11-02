//! Explain and diff over the lowered plans (the kernel side is the oracle
//! suite in `procage`).

use procage_policy::explain::{
    Change, Context, Decider, Decision, Direction, ExplainError, Explainer, MODELLED, Op, Question,
    diff,
};
use procage_policy::{
    AbsPath, Access, Base, FsRule, FsTarget, GapKind, Grant, GrantName, HardDenyClass, LowerError,
    LowerOptions, Policy, Target, Tier, presets,
};

const T1: Target = Target::Linux {
    tier: Tier::T1,
    landlock_abi: 6,
};
const T2: Target = Target::Linux {
    tier: Tier::T2,
    landlock_abi: 6,
};
const TARGETS: [Target; 3] = [Target::MacOs, T1, T2];

fn abs(p: &str) -> AbsPath {
    AbsPath::new(p).unwrap()
}

/// Lowering options that accept every approximation the policy needs.
fn options(policy: &Policy, target: Target) -> LowerOptions {
    let mut options = LowerOptions::default();
    loop {
        match procage_policy::lower(policy, target, &options) {
            Err(LowerError::Gaps(gaps))
                if gaps.iter().all(|g| g.kind == GapKind::Approximation) =>
            {
                options
                    .allow_degrade
                    .extend(gaps.iter().map(|g| g.construct));
            }
            _ => return options,
        }
    }
}

fn explainer(policy: &Policy, target: Target) -> Explainer {
    Explainer::new(policy, target, &options(policy, target))
        .unwrap_or_else(|e| panic!("{target}: {e}"))
}

/// The explainer, or `None` when the target cannot express the policy.
fn lowers(policy: &Policy, target: Target) -> Option<Explainer> {
    Explainer::new(policy, target, &options(policy, target)).ok()
}

fn ask(ex: &Explainer, op: Op, path: &str, ctx: &Context) -> procage_policy::explain::Answer {
    ex.explain(&Question::new(op, path), ctx).unwrap()
}

fn home(target: Target) -> &'static str {
    if target == Target::MacOs {
        "/Users/me"
    } else {
        "/home/me"
    }
}

/// Options that lower both policies.
fn both(a: &Policy, b: &Policy, target: Target) -> LowerOptions {
    let mut o = options(a, target);
    o.allow_degrade.extend(options(b, target).allow_degrade);
    o
}

/// A policy with every rule kind for `target`.
fn kinds(target: Target) -> Policy {
    let mut p = Policy::default();
    p.base = Base::V3;
    p.fs.push(FsRule::new(Access::Write, FsTarget::Subpath(abs("/work"))));
    if target != T2 {
        p.fs.push(FsRule::new(
            Access::Protect,
            FsTarget::Subpath(abs("/work/ro")),
        ));
        p.fs.push(FsRule::new(
            Access::Hide,
            FsTarget::Subpath(abs("/work/secret")),
        ));
    } else {
        // T2 cannot cover trust-handoff names under a writable tree, and
        // reaches the secrets class through a readable home instead.
        p.waive.insert(HardDenyClass::TrustHandoff);
        p.fs.push(FsRule::new(
            Access::Read,
            FsTarget::Subpath(abs("/home/me")),
        ));
        p.fs.push(FsRule::new(Access::Read, FsTarget::Subpath(abs("/data"))));
        p.fs.push(FsRule::new(
            Access::Hide,
            FsTarget::Subpath(abs("/data/secret")),
        ));
    }
    p.grants.push(Grant {
        name: GrantName::new("out").unwrap(),
        access: Access::Write,
    });
    p
}

fn context(target: Target) -> Context {
    Context {
        grants: vec![(GrantName::new("out").unwrap(), abs("/out"))],
        homes: vec![abs(home(target))],
    }
}

#[test]
fn every_rule_kind_on_macos() {
    let t = Target::MacOs;
    let ex = explainer(&kinds(t), t);
    let ctx = context(t);
    let a = ask(&ex, Op::Read, "/work/a", &ctx);
    assert_eq!(
        (a.decision, &a.by),
        (Decision::Allowed, &Decider::Rule(kinds(t).fs[0].clone()))
    );
    let a = ask(&ex, Op::Write, "/work/ro/x", &ctx);
    assert_eq!(a.decision, Decision::Denied);
    assert!(matches!(&a.by, Decider::Rule(r) if r.access == Access::Protect));
    assert!(
        matches!(&a.remedy.unwrap().changes[..], [Change::Remove(r)] if r.access == Access::Protect)
    );
    let a = ask(&ex, Op::Read, "/work/secret/k", &ctx);
    assert!(matches!(&a.by, Decider::Rule(r) if r.access == Access::Hide));
    let a = ask(&ex, Op::Write, "/work/.git/hooks/pre-commit", &ctx);
    assert_eq!(a.by, Decider::HardDeny(HardDenyClass::TrustHandoff));
    assert_eq!(
        a.remedy.unwrap().changes,
        [Change::Waive(HardDenyClass::TrustHandoff)]
    );
    let a = ask(&ex, Op::Read, "/Users/me/.ssh/id_ed25519", &ctx);
    assert_eq!(a.by, Decider::HardDeny(HardDenyClass::Secrets));
    let a = ask(&ex, Op::Write, "/Users/me/.SSH/config", &ctx);
    assert!(matches!(a.by, Decider::HardDeny(_)), "{a:?}");
    let a = ask(&ex, Op::Exec, "/usr/bin/true", &ctx);
    assert_eq!(
        (a.decision, a.by),
        (Decision::Allowed, Decider::Base(Base::V3))
    );
    let a = ex
        .explain(
            &Question::new(Op::Exec, "/usr/bin/su").with_mode(0o4755),
            &ctx,
        )
        .unwrap();
    assert_eq!(a.by, Decider::HardDeny(HardDenyClass::Privilege));
    let a = ask(&ex, Op::Write, "/out/x", &ctx);
    assert_eq!(
        (a.decision, a.by),
        (
            Decision::Allowed,
            Decider::Grant(GrantName::new("out").unwrap())
        )
    );
    let a = ask(&ex, Op::Write, "/out/x", &Context::default());
    assert_eq!(a.by, Decider::Default);
    let a = ask(&ex, Op::Read, "/elsewhere/x", &ctx);
    assert_eq!(a.by, Decider::Default);
    let r = a.remedy.unwrap();
    assert_eq!(
        r.changes,
        [Change::Add(FsRule::new(
            Access::Read,
            FsTarget::Literal(abs("/elsewhere/x"))
        ))]
    );
}

#[test]
fn every_rule_kind_on_linux() {
    for t in [T1, T2] {
        let ex = explainer(&kinds(t), t);
        let ctx = context(t);
        let a = ask(&ex, Op::Write, "/work/a", &ctx);
        assert_eq!(a.decision, Decision::Allowed, "{t}");
        assert!(
            matches!(&a.by, Decider::Rule(r) if r.access == Access::Write),
            "{t}"
        );
        let a = ask(&ex, Op::Write, "/work/.git/hooks/pre-commit", &ctx);
        let a2 = ask(
            &ex,
            Op::Write,
            "/home/me/.config/systemd/user/x.service",
            &ctx,
        );
        let a3 = ask(&ex, Op::Read, "/home/me/.ssh/id_ed25519", &ctx);
        if t == T1 {
            assert_eq!(a.by, Decider::HardDeny(HardDenyClass::TrustHandoff));
            assert!(a.caveat.is_some());
            let a = ask(&ex, Op::Write, "/work/ro/x", &ctx);
            assert!(matches!(&a.by, Decider::Rule(r) if r.access == Access::Protect));
            let a = ask(&ex, Op::Read, "/work/secret/k", &ctx);
            assert!(matches!(&a.by, Decider::Rule(r) if r.access == Access::Hide));
        } else {
            let a = ask(&ex, Op::Read, "/data/secret/k", &ctx);
            assert!(
                matches!(&a.by, Decider::Rule(r) if r.access == Access::Hide),
                "{a:?}"
            );
            assert!(a.caveat.is_some());
            let a = ask(&ex, Op::Read, "/data/x", &ctx);
            assert_eq!(a.decision, Decision::Allowed);
            assert!(a.caveat.is_some(), "the tree around a hidden path is split");
        }
        assert_eq!(a2.decision, Decision::Denied, "{t}");
        assert_eq!(a3.by, Decider::HardDeny(HardDenyClass::Secrets), "{t}");
        let a = ask(&ex, Op::Exec, "/usr/bin/true", &ctx);
        assert_eq!(
            (a.decision, &a.by),
            (Decision::Allowed, &Decider::Base(Base::V3)),
            "{t}"
        );
        let a = ask(&ex, Op::Write, "/out/x", &ctx);
        assert_eq!(a.by, Decider::Grant(GrantName::new("out").unwrap()));
        let a = ask(&ex, Op::Read, "/elsewhere/x", &ctx);
        assert_eq!(a.by, Decider::Default);
        assert!(a.remedy.is_some(), "{t}");
    }
}

#[test]
fn exec_any_is_unhandled_on_linux() {
    let mut p = kinds(T1);
    p.process.exec = procage_policy::Exec::Any;
    let a = ask(
        &explainer(&p, T1),
        Op::Exec,
        "/elsewhere/tool",
        &context(T1),
    );
    assert_eq!((a.decision, a.by), (Decision::Allowed, Decider::Unhandled));
}

fn every_preset(root: &AbsPath) -> Vec<Policy> {
    use presets::*;
    vec![
        minimal::v1(),
        minimal::v2(),
        minimal::v3(),
        agent_readonly::v1(root),
        agent_readonly::v2(root),
        agent_readonly::v3(root),
        agent_workspace::v1(root),
        agent_workspace::v2(root),
        agent_workspace::v3(root),
        build::v1(root),
        build::v2(root),
        build::v3(root),
    ]
}

fn paths(target: Target) -> Vec<String> {
    let h = home(target);
    let mut out: Vec<String> = [
        "/work/src/main.rs",
        "/work/.git/config",
        "/work/.git/hooks/pre-commit",
        "/work/.envrc",
        "/work/target/debug/app",
        "/usr/bin/true",
        "/usr/lib/libc.so",
        "/bin/sh",
        "/dev/null",
        "/opt/homebrew/bin/git",
        "/elsewhere/file",
        "/out/x",
        "/work/a*[b",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    for rel in [
        ".ssh/id_ed25519",
        ".aws/credentials",
        ".bashrc",
        ".config/autostart/x",
        "notes.txt",
    ] {
        out.push(format!("{h}/{rel}"));
    }
    if target == Target::MacOs {
        out.push("/private/etc/hosts".into());
        out.push("/System/Library/x".into());
    } else {
        out.push("/etc/hosts".into());
        out.push("/proc/self/status".into());
    }
    out
}

#[test]
fn unmodelled_operations_are_never_guessed() {
    let root = abs("/work");
    for t in TARGETS {
        for p in every_preset(&root) {
            let Some(ex) = lowers(&p, t) else { continue };
            for name in [
                "file-read-metadata",
                "file-write-unlink",
                "network-outbound",
                "signal",
            ] {
                let a = ask(&ex, Op::Other(name.into()), "/work/x", &context(t));
                assert_eq!((a.decision, a.by), (Decision::NotModelled, Decider::None));
            }
        }
    }
}

#[test]
fn non_canonical_paths_name_their_canonical_form() {
    let ex = explainer(&kinds(Target::MacOs), Target::MacOs);
    let named = |p: &str| match ex.explain(&Question::new(Op::Read, p), &Context::default()) {
        Err(ExplainError::NotCanonical { canonical }) => canonical.map(|c| c.to_string()),
        Ok(a) => panic!("{p}: {a:?}"),
    };
    assert_eq!(named("/etc/hosts").as_deref(), Some("/private/etc/hosts"));
    assert_eq!(named("/work/a/../b").as_deref(), Some("/work/b"));
    assert_eq!(named("work/a"), None);
}

#[test]
fn pattern_characters_stay_literal() {
    let mut p = kinds(Target::MacOs);
    p.fs.push(FsRule::new(
        Access::Protect,
        FsTarget::Literal(abs("/work/ab")),
    ));
    let ex = explainer(&p, Target::MacOs);
    let a = ask(&ex, Op::Write, "/work/a*[b", &Context::default());
    assert_eq!(a.decision, Decision::Allowed);
    let a = ask(&ex, Op::Write, "/work/ab", &Context::default());
    assert_eq!(a.decision, Decision::Denied);
}

#[test]
fn every_remedy_flips_its_question() {
    let root = abs("/work");
    for t in TARGETS {
        let ctx = context(t);
        for p in every_preset(&root).into_iter().chain([kinds(t)]) {
            let Some(ex) = lowers(&p, t) else { continue };
            for path in paths(t) {
                for op in MODELLED {
                    let a = ask(&ex, op.clone(), &path, &ctx);
                    if a.decision != Decision::Denied {
                        continue;
                    }
                    let Some(r) = a.remedy else { continue };
                    let mut changed = p.clone();
                    for c in &r.changes {
                        match c {
                            Change::Add(rule) => changed.fs.push(rule.clone()),
                            Change::Remove(rule) => changed.fs.retain(|x| x != rule),
                            Change::Waive(class) => {
                                changed.waive.insert(*class);
                            }
                        }
                        if let Change::Add(rule) = c {
                            assert_eq!(rule.target, FsTarget::Literal(abs(&path)));
                        }
                    }
                    let mut opts = options(&p, t);
                    opts.allow_degrade.extend(r.accept.iter().copied());
                    let after = Explainer::new(&changed, t, &opts).unwrap();
                    let b = ask(&after, op.clone(), &path, &ctx);
                    assert_eq!(
                        b.decision,
                        Decision::Allowed,
                        "{t} {op} {path}: {:?}",
                        r.changes
                    );
                    assert_eq!(diff(&p, &changed, &[t], &opts).unwrap(), r.diff);
                    assert!(
                        r.diff
                            .entries
                            .iter()
                            .any(|e| e.covers(op, path.as_bytes(), &ctx))
                    );
                }
            }
        }
    }
}

/// Policy pairs: a preset and one change to it.
fn mutations(p: &Policy) -> Vec<Policy> {
    let mut out = Vec::new();
    let mut add = |f: &dyn Fn(&mut Policy)| {
        let mut q = p.clone();
        f(&mut q);
        out.push(q);
    };
    add(&|q| {
        q.fs.push(FsRule::new(
            Access::Write,
            FsTarget::Subpath(abs("/elsewhere")),
        ))
    });
    add(&|q| {
        q.fs.push(FsRule::new(
            Access::Read,
            FsTarget::Subpath(abs("/home/me")),
        ))
    });
    add(&|q| {
        q.fs.push(FsRule::new(
            Access::Exec,
            FsTarget::Subpath(abs("/work/target")),
        ))
    });
    add(&|q| q.fs.retain(|r| r.access != Access::Write));
    add(&|q| q.base = Base::V1);
    add(&|q| q.base = Base::None);
    for &class in HardDenyClass::ALL {
        add(&|q| {
            q.waive.insert(class);
        });
    }
    add(&|q| {
        q.grants.push(Grant {
            name: GrantName::new("out").unwrap(),
            access: Access::Write,
        })
    });
    out
}

#[test]
fn diff_covers_every_changed_answer() {
    let root = abs("/work");
    for t in TARGETS {
        let ctx = context(t);
        let v3 = every_preset(&root).into_iter().skip(2).step_by(3);
        for a in v3.chain([kinds(t)]) {
            for b in mutations(&a) {
                let opts = options(&a, t);
                let opts = {
                    let mut o = opts.clone();
                    o.allow_degrade.extend(options(&b, t).allow_degrade);
                    o
                };
                let (Ok(ea), Ok(eb)) = (Explainer::new(&a, t, &opts), Explainer::new(&b, t, &opts))
                else {
                    continue;
                };
                let d = diff(&a, &b, &[t], &opts).unwrap();
                for path in paths(t) {
                    for op in MODELLED {
                        let (x, y) = (
                            ask(&ea, op.clone(), &path, &ctx),
                            ask(&eb, op.clone(), &path, &ctx),
                        );
                        if x.decision == y.decision {
                            continue;
                        }
                        let want = if y.decision == Decision::Allowed {
                            Direction::Loosens
                        } else {
                            Direction::Tightens
                        };
                        assert!(
                            d.entries
                                .iter()
                                .any(|e| e.direction == want && e.covers(op, path.as_bytes(), &ctx)),
                            "{t} {op} {path}: {:?} → {:?}, diff {:#?}",
                            x.by,
                            y.by,
                            d.entries
                        );
                    }
                }
            }
        }
    }
}

#[test]
fn one_more_writable_path_or_waiver() {
    let root = abs("/work");
    let a = presets::agent_workspace::v3(&root);
    for t in TARGETS {
        if lowers(&a, t).is_none() {
            continue;
        }
        let mut b = a.clone();
        b.fs.push(FsRule::new(Access::Write, FsTarget::Subpath(abs("/extra"))));
        let d = diff(&a, &b, &[t], &both(&a, &b, t)).unwrap();
        assert!(!d.entries.is_empty());
        for e in &d.entries {
            // Rename anchors adds a deny on removing the new root.
            let anchor = e.by == Decider::HardDeny(HardDenyClass::RenameAnchors);
            assert!(anchor || e.direction == Direction::Loosens, "{t} {e:?}");
            assert!(
                matches!(&e.by, Decider::Rule(r) if r.target == FsTarget::Subpath(abs("/extra")))
                    || matches!(
                        &e.by,
                        Decider::Base(_) | Decider::HardDeny(HardDenyClass::RenameAnchors)
                    ),
                "{t} {e:?}"
            );
            assert!(
                e.paths.contains(b"/extra", &Context::default()),
                "{t} {e:?}"
            );
        }
        let mut c = a.clone();
        c.waive.insert(HardDenyClass::TrustHandoff);
        let d = diff(&a, &c, &[t], &both(&a, &c, t)).unwrap();
        assert!(d.settings.contains(&(t, "waivers")));
        assert!(
            d.entries
                .iter()
                .all(|e| e.by == Decider::HardDeny(HardDenyClass::TrustHandoff)
                    && e.direction == Direction::Loosens),
            "{t} {:?}",
            d.entries
        );
    }
}

#[test]
fn entries_are_tagged_with_their_target() {
    let a = kinds(T1);
    let mut b = a.clone();
    b.linux = Some(procage_policy::linux::Layer {
        landlock_extra: vec![(abs("/srv"), Access::Read)],
        ..Default::default()
    });
    let opts = options(&b, T2).allow(procage_policy::Construct::LinuxLayer);
    let mut opts = opts;
    opts.allow_degrade.extend(options(&b, T1).allow_degrade);
    let d = diff(&a, &b, &[Target::MacOs, T1], &opts).unwrap();
    assert!(!d.entries.is_empty());
    assert!(d.entries.iter().all(|e| e.target == T1), "{:?}", d.entries);
}

#[test]
fn preset_versions_differ_only_in_their_base() {
    let root = abs("/work");
    let all = every_preset(&root);
    for chunk in all.chunks(3) {
        for pair in chunk.windows(2) {
            for t in TARGETS {
                if lowers(&pair[0], t).is_none() || lowers(&pair[1], t).is_none() {
                    continue;
                }
                let opts = both(&pair[0], &pair[1], t);
                let d = diff(&pair[0], &pair[1], &[t], &opts).unwrap();
                assert!(d.settings.contains(&(t, "base")), "{t}");
                assert!(d.settings.contains(&(t, "preset")), "{t}");
                // v3 only adds quiet denies to v2.
                if pair[1].base == Base::V3 {
                    assert!(
                        d.entries.iter().all(|e| e.direction == Direction::Tightens),
                        "{t}: {:?}",
                        d.entries
                    );
                }
                // `build` v2 also allows Unix sockets in the workspace.
                let sockets = pair[0].ipc.unix_sockets != pair[1].ipc.unix_sockets;
                for e in &d.entries {
                    let ok = matches!(e.by, Decider::Base(_))
                        || (sockets && e.by == Decider::Setting("ipc.unix_sockets"));
                    assert!(ok, "{t} {e:?}");
                }
            }
        }
    }
}

#[test]
fn diff_is_fast_on_large_policies() {
    let mut a = Policy::default();
    for i in 0..10_000 {
        a.fs.push(FsRule::new(
            Access::Read,
            FsTarget::Subpath(abs(&format!("/data/d{i}"))),
        ));
    }
    let mut b = a.clone();
    b.fs.push(FsRule::new(
        Access::Read,
        FsTarget::Subpath(abs("/data/new")),
    ));
    let start = std::time::Instant::now();
    let d = diff(&a, &b, &[T2], &LowerOptions::default()).unwrap();
    assert_eq!(d.entries.len(), 1);
    // Under a second in release (about 0.05 s measured); debug builds are
    // several times slower.
    let bound = if cfg!(debug_assertions) { 10 } else { 1 };
    assert!(
        start.elapsed() < std::time::Duration::from_secs(bound),
        "{:?}",
        start.elapsed()
    );
}

#[test]
fn explain_is_fast_on_long_paths() {
    let root = abs("/work");
    let p = presets::agent_workspace::v3(&root);
    let long = format!(
        "/work{}",
        "/abcdefghijklmnopqrstuvwxyz0123456789".repeat(110)
    );
    for t in TARGETS {
        let Some(ex) = lowers(&p, t) else { continue };
        let start = std::time::Instant::now();
        for _ in 0..100 {
            ask(&ex, Op::Write, &long, &context(t));
        }
        let each = start.elapsed() / 100;
        let bound = if cfg!(debug_assertions) { 20 } else { 1 };
        assert!(
            each < std::time::Duration::from_millis(bound),
            "{t}: {each:?}"
        );
    }
}
