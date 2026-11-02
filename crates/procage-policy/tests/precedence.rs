//! Fixed precedence: allows, then deny-within-allow, then the hard-deny tier,
//! then (with fork) the run-marker block last; independent of rule order;
//! waivers by name and recorded.

mod common;

use std::collections::BTreeSet;

use common::*;
use procage_policy::*;

/// Splits a profile into its rule lines (after `(deny default)`).
fn rules(profile: &str) -> Vec<&str> {
    profile.lines().skip(2).collect()
}

/// The run-marker block.
const MARKER: [&str; 2] = [
    "(deny mach-lookup (global-name-prefix (param \"procage-run-prefix\")))",
    "(allow mach-lookup (global-name (param \"procage-run-marker\")))",
];

/// The rule lines before the run-marker block, which must be exactly the
/// last two lines when the plan has one, and absent otherwise.
fn without_marker(plan: &SeatbeltPlan) -> Vec<&str> {
    let mut lines = rules(&plan.profile);
    if plan.run_marker {
        let tail = lines.split_off(lines.len() - 2);
        assert_eq!(tail, MARKER, "{}", plan.profile);
    }
    assert!(
        !lines.iter().any(|l| l.contains("procage-run-")),
        "{}",
        plan.profile
    );
    lines
}

/// The hard-deny lines of `class` in an otherwise empty policy.
fn class_lines(class: HardDenyClass, base: &Policy) -> BTreeSet<String> {
    let with = seatbelt_plan(base, &LowerOptions::default());
    let mut waived = base.clone();
    waived.waive.insert(class);
    let without = seatbelt_plan(&waived, &LowerOptions::default());
    let without: BTreeSet<_> = rules(&without.profile).into_iter().collect();
    rules(&with.profile)
        .into_iter()
        .filter(|l| !without.contains(l))
        .map(String::from)
        .collect()
}

#[test]
fn rule_order_never_changes_the_plan() {
    let mut rng = Rng::new(0x5eed);
    let options = allow_all();
    for (name, policy) in reference_policies() {
        for target in targets() {
            let base = lower(&policy, target, &options);
            for _ in 0..50 {
                let again = lower(&shuffled(&policy, &mut rng), target, &options);
                assert_eq!(base, again, "{name} on {target}");
            }
        }
    }
}

#[test]
fn blocks_are_in_fixed_order_and_the_tier_is_last() {
    // The tier's own denies; a class may also add an early deny and an allow
    // elsewhere (process access), which are not part of the tier.
    let hard: BTreeSet<String> = HardDenyClass::ALL
        .iter()
        .flat_map(|&c| class_lines(c, &hard_deny_base()))
        .filter(|l| l.starts_with("(deny") && !l.ends_with(" (with no-report))"))
        .collect();
    for (name, policy) in reference_policies() {
        let Ok(Plan::Seatbelt(plan)) = lower(&policy, Target::MacOs, &allow_all()) else {
            panic!("{name}: no Seatbelt plan");
        };
        let all = without_marker(&plan);
        // Quiet denies (base V3) come before every allow, so every allow
        // wins over them; the rest of the order is as for every base.
        let quiet = |l: &&str| l.ends_with(" (with no-report))");
        let last_quiet = all.iter().rposition(quiet);
        let first_allow = all.iter().position(|l| l.starts_with("(allow"));
        if let (Some(q), Some(a)) = (last_quiet, first_allow) {
            assert!(
                q < a,
                "{name}: a quiet deny follows an allow:\n{}",
                plan.profile
            );
        }
        let lines: Vec<&str> = all.iter().copied().filter(|l| !quiet(l)).collect();
        let first_deny = lines
            .iter()
            .position(|l| l.starts_with("(deny"))
            .unwrap_or(lines.len());
        assert!(
            lines[first_deny..].iter().all(|l| l.starts_with("(deny")),
            "{name}: an allow follows a deny:\n{}",
            plan.profile
        );
        // Every hard-deny line comes after every other deny.
        let first_hard = lines
            .iter()
            .position(|l| hard.contains(*l) || l.starts_with("(deny file-write-unlink"))
            .unwrap_or(lines.len());
        assert!(
            lines[first_hard..]
                .iter()
                .all(|l| hard.contains(*l) || l.starts_with("(deny file-write-unlink")),
            "{name}: a non-tier rule follows the hard-deny tier:\n{}",
            plan.profile
        );
        assert!(
            lines
                .last()
                .is_some_and(|l| *l == "(deny system-fcntl (fcntl-command 80 110))")
        );
    }
}

#[test]
fn a_forking_policy_ends_with_the_run_marker() {
    for lifetime in [Lifetime::Run, Lifetime::Tree] {
        let mut p = hard_deny_base();
        p.process.fork = true;
        p.process.lifetime = lifetime;
        let plan = seatbelt_plan(&p, &LowerOptions::default());
        assert!(plan.run_marker, "{lifetime:?}");
        assert!(without_marker(&plan).len() > 2);
        // Bound at spawn, never by the lowering, and never through an
        // extension the child could release.
        assert!(
            plan.params
                .iter()
                .all(|(n, _)| !n.starts_with("procage-run-"))
        );
        assert!(!MARKER.iter().any(|l| l.contains("extension")));
    }
    let plan = seatbelt_plan(&hard_deny_base(), &LowerOptions::default());
    assert!(!plan.run_marker);
    without_marker(&plan);
}

#[test]
fn protect_inside_a_writable_root_comes_after_the_allow() {
    let plan = seatbelt_plan(
        &reference_policy(Construct::FsProtect),
        &LowerOptions::default(),
    );
    let lines = rules(&plan.profile);
    let allow = lines
        .iter()
        .position(|l| *l == "(allow file-read* file-write* (subpath \"/work\"))")
        .unwrap();
    let deny = lines
        .iter()
        .position(|l| *l == "(deny file-write* (subpath \"/work/.git\"))")
        .unwrap();
    assert!(allow < deny);
    assert!(lines.contains(&"(deny file-write-unlink (path-ancestors \"/work/.git\"))"));
    assert!(lines.contains(&"(deny file-write-unlink (literal \"/work\"))"));
}

#[test]
fn a_raw_allow_cannot_override_protect_or_the_tier() {
    use procage_policy::seatbelt::{Effect, Filter, Layer, Operation, Rule};
    let mut p = reference_policy(Construct::FsProtect);
    p.seatbelt = Some(Layer {
        rules: vec![
            Rule {
                effect: Effect::Allow,
                ops: vec![Operation::FileWriteAll],
                filters: vec![Filter::Subpath(path("/work/.git"))],
            },
            Rule {
                effect: Effect::Allow,
                ops: vec![Operation::Lsopen],
                filters: vec![],
            },
        ],
    });
    let plan = seatbelt_plan(&p, &LowerOptions::default());
    let lines = rules(&plan.profile);
    let raw = lines
        .iter()
        .position(|l| *l == "(allow file-write* (subpath \"/work/.git\"))")
        .unwrap();
    let protect = lines
        .iter()
        .position(|l| *l == "(deny file-write* (subpath \"/work/.git\"))")
        .unwrap();
    let raw_lsopen = lines.iter().position(|l| *l == "(allow lsopen)").unwrap();
    let tier_lsopen = lines.iter().position(|l| *l == "(deny lsopen)").unwrap();
    assert!(raw < protect && raw_lsopen < tier_lsopen);
}

#[test]
fn waivers_remove_exactly_their_class_and_are_listed() {
    let base = hard_deny_base();
    let full = seatbelt_plan(&base, &LowerOptions::default());
    assert!(full.waivers.is_empty());
    for &class in HardDenyClass::ALL {
        let mut p = base.clone();
        p.waive.insert(class);
        let plan = seatbelt_plan(&p, &LowerOptions::default());
        assert_eq!(plan.waivers, vec![class]);
        let removed = class_lines(class, &base);
        let kept: BTreeSet<_> = rules(&plan.profile).into_iter().collect();
        for line in rules(&full.profile) {
            assert_eq!(
                kept.contains(line),
                !removed.contains(line),
                "{class}: {line}"
            );
        }
        // Linux lists the waiver too (the base's write rule reaches the
        // data classes, which T1 masks at spawn: an approximation).
        let t1 = Target::Linux {
            tier: Tier::T1,
            landlock_abi: 8,
        };
        let masked = LowerOptions::default()
            .allow(Construct::HdSecrets)
            .allow(Construct::HdTrustHandoff)
            .allow(Construct::HdPersistence);
        assert_eq!(lower(&p, t1, &masked).unwrap().waivers(), &[class]);
    }
    // Classes that apply on macOS emit something when not waived.
    for class in [
        HardDenyClass::FcntlModify,
        HardDenyClass::Privilege,
        HardDenyClass::ServiceHandoff,
        HardDenyClass::ProcessAccess,
        HardDenyClass::RenameAnchors,
        HardDenyClass::TerminalInjection,
    ] {
        assert!(!class_lines(class, &base).is_empty(), "{class}");
    }
}

#[test]
fn duplicate_rules_collapse() {
    let mut p = read_only();
    p.fs.push(subpath(Access::Read, "/work"));
    let a = seatbelt_plan(&p, &LowerOptions::default());
    let b = seatbelt_plan(&read_only(), &LowerOptions::default());
    assert_eq!(a.profile, b.profile);
}

/// No allow appears without a source in the policy.
#[test]
fn every_allow_has_a_source() {
    let allows = |p: &Policy| -> BTreeSet<String> {
        let plan = seatbelt_plan(p, &LowerOptions::default());
        rules(&plan.profile)
            .into_iter()
            .filter(|l| l.starts_with("(allow"))
            .map(String::from)
            .collect()
    };
    // The process-access class's allow of the run's own process information
    // is the only allow without a rule of the policy.
    let class_allow = "(allow process-info-pidinfo (target same-sandbox))".to_string();
    assert_eq!(
        allows(&Policy::default()),
        BTreeSet::from([class_allow.clone()])
    );
    for composite in [agent_workspace(), build(), read_only()] {
        let mut union = BTreeSet::new();
        let mut parts = Vec::new();
        for rule in &composite.fs {
            let mut p = Policy::default();
            p.fs.push(rule.clone());
            parts.push(p);
        }
        for g in &composite.grants {
            let mut p = Policy::default();
            p.grants.push(g.clone());
            parts.push(p);
        }
        let mut p = Policy::default();
        p.net = composite.net.clone();
        parts.push(p);
        let mut p = Policy::default();
        p.process = composite.process.clone();
        parts.push(p);
        let mut p = Policy::default();
        p.ipc = composite.ipc.clone();
        parts.push(p);
        for part in &parts {
            union.extend(allows(part));
        }
        assert_eq!(allows(&composite), union);
    }
}
