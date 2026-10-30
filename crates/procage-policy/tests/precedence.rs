//! Fixed precedence: allows, then deny-within-allow, then the hard-deny tier
//! last; independent of rule order; waivers by name and recorded.

mod common;

use std::collections::BTreeSet;

use common::*;
use procage_policy::*;

/// Splits a profile into its rule lines (after `(deny default)`).
fn rules(profile: &str) -> Vec<&str> {
    profile.lines().skip(2).collect()
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
    let hard: BTreeSet<String> = HardDenyClass::ALL
        .iter()
        .flat_map(|&c| class_lines(c, &hard_deny_base()))
        .collect();
    for (name, policy) in reference_policies() {
        let Ok(Plan::Seatbelt(plan)) = lower(&policy, Target::MacOs, &allow_all()) else {
            panic!("{name}: no Seatbelt plan");
        };
        let lines = rules(&plan.profile);
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
            plan.profile
                .ends_with("(deny system-fcntl (fcntl-command 80 110))\n")
        );
    }
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
        // Linux lists the waiver too.
        let t1 = Target::Linux {
            tier: Tier::T1,
            landlock_abi: 8,
        };
        assert_eq!(
            lower(&p, t1, &LowerOptions::default()).unwrap().waivers(),
            &[class]
        );
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

/// FR-018: no allow appears without a source in the policy.
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
    assert!(allows(&Policy::default()).is_empty());
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
