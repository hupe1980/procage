//! The limits guard: a rule limit that fails closed, and one rewrite that
//! never changes a decision.

mod common;

use common::*;
use procage_policy::sbpl::{Filter, MAX_MERGED_FILTERS, Rule, merge_adjacent};
use procage_policy::seatbelt::Effect;
use procage_policy::*;

const OPS: &[&[&str]] = &[
    &["file-read*"],
    &["file-read*", "file-write*"],
    &["file-write*"],
    &["process-exec*"],
];
const REQUEST_OPS: &[&str] = &[
    "file-read-data",
    "file-write-data",
    "file-write-unlink",
    "process-exec",
];
const PATHS: &[&str] = &["/", "/a", "/a/b", "/a/b/c", "/ab", "/b", "/b/c", "/c"];

fn random_rules(rng: &mut Rng) -> Vec<Rule> {
    let n = 1 + rng.below(12);
    (0..n)
        .map(|_| {
            let effect = if rng.chance(60) {
                Effect::Allow
            } else {
                Effect::Deny
            };
            let ops = rng.pick(OPS);
            let filters = (0..rng.below(3))
                .map(|_| {
                    let p = rng.pick(PATHS).as_bytes().to_vec();
                    match rng.below(3) {
                        0 => Filter::Literal(p),
                        1 => Filter::Subpath(p),
                        _ => Filter::Extension(format!("procage.g{}", rng.below(2))),
                    }
                })
                .collect();
            Rule::new(effect, ops, filters)
        })
        .collect()
}

#[test]
fn merging_never_changes_a_decision() {
    let mut rng = Rng::new(2026);
    let mut merges = 0;
    for _ in 0..CASES {
        let mut rules = random_rules(&mut rng);
        if rng.chance(50) {
            rules.sort();
        }
        let max = 1 + rng.below(MAX_MERGED_FILTERS);
        let merged = merge_adjacent(rules.clone(), max);
        merges += rules.len() - merged.len();
        for _ in 0..8 {
            let req = Request {
                op: rng.pick(REQUEST_OPS),
                path: rng.pick(PATHS).as_bytes().to_vec(),
                extension: rng.chance(30).then(|| format!("procage.g{}", rng.below(2))),
            };
            assert_eq!(
                eval(&rules, &req),
                eval(&merged, &req),
                "{rules:?}\n{merged:?}\n{req:?}"
            );
        }
        for pair in merged.windows(2) {
            if pair[0].effect == pair[1].effect && pair[0].ops == pair[1].ops {
                // Neighbours stay apart only when one group is full.
                assert!(
                    !pair[0].filters.is_empty()
                        && !pair[1].filters.is_empty()
                        && pair[0].filters.len() + pair[1].filters.len() > max,
                    "unmerged neighbours: {pair:?}"
                );
            }
        }
    }
    assert!(
        merges > 1000,
        "the generator rarely triggered a merge ({merges})"
    );
}

#[test]
fn merged_rules_never_mix_effects() {
    let lit = |s: &str| Filter::Literal(s.as_bytes().to_vec());
    let rules = vec![
        Rule::new(Effect::Allow, &["file-read*"], vec![lit("/a")]),
        Rule::new(Effect::Deny, &["file-read*"], vec![lit("/a")]),
        Rule::new(Effect::Allow, &["file-read*"], vec![lit("/b")]),
    ];
    assert_eq!(merge_adjacent(rules.clone(), MAX_MERGED_FILTERS), rules);
}

fn literal_policy(n: usize, access: impl Fn(usize) -> Access) -> Policy {
    let mut p = Policy::default();
    for i in 0..n {
        p.fs.push(FsRule::new(
            access(i),
            FsTarget::Literal(path(&format!("/data/f{i:05}"))),
        ));
    }
    p
}

#[test]
fn over_the_limit_fails_closed() {
    use procage_policy::seatbelt::{Layer, Operation, Rule as RawRule};
    // 2,001 raw rules, each over a different pair of operations: nothing can
    // merge, because merging needs equal operation lists.
    let all = Operation::ALL;
    let rules: Vec<RawRule> = (0..all.len())
        .flat_map(|i| (i + 1..all.len()).map(move |j| (i, j)))
        .take(2001)
        .map(|(i, j)| RawRule {
            effect: Effect::Allow,
            ops: vec![all[i].clone(), all[j].clone()],
            filters: vec![],
        })
        .collect();
    let mut p = Policy::default();
    p.seatbelt = Some(Layer { rules });
    match lower(&p, Target::MacOs, &LowerOptions::default()) {
        Err(LowerError::LimitExceeded { limit, rules }) => {
            assert_eq!(limit, 2000);
            assert!(rules > 2000, "{rules}");
        }
        other => panic!("expected LimitExceeded, got {:?}", other.map(|_| ())),
    }
    // Over a configured limit even after merging: 21 groups of 64 literals.
    let p = literal_policy(21 * MAX_MERGED_FILTERS, |_| Access::Read);
    assert!(matches!(
        lower(
            &p,
            Target::MacOs,
            &LowerOptions::default().with_max_rules(20)
        ),
        Err(LowerError::LimitExceeded { limit: 20, .. })
    ));
    assert!(matches!(
        lower(
            &read_only(),
            Target::MacOs,
            &LowerOptions::default().with_max_rules(5)
        ),
        Err(LowerError::LimitExceeded { limit: 5, .. })
    ));
}

#[test]
fn a_mergeable_policy_passes_the_limit_unchanged_in_meaning() {
    let p = literal_policy(5000, |_| Access::Read);
    let plan = seatbelt_plan(&p, &LowerOptions::default());
    assert!(plan.merged);
    assert!(plan.rule_count <= 2000, "{}", plan.rule_count);
    let unmerged = seatbelt_plan(&p, &LowerOptions::default().with_max_rules(usize::MAX));
    assert!(!unmerged.merged);
    assert!(unmerged.rule_count > 5000);
    // Every literal is still there, once.
    for i in [0, 1234, 4999] {
        let needle = format!("(literal \"/data/f{i:05}\")");
        assert_eq!(plan.profile.matches(&needle).count(), 1, "{needle}");
    }
    assert!(plan.profile.contains("(require-any"));
}
