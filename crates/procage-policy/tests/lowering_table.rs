//! The lowering table in the crate docs is the fixture: every construct is
//! lowered for every target and ABI, and the outcome must be the one the
//! table states.

mod common;

use std::collections::BTreeSet;

use common::{class_of, reference_policy};
use procage_policy::path::AbsPath;
use procage_policy::*;

const TABLE: &str = include_str!("../src/lowering.md");
const HEADER: &str = "| Construct | macOS | Linux T1 | Linux T2 | Note |";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Cell {
    Exact,
    Approximated,
    Unsupported,
    NotApplicable,
}

#[derive(Debug, Clone, Copy)]
enum Column {
    Fixed(Cell),
    /// `<at least> (ABI ≥ n) / <below>`.
    Abi {
        n: u8,
        at_least: Cell,
        below: Cell,
    },
}

impl Column {
    fn at(self, abi: u8) -> Cell {
        match self {
            Column::Fixed(c) => c,
            Column::Abi { n, at_least, below } => {
                if abi >= n {
                    at_least
                } else {
                    below
                }
            }
        }
    }
}

fn cell(text: &str) -> Result<Cell, String> {
    match text {
        "exact" => Ok(Cell::Exact),
        "approximated" => Ok(Cell::Approximated),
        "unsupported" => Ok(Cell::Unsupported),
        "n/a" => Ok(Cell::NotApplicable),
        other => Err(format!("unknown outcome {other:?}")),
    }
}

fn column(text: &str, linux: bool) -> Result<Column, String> {
    if let Some((left, below)) = text.split_once(" / ") {
        if !linux {
            return Err(format!(
                "ABI-dependent cell {text:?} outside a Linux column"
            ));
        }
        let (at_least, rest) = left
            .split_once(" (ABI ≥ ")
            .ok_or_else(|| format!("malformed cell {text:?}"))?;
        let n = rest
            .strip_suffix(')')
            .and_then(|n| n.parse().ok())
            .ok_or_else(|| format!("malformed ABI in {text:?}"))?;
        return Ok(Column::Abi {
            n,
            at_least: cell(at_least)?,
            below: cell(below)?,
        });
    }
    cell(text).map(Column::Fixed)
}

struct Row {
    construct: Construct,
    mac: Column,
    t1: Column,
    t2: Column,
}

fn parse() -> Vec<Row> {
    let section = TABLE
        .split_once("## Lowering table\n")
        .expect("heading `## Lowering table`")
        .1;
    let mut lines = section.lines().skip_while(|l| l.trim().is_empty());
    assert_eq!(lines.next(), Some(HEADER), "table header");
    assert!(
        lines.next().is_some_and(|l| l.starts_with("|---")),
        "separator row"
    );
    let mut rows = Vec::new();
    let mut seen = BTreeSet::new();
    for line in lines.take_while(|l| l.starts_with('|')) {
        let cells: Vec<&str> = line.trim_matches('|').split('|').map(str::trim).collect();
        assert_eq!(cells.len(), 5, "row {line:?} must have 5 cells");
        let name = cells[0]
            .strip_prefix('`')
            .and_then(|c| c.strip_suffix('`'))
            .unwrap_or_else(|| panic!("construct cell {:?} must be backticked", cells[0]));
        let construct: Construct = name.parse().unwrap_or_else(|e| panic!("{e}"));
        assert!(seen.insert(construct), "construct {name} listed twice");
        let parse_col = |i: usize, linux: bool| {
            column(cells[i], linux).unwrap_or_else(|e| panic!("{name}: {e}"))
        };
        rows.push(Row {
            construct,
            mac: parse_col(1, false),
            t1: parse_col(2, true),
            t2: parse_col(3, true),
        });
    }
    for construct in Construct::ALL {
        assert!(
            seen.contains(construct),
            "construct {construct} missing from the table"
        );
    }
    rows
}

const DATA_CLASSES: [HardDenyClass; 3] = [
    HardDenyClass::Secrets,
    HardDenyClass::TrustHandoff,
    HardDenyClass::Persistence,
];

/// The reference policy of `construct`, measured in isolation: the data
/// classes react to any rule that can reach their paths, so they are waived
/// for every other row, and their own rows use a rule that reaches them.
fn isolated(construct: Construct) -> Policy {
    let mut p = reference_policy(construct);
    match class_of(construct) {
        Some(class) if DATA_CLASSES.contains(&class) => {
            p.fs.push(FsRule::new(
                Access::Write,
                FsTarget::Subpath(AbsPath::new("/home").unwrap()),
            ));
            p.waive
                .extend(DATA_CLASSES.into_iter().filter(|&c| c != class));
        }
        _ => p.waive.extend(DATA_CLASSES),
    }
    p
}

/// The policy without `construct`: waived for hard-deny classes.
fn without(construct: Construct) -> Policy {
    let mut p = isolated(construct);
    let class = class_of(construct).expect("n/a is only used for hard-deny classes");
    p.waive.insert(class);
    p
}

fn comparable(plan: Plan) -> Plan {
    match plan {
        Plan::Seatbelt(mut p) => {
            p.waivers.clear();
            Plan::Seatbelt(p)
        }
        Plan::Linux(mut p) => {
            p.waivers.clear();
            Plan::Linux(p)
        }
    }
}

fn has_gap(result: &Result<Plan, LowerError>, construct: Construct, kind: &GapKind) -> bool {
    matches!(result, Err(LowerError::Gaps(gaps)) if gaps.iter().any(|g| g.construct == construct && g.kind == *kind))
}

fn check(construct: Construct, target: Target, expected: Cell) -> Result<(), String> {
    let policy = isolated(construct);
    let plain = LowerOptions::default();
    let allowed = LowerOptions::default().allow(construct);
    let result = lower(&policy, target, &plain);
    let with_allow = lower(&policy, target, &allowed);
    let degraded = |r: &Result<Plan, LowerError>| -> Result<usize, String> {
        r.as_ref()
            .map(|p| {
                p.degradations()
                    .iter()
                    .filter(|d| d.construct == construct)
                    .count()
            })
            .map_err(|e| e.to_string())
    };
    match expected {
        Cell::Exact => match degraded(&result) {
            Ok(0) => Ok(()),
            other => Err(format!("expected exact, got {other:?} / {result:?}")),
        },
        Cell::Approximated => {
            if !has_gap(&result, construct, &GapKind::Approximation) {
                return Err(format!("expected an approximation gap, got {result:?}"));
            }
            match degraded(&with_allow) {
                Ok(1) => Ok(()),
                other => Err(format!(
                    "allowed approximation should give one degradation, got {other:?}"
                )),
            }
        }
        Cell::Unsupported => {
            if has_gap(&result, construct, &GapKind::Unsupported)
                && has_gap(&with_allow, construct, &GapKind::Unsupported)
            {
                Ok(())
            } else {
                Err(format!(
                    "expected an unsupported gap with and without permission, got {result:?}"
                ))
            }
        }
        Cell::NotApplicable => {
            let a = result.map(comparable).map_err(|e| e.to_string())?;
            let b = lower(&without(construct), target, &plain)
                .map(comparable)
                .map_err(|e| e.to_string())?;
            if a == b {
                Ok(())
            } else {
                Err("n/a construct changed the plan".into())
            }
        }
    }
}

fn abis(tier: Tier, column: Column) -> Vec<u8> {
    let min = tier.min_landlock_abi();
    let mut out: Vec<u8> = match tier {
        Tier::T1 => vec![1, 8, 12],
        Tier::T2 => vec![4, 5, 6, 8, 9, 12],
    };
    if let Column::Abi { n, .. } = column {
        out.extend([n.saturating_sub(1), n]);
    }
    out.retain(|&abi| abi >= min);
    out.sort();
    out.dedup();
    out
}

#[test]
fn every_row_matches_the_lowering() {
    let mut failures = Vec::new();
    let rows = parse();
    for row in &rows {
        let mut cases = vec![(Target::MacOs, row.mac.at(0))];
        for (tier, col) in [(Tier::T1, row.t1), (Tier::T2, row.t2)] {
            for abi in abis(tier, col) {
                cases.push((
                    Target::Linux {
                        tier,
                        landlock_abi: abi,
                    },
                    col.at(abi),
                ));
            }
        }
        for (target, expected) in cases {
            if let Err(e) = check(row.construct, target, expected) {
                failures.push(format!("{} on {target}: {e}", row.construct));
            }
        }
    }
    assert!(
        failures.is_empty(),
        "{} mismatches:\n{}",
        failures.len(),
        failures.join("\n")
    );
    assert_eq!(rows.len(), Construct::ALL.len());
}

#[test]
fn a_changed_cell_is_detected() {
    // fs-protect on T2 is unsupported; claiming exact must fail the check.
    let target = Target::Linux {
        tier: Tier::T2,
        landlock_abi: 6,
    };
    assert!(check(Construct::FsProtect, target, Cell::Exact).is_err());
    assert!(check(Construct::FsProtect, target, Cell::Unsupported).is_ok());
}
