//! Presets V1 and the data-driven class lists are frozen: their lowered
//! macOS profiles (workspace `/work`) are pinned as fixtures.

mod common;

use procage_policy::presets::{self, agent_readonly, agent_workspace, build, minimal};
use procage_policy::*;

fn profile(p: &Policy) -> String {
    match lower(p, Target::MacOs, &LowerOptions::default()) {
        Ok(Plan::Seatbelt(plan)) => plan.profile,
        other => panic!("{other:?}"),
    }
}

fn all() -> Vec<(&'static str, Policy)> {
    let w = AbsPath::new("/work").unwrap();
    vec![
        ("minimal", minimal::v1()),
        ("agent_readonly", agent_readonly::v1(&w)),
        ("agent_workspace", agent_workspace::v1(&w)),
        ("build", build::v1(&w)),
    ]
}

#[test]
fn every_preset_is_pinned() {
    let fixtures = [
        include_str!("fixtures/presets/minimal-v1.sb"),
        include_str!("fixtures/presets/agent_readonly-v1.sb"),
        include_str!("fixtures/presets/agent_workspace-v1.sb"),
        include_str!("fixtures/presets/build-v1.sb"),
    ];
    for ((name, policy), fixture) in all().into_iter().zip(fixtures) {
        assert_eq!(profile(&policy), fixture, "preset {name} v1 changed");
    }
}

#[test]
fn presets_carry_their_tag_and_the_full_tier() {
    for (name, policy) in all() {
        assert_eq!(
            policy.preset,
            Some(PresetTag {
                name: name.into(),
                version: 1
            })
        );
        assert_eq!(policy.base, Base::V1);
        assert!(policy.waive.is_empty(), "{name} waives a class");
        for class in [
            HardDenyClass::Secrets,
            HardDenyClass::TrustHandoff,
            HardDenyClass::Persistence,
        ] {
            assert!(!presets::patterns(class).is_empty());
        }
    }
}

#[test]
fn the_class_lists_are_pinned() {
    assert_eq!(presets::SECRETS_HOME.len(), 20);
    assert_eq!(presets::HANDOFF_ANYWHERE.len(), 20);
    assert_eq!(
        presets::HANDOFF_HOME,
        [".cargo/bin", ".local/bin", ".ssh/config"]
    );
    assert_eq!(
        presets::PERSISTENCE_SYSTEM,
        ["/Library/LaunchAgents", "/Library/LaunchDaemons"]
    );
    let lines = profile(&minimal::v1());
    for (needle, class) in [
        (r#"\\.[sS][sS][hH](/.*)?$"#, "secrets"),
        (
            r#"\\.[gG][iI][tT]/[hH][oO][oO][kK][sS](/.*)?$"#,
            "trust-handoff",
        ),
        (
            r#"[lL][aA][uU][nN][cC][hH][aA][gG][eE][nN][tT][sS](/.*)?$"#,
            "persistence",
        ),
        (
            r#"(deny file-write-unlink (regex "^/(.*/)?\\.[gG][iI][tT]$"))"#,
            "git dir",
        ),
    ] {
        assert!(lines.contains(needle), "{class} pattern missing");
    }
}

#[cfg(feature = "serde")]
#[test]
fn presets_round_trip_with_their_tag() {
    for (name, policy) in all() {
        let text = serde_json::to_string(&policy).unwrap();
        assert!(
            text.contains(&format!(r#""preset":{{"name":"{name}","version":1}}"#)),
            "{text}"
        );
        assert_eq!(serde_json::from_str::<Policy>(&text).unwrap(), policy);
    }
}
