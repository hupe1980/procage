//! Reporting denials: the rule messages are the only difference, they name
//! the run marker and the rule's kind, and the run-marker block has none.

mod common;

use procage_policy::{
    DenyReason, HardDenyClass, LowerOptions, Plan, Policy, RUN_MARKER_PARAM, RUN_PREFIX_PARAM,
    Target, lower,
};

fn profile(policy: &Policy, options: &LowerOptions) -> String {
    match lower(policy, Target::MacOs, options) {
        Ok(Plan::Seatbelt(plan)) => plan.profile,
        other => panic!("no Seatbelt plan: {other:?}"),
    }
}

/// The profile with every reporting message removed.
fn stripped(text: &str) -> String {
    let default = format!("(deny default (with message (param \"{RUN_MARKER_PARAM}\")))");
    text.lines()
        .map(|line| {
            if line == default {
                return "(deny default)".to_string();
            }
            match line.find(" (with message (string-append") {
                Some(at) => format!("{})", &line[..at]),
                None => line.to_string(),
            }
        })
        .map(|line| line + "\n")
        .collect()
}

#[test]
fn every_code_round_trips_and_is_one_word() {
    let mut reasons = vec![DenyReason::Protect, DenyReason::Hide, DenyReason::Layer];
    reasons.extend(HardDenyClass::ALL.iter().map(|&c| DenyReason::HardDeny(c)));
    for reason in reasons {
        let code = reason.code();
        assert!(!code.contains([' ', '\n', '"']), "{code}");
        assert_eq!(DenyReason::from_code(&code), Some(reason), "{code}");
    }
    for unknown in ["", "hd:", "hd:nothing", "Protect", "hide "] {
        assert_eq!(DenyReason::from_code(unknown), None, "{unknown:?}");
    }
}

/// Reporting changes nothing but messages, for every reference policy.
#[test]
fn reporting_adds_only_messages() {
    let off = common::allow_all();
    let on = common::allow_all().with_violations();
    let mut reported = 0;
    for (name, policy) in common::reference_policies() {
        let without = profile(&policy, &off);
        let with = profile(&policy, &on);
        assert!(!without.contains("with message"), "{name}");
        assert_eq!(stripped(&with), without, "{name}");
        reported += with.matches("(with message (string-append").count();
    }
    assert!(reported > 0);
}

#[test]
fn the_run_marker_block_carries_no_message() {
    let on = common::allow_all().with_violations();
    let text = profile(&common::agent_workspace(), &on);
    let marker: Vec<&str> = text
        .lines()
        .filter(|l| l.contains(RUN_PREFIX_PARAM) || l.contains("global-name (param"))
        .collect();
    assert!(!marker.is_empty(), "{text}");
    for line in marker {
        assert!(!line.contains("with message"), "{line}");
    }
}

#[test]
fn each_deny_names_its_kind() {
    let mut policy = common::agent_workspace();
    policy.waive.clear();
    let text = profile(&policy, &LowerOptions::default().with_violations());
    let code = |reason: DenyReason| format!("\" {}\"))", reason.code());
    let line_with = |needle: &str, reason: DenyReason| {
        text.lines()
            .find(|l| l.contains(needle) && l.ends_with(&format!("{})", code(reason))))
            .unwrap_or_else(|| panic!("no {needle} line with {reason:?} in\n{text}"))
    };
    line_with("/work/.git", DenyReason::Protect);
    line_with("/work/.env", DenyReason::Hide);
    line_with(
        "file-write-setugid",
        DenyReason::HardDeny(HardDenyClass::Privilege),
    );
    line_with(
        "file-ioctl",
        DenyReason::HardDeny(HardDenyClass::TerminalInjection),
    );
    // A data class names the class, not the access it lowers to.
    let secrets = code(DenyReason::HardDeny(HardDenyClass::Secrets));
    assert!(
        text.lines().any(|l| l.ends_with(&format!("{secrets})"))),
        "{text}"
    );
    // The default names only the marker.
    assert!(text.contains(&format!(
        "(deny default (with message (param \"{RUN_MARKER_PARAM}\")))"
    )));
}

#[test]
fn a_raw_layer_deny_is_a_layer_denial() {
    use procage_policy::seatbelt::{Effect, Layer, Operation, Rule};
    let mut policy = Policy::default();
    policy.seatbelt = Some(Layer {
        rules: vec![Rule {
            effect: Effect::Deny,
            ops: vec![Operation::SysctlRead],
            filters: vec![],
        }],
    });
    let text = profile(&policy, &common::allow_all().with_violations());
    let layer = format!(
        "(deny sysctl-read (with message (string-append (param \"{RUN_MARKER_PARAM}\") \" layer\")))"
    );
    assert!(text.lines().any(|l| l == layer), "{text}");
}
