//! Lowered Seatbelt profiles compile through libsandbox.
//!
//! This is a **well-formedness check only**. It shows that libsandbox accepts
//! the profiles procage-policy writes, and every operation of its closed list.
//! It does not apply any profile and is not evidence that anything is
//! enforced; enforcement is established by tests that cage a real child.

#![cfg(target_os = "macos")]

#[path = "../../procage-policy/tests/common/mod.rs"]
mod common;

use procage_kernel_facts::sys::macos::Sandbox;
use procage_policy::seatbelt::Operation;
use procage_policy::{
    Access, LowerOptions, Plan, Policy, RUN_MARKER_PARAM, RUN_PREFIX_PARAM, SeatbeltPlan, Tag,
    Target, lower,
};

fn compile(sandbox: &Sandbox, profile: &str, params: &[(String, String)]) -> Result<usize, String> {
    let params: Vec<(&str, &str)> = params
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
    sandbox
        .compile(profile, &params)
        .map(|bytecode| bytecode.data.len())
        .map_err(|e| e.text.unwrap_or_else(|| "<no error text>".into()))
}

/// The plan's parameters, plus run-marker values like the ones the spawn
/// backend binds.
fn bound(plan: &SeatbeltPlan) -> Vec<(String, String)> {
    let mut params = plan.params.clone();
    if plan.run_marker {
        params.push((RUN_PREFIX_PARAM.into(), "org.procage.run.check.".into()));
        params.push((RUN_MARKER_PARAM.into(), "org.procage.run.check.0".into()));
    }
    params
}

#[test]
fn every_reference_profile_compiles() {
    let sandbox = Sandbox::load().expect("libsandbox symbols");
    let options = common::allow_all().with_tag(Tag::new("procage-policy-check").unwrap());
    let mut failures = Vec::new();
    let mut count = 0;
    for (name, policy) in common::reference_policies() {
        let Ok(Plan::Seatbelt(plan)) = lower(&policy, Target::MacOs, &options) else {
            panic!("{name}: no Seatbelt plan");
        };
        count += 1;
        if let Err(e) = compile(&sandbox, &plan.profile, &bound(&plan)) {
            failures.push(format!("{name}: {e}\n{}", plan.profile));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n\n"));
    assert!(count >= 35, "{count} profiles");
}

#[test]
fn a_parameter_backed_long_path_compiles() {
    let sandbox = Sandbox::load().expect("libsandbox symbols");
    let long = format!("/tmp/{}", "a".repeat(1500));
    let mut policy = Policy::default();
    policy.fs.push(common::subpath(Access::Read, &long));
    let Ok(Plan::Seatbelt(plan)) = lower(&policy, Target::MacOs, &LowerOptions::default()) else {
        panic!("no Seatbelt plan");
    };
    assert_eq!(plan.params.len(), 1);
    compile(&sandbox, &plan.profile, &plan.params)
        .unwrap_or_else(|e| panic!("{e}\n{}", plan.profile));
    // Without the parameter value the profile must not compile: the value
    // really travels in the plan, not in the text.
    assert!(compile(&sandbox, &plan.profile, &[]).is_err());
}

#[test]
fn every_operation_of_the_closed_list_compiles() {
    let sandbox = Sandbox::load().expect("libsandbox symbols");
    let failures: Vec<String> = Operation::ALL
        .iter()
        .filter_map(|op| {
            let profile = format!("(version 1)\n(deny default)\n(allow {})\n", op.as_str());
            compile(&sandbox, &profile, &[])
                .err()
                .map(|e| format!("{op}: {e}"))
        })
        .collect();
    assert!(failures.is_empty(), "{}", failures.join("\n"));
    assert_eq!(Operation::ALL.len(), 112);
}
