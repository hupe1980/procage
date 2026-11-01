//! Every seccomp rule says why it refuses, and its condition decides like
//! the filter.

mod common;

use procage_policy::linux::{CLONE_THREAD, Condition, O_TRUNC, SeccompRule, Syscall};
use procage_policy::{
    DenyReason, HardDenyClass, Lifetime, LowerOptions, Network, Plan, Policy, Target, Tier, linux,
    lower,
};

fn rules(policy: &Policy, abi: u8) -> Vec<SeccompRule> {
    let target = Target::Linux {
        tier: Tier::T1,
        landlock_abi: abi,
    };
    match lower(policy, target, &LowerOptions::default()) {
        Ok(Plan::Linux(plan)) => plan.seccomp,
        other => panic!("{other:?}"),
    }
}

fn reason(rules: &[SeccompRule], syscall: &str) -> Option<DenyReason> {
    let call = Syscall::from_name(syscall).unwrap();
    rules
        .iter()
        .find(|r| r.syscall == call)
        .unwrap_or_else(|| panic!("no rule for {syscall}"))
        .reason
}

#[test]
fn each_origin_names_its_reason() {
    let mut policy = Policy::default();
    policy.net = Network::None;
    policy.process.fork = true;
    policy.process.lifetime = Lifetime::Run;
    policy.linux = Some(linux::Layer {
        syscalls_deny: vec![Syscall::from_name("acct").unwrap()],
        landlock_extra: vec![],
    });
    let r = rules(&policy, 2);
    assert_eq!(
        reason(&r, "ptrace"),
        Some(DenyReason::HardDeny(HardDenyClass::ProcessAccess))
    );
    assert_eq!(
        reason(&r, "io_uring_setup"),
        Some(DenyReason::HardDeny(HardDenyClass::KernelSurface))
    );
    assert_eq!(
        reason(&r, "unshare"),
        Some(DenyReason::HardDeny(HardDenyClass::Namespaces))
    );
    assert_eq!(reason(&r, "socket"), None, "no network: not granted");
    assert_eq!(reason(&r, "setsid"), Some(DenyReason::Lifetime));
    assert_eq!(reason(&r, "truncate"), Some(DenyReason::OlderKernel));
    assert_eq!(reason(&r, "acct"), Some(DenyReason::Layer));
    // The guard is only there below ABI 3.
    assert!(
        rules(&policy, 3)
            .iter()
            .all(|r| r.reason != Some(DenyReason::OlderKernel))
    );
}

#[test]
fn a_layer_repeating_a_class_keeps_the_class() {
    let mut policy = Policy::default();
    policy.linux = Some(linux::Layer {
        syscalls_deny: vec![Syscall::from_name("ptrace").unwrap()],
        landlock_extra: vec![],
    });
    let r = rules(&policy, 8);
    let ptrace: Vec<_> = r
        .iter()
        .filter(|x| x.syscall == Syscall::from_name("ptrace").unwrap())
        .collect();
    assert_eq!(ptrace.len(), 1, "{ptrace:?}");
    assert!(ptrace[0].reason.is_some());
}

#[test]
fn the_new_codes_round_trip() {
    for reason in [DenyReason::Lifetime, DenyReason::OlderKernel] {
        assert_eq!(DenyReason::from_code(&reason.code()), Some(reason));
    }
}

#[test]
fn conditions_use_the_low_32_bits_like_the_filter() {
    let high = 1u64 << 32;
    assert!(Condition::SocketFamily(vec![2]).matches(&[2 | high, 0, 0, 0, 0, 0]));
    assert!(!Condition::SocketFamilyExcept(vec![1]).matches(&[1 | high, 0, 0, 0, 0, 0]));
    assert!(Condition::CloneWithoutThread.matches(&[
        u64::from(!CLONE_THREAD) & 0xffff,
        0,
        0,
        0,
        0,
        0
    ]));
    assert!(!Condition::CloneWithoutThread.matches(&[u64::from(CLONE_THREAD), 0, 0, 0, 0, 0]));
    let trunc = Condition::TruncWithoutWrite { flags_arg: 2 };
    assert!(trunc.matches(&[0, 0, u64::from(O_TRUNC), 0, 0, 0]));
    assert!(!trunc.matches(&[0, 0, u64::from(O_TRUNC | 1), 0, 0, 0]));
    assert!(trunc.matches(&[0, 0, u64::from(O_TRUNC | 3), 0, 0, 0]));
    let _ = common::path("/x");
}
