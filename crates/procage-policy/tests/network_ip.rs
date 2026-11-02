//! `Network::Ip`: the IP network, with Unix sockets as with the network off.

use procage_policy::linux::{AF_INET, AF_INET6, AF_UNIX, Condition, Syscall};
use procage_policy::*;

fn linux(tier: Tier, landlock_abi: u8) -> Target {
    Target::Linux { tier, landlock_abi }
}

fn ip() -> Policy {
    let mut p = Policy::default();
    p.net = Network::Ip;
    p
}

fn linux_plan(p: &Policy, target: Target) -> LinuxPlan {
    let options = LowerOptions::default().accept_spawn_snapshot();
    match lower(p, target, &options) {
        Ok(Plan::Linux(plan)) => plan,
        other => panic!("{target}: {other:?}"),
    }
}

/// The families `socket()` is allowed for, from the plan's one
/// "every family but" rule.
fn allowed_families(plan: &LinuxPlan) -> Vec<u32> {
    let rules: Vec<&Vec<u32>> = plan
        .seccomp
        .iter()
        .filter(|r| r.syscall == Syscall::Socket)
        .filter_map(|r| match &r.condition {
            Condition::SocketFamilyExcept(families) => Some(families),
            _ => None,
        })
        .collect();
    assert_eq!(rules.len(), 1, "{:?}", plan.seccomp);
    rules[0].clone()
}

#[test]
fn only_ip_sockets_are_created_without_a_namespace_or_a_socket_search() {
    for tier in [Tier::T1, Tier::T2] {
        for waived in [false, true] {
            let mut p = ip();
            if waived {
                p.waive.insert(HardDenyClass::SocketFamilies);
            }
            let plan = linux_plan(&p, linux(tier, 8));
            assert_eq!(allowed_families(&plan), [AF_INET, AF_INET6], "{tier:?}");
            assert!(plan.namespaces.is_none_or(|ns| !ns.net), "{tier:?}");
            assert!(plan.service_sockets.is_empty(), "{tier:?}");
            assert!(plan.degradations.is_empty(), "{tier:?}");
        }
    }
}

#[test]
fn unix_sockets_at_their_paths_as_with_the_network_off() {
    let mut p = ip();
    p.ipc.unix_sockets.push(AbsPath::new("/work/run").unwrap());
    for tier in [Tier::T1, Tier::T2] {
        let plan = linux_plan(&p, linux(tier, 9));
        assert_eq!(allowed_families(&plan), [AF_INET, AF_INET6, AF_UNIX]);
        assert!(plan.degradations.is_empty(), "{tier:?}");
    }
    // Below ABI 9 T2 cannot restrict pathname sockets; T1 masks them, and
    // without a network namespace only the scope (ABI 6) keeps abstract
    // sockets out.
    let unsupported = |target: Target| match lower(&p, target, &LowerOptions::default()) {
        Err(LowerError::Gaps(gaps)) => gaps
            .iter()
            .any(|g| g.construct == Construct::IpcUnixSockets && g.kind == GapKind::Unsupported),
        _ => false,
    };
    assert!(unsupported(linux(Tier::T2, 8)));
    assert!(unsupported(linux(Tier::T1, 5)));
    let plan = linux_plan(&p, linux(Tier::T1, 6));
    assert!(
        plan.degradations
            .iter()
            .any(|d| d.construct == Construct::IpcUnixSockets)
    );
}

#[test]
fn macos_allows_ip_addresses_and_the_resolver_only() {
    let Ok(Plan::Seatbelt(plan)) = lower(&ip(), Target::MacOs, &LowerOptions::default()) else {
        panic!("no macOS plan");
    };
    let profile = &plan.profile;
    assert!(!profile.contains("(allow network*"), "{profile}");
    assert!(profile.contains(r#"(remote ip "*:*")"#), "{profile}");
    assert!(profile.contains(r#"(local ip "*:*")"#), "{profile}");
    assert!(
        profile.contains(r#"(remote unix-socket (path-literal "/private/var/run/mDNSResponder"))"#),
        "{profile}"
    );
}

#[test]
fn the_construct_is_exact_everywhere() {
    for target in [Target::MacOs, linux(Tier::T1, 1), linux(Tier::T2, 1)] {
        assert!(
            lower(&ip(), target, &LowerOptions::default()).is_ok(),
            "{target}"
        );
    }
    assert_eq!(Construct::NetIp.as_str(), "net-ip");
}
