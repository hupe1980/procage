//! Lowering to a Seatbelt profile.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;

use super::{
    Construct, GapKind, GrantSlot, Hygiene, Ledger, LowerError, LowerOptions, Outcome,
    SeatbeltPlan, Target, fs_construct, subject_of,
};
use crate::policy::{Access, Base, Exec, FsTarget, HardDenyClass, Network, Policy, Ports, Signals};
use crate::sbpl::{self, Filter, Rule};
use crate::seatbelt::{self, Effect};

/// Operations an access kind allows (or, for protect and hide, denies).
fn ops(access: Access) -> &'static [&'static str] {
    match access {
        Access::Read => &["file-read*"],
        Access::Write => &["file-read*", "file-write*"],
        Access::Exec => &["file-read*", "process-exec*", "file-map-executable"],
        Access::Protect => &["file-write*"],
        Access::Hide => &[
            "file-read*",
            "file-write*",
            "process-exec*",
            "file-map-executable",
        ],
    }
}

fn path_filter(target: &FsTarget) -> Filter {
    match target {
        FsTarget::Literal(p) => Filter::Literal(p.as_bytes().to_vec()),
        FsTarget::Subpath(p) => Filter::Subpath(p.as_bytes().to_vec()),
        FsTarget::Glob(g) => Filter::Regex(g.to_sbpl_regex()),
    }
}

fn loopback(ports: &Ports) -> Vec<String> {
    match ports {
        Ports::Any => vec!["localhost:*".to_string()],
        Ports::List(list) => list.iter().map(|p| format!("localhost:{p}")).collect(),
    }
}

/// Pushes `rule` unless one of its values cannot be quoted, in which case the
/// construct gets an `Unrepresentable` gap.
fn push(
    ledger: &mut Ledger<'_>,
    block: &mut Vec<Rule>,
    construct: Construct,
    subject: Option<String>,
    rule: Rule,
) {
    for value in rule.values() {
        if let Err(e) = sbpl::quote(value) {
            ledger.gap(construct, GapKind::Unrepresentable(e), subject);
            return;
        }
    }
    block.push(rule);
}

fn raw_filter(filter: &seatbelt::Filter) -> Vec<Filter> {
    use seatbelt::Filter as F;
    match filter {
        F::Literal(p) => vec![Filter::Literal(p.as_bytes().to_vec())],
        F::Subpath(p) => vec![Filter::Subpath(p.as_bytes().to_vec())],
        F::Glob(g) => vec![Filter::Regex(g.to_sbpl_regex())],
        F::Extension(name) => vec![Filter::Extension(format!("procage.{name}"))],
        F::GlobalName(n) => vec![Filter::GlobalName(n.as_str().into())],
        F::GlobalNamePrefix(n) => vec![Filter::GlobalNamePrefix(n.as_str().into())],
        F::TargetSelf => vec![Filter::Target("self")],
        F::TargetChildren => vec![Filter::Target("children")],
        F::TargetOthers => vec![Filter::Target("others")],
        F::RemoteLoopback(ports) => loopback(ports).into_iter().map(Filter::RemoteIp).collect(),
        F::LocalLoopback(ports) => loopback(ports).into_iter().map(Filter::LocalIp).collect(),
        F::UnixSocket(p) => vec![Filter::RemoteUnixSocket(p.as_bytes().to_vec())],
    }
}

/// The hard-deny rules of `class` for `policy`.
fn hard_deny(class: HardDenyClass, policy: &Policy) -> Vec<Rule> {
    let deny = |ops: &[&str], filters: Vec<Filter>| Rule::new(Effect::Deny, ops, filters);
    match class {
        HardDenyClass::FcntlModify => vec![deny(
            &["system-fcntl"],
            vec![Filter::FcntlCommand(vec![80, 110])],
        )],
        HardDenyClass::Privilege => vec![
            deny(&["file-write-setugid"], vec![]),
            deny(&["process-exec*"], vec![Filter::FileMode(0o4000)]),
            deny(&["process-exec*"], vec![Filter::FileMode(0o2000)]),
        ],
        HardDenyClass::ServiceHandoff => vec![
            deny(
                &["mach-lookup"],
                vec![
                    Filter::GlobalName("com.apple.coreservices.launchservicesd".into()),
                    Filter::GlobalNamePrefix("com.apple.lsd.".into()),
                    Filter::GlobalName("com.apple.coreservices.appleevents".into()),
                    Filter::GlobalName("com.apple.pasteboard.1".into()),
                ],
            ),
            deny(
                &["mach-lookup"],
                vec![Filter::XpcServiceNamePrefix(String::new())],
            ),
            deny(&["lsopen"], vec![]),
            deny(&["appleevent-send"], vec![]),
        ],
        HardDenyClass::ProcessAccess => vec![
            deny(
                &[
                    "mach-priv-task-port",
                    "mach-task-name",
                    "mach-task-inspect",
                    "mach-task-read",
                ],
                vec![],
            ),
            deny(&["process-info*"], vec![Filter::OutsideSameSandbox]),
            deny(&["signal"], vec![Filter::Target("others")]),
        ],
        HardDenyClass::RenameAnchors => {
            let mut rules = Vec::new();
            for rule in &policy.fs {
                match (&rule.access, &rule.target) {
                    (Access::Write, FsTarget::Subpath(root)) => {
                        rules.push(deny(
                            &["file-write-unlink"],
                            vec![Filter::Literal(root.as_bytes().to_vec())],
                        ));
                    }
                    (
                        Access::Protect | Access::Hide,
                        FsTarget::Subpath(p) | FsTarget::Literal(p),
                    ) => {
                        rules.push(deny(
                            &["file-write-unlink"],
                            vec![Filter::PathAncestors(p.as_bytes().to_vec())],
                        ));
                    }
                    _ => {}
                }
            }
            rules
        }
        HardDenyClass::TerminalInjection => vec![deny(
            &["file-ioctl"],
            vec![Filter::IoctlCommand(0x8001_7472)],
        )],
        HardDenyClass::Secrets => vec![deny(&["file-read*", "file-write*"], folded(class))],
        HardDenyClass::TrustHandoff => vec![
            deny(&["file-write*"], folded(class)),
            deny(
                &["file-write-unlink"],
                vec![Filter::Regex(
                    crate::presets::git_dir().to_sbpl_regex_folded(),
                )],
            ),
        ],
        HardDenyClass::Persistence => vec![deny(&["file-write*"], folded(class))],
        HardDenyClass::KernelSurface
        | HardDenyClass::Namespaces
        | HardDenyClass::SocketFamilies => vec![],
    }
}

/// The case-folded pattern filters of a data-driven class.
fn folded(class: HardDenyClass) -> Vec<Filter> {
    crate::presets::patterns(class)
        .iter()
        .map(|g| Filter::Regex(g.to_sbpl_regex_folded()))
        .collect()
}

fn class_outcome(class: HardDenyClass) -> Outcome {
    match class {
        HardDenyClass::KernelSurface
        | HardDenyClass::Namespaces
        | HardDenyClass::SocketFamilies => Outcome::NotApplicable,
        _ => Outcome::Exact,
    }
}

pub(super) fn lower(policy: &Policy, options: &LowerOptions) -> Result<SeatbeltPlan, LowerError> {
    let mut ledger = Ledger::new(Target::MacOs, options);
    let mut allow = Vec::new();
    let mut within = Vec::new();
    let mut hard = Vec::new();

    for rule in &policy.fs {
        let construct = fs_construct(rule);
        let subject = Some(subject_of(&rule.target));
        ledger.outcome(construct, Outcome::Exact, None, "");
        let block = match rule.access {
            Access::Protect | Access::Hide => &mut within,
            _ => &mut allow,
        };
        let effect = match rule.access {
            Access::Protect | Access::Hide => Effect::Deny,
            _ => Effect::Allow,
        };
        let r = Rule::new(effect, ops(rule.access), vec![path_filter(&rule.target)]);
        push(&mut ledger, block, construct, subject, r);
    }

    let mut grants = Vec::new();
    for grant in &policy.grants {
        ledger.outcome(Construct::Grant, Outcome::Exact, None, "");
        let class = format!("procage.{}", grant.name);
        allow.push(Rule::new(
            Effect::Allow,
            ops(grant.access),
            vec![Filter::Extension(class.clone())],
        ));
        grants.push(GrantSlot {
            name: grant.name.clone(),
            class,
            access: grant.access,
        });
    }
    grants.sort();

    let socket = || Rule::new(Effect::Allow, &["system-socket"], vec![]);
    match &policy.net {
        Network::None => {
            ledger.outcome(Construct::NetNone, Outcome::Exact, None, "");
        }
        Network::Loopback(ports) => {
            ledger.outcome(Construct::NetLoopback, Outcome::Exact, None, "");
            let addrs = loopback(ports);
            allow.push(Rule::new(
                Effect::Allow,
                &["network-outbound"],
                addrs.iter().cloned().map(Filter::RemoteIp).collect(),
            ));
            allow.push(Rule::new(
                Effect::Allow,
                &["network-bind", "network-inbound"],
                addrs.into_iter().map(Filter::LocalIp).collect(),
            ));
            allow.push(socket());
        }
        Network::UnixSockets(paths) => {
            ledger.outcome(Construct::NetUnixSockets, Outcome::Exact, None, "");
            for path in paths {
                let r = Rule::new(
                    Effect::Allow,
                    &["network-outbound"],
                    vec![Filter::RemoteUnixSocket(path.as_bytes().to_vec())],
                );
                push(
                    &mut ledger,
                    &mut allow,
                    Construct::NetUnixSockets,
                    Some(path.to_string()),
                    r,
                );
            }
            allow.push(socket());
        }
        Network::Proxy { http, socks } => {
            ledger.outcome(Construct::NetProxy, Outcome::Exact, None, "");
            let filters = http
                .iter()
                .chain(socks.iter())
                .map(|p| Filter::RemoteIp(format!("localhost:{p}")))
                .collect();
            allow.push(Rule::new(Effect::Allow, &["network-outbound"], filters));
            allow.push(socket());
        }
        Network::All => {
            ledger.outcome(Construct::NetAll, Outcome::Exact, None, "");
            allow.push(Rule::new(Effect::Allow, &["network*"], vec![]));
            allow.push(socket());
        }
    }

    match policy.process.exec {
        Exec::Granted => {}
        Exec::Any => {
            ledger.outcome(Construct::ExecAny, Outcome::Exact, None, "");
            allow.push(Rule::new(
                Effect::Allow,
                &["process-exec*", "file-map-executable"],
                vec![],
            ));
        }
        Exec::Never => {
            ledger.outcome(Construct::ExecNever, Outcome::Exact, None, "");
        }
    }
    if policy.process.fork {
        allow.push(Rule::new(Effect::Allow, &["process-fork"], vec![]));
    } else {
        ledger.outcome(Construct::ForkDenied, Outcome::Exact, None, "");
    }
    match policy.process.signals {
        Signals::SelfAndChildren => {
            ledger.outcome(Construct::SignalsSelfAndChildren, Outcome::Exact, None, "");
            allow.push(Rule::new(
                Effect::Allow,
                &["signal"],
                vec![Filter::Target("self"), Filter::Target("children")],
            ));
        }
        Signals::None => {
            ledger.outcome(Construct::SignalsNone, Outcome::Exact, None, "");
        }
    }
    if policy.ipc.posix_shm {
        ledger.outcome(Construct::PosixShm, Outcome::Exact, None, "");
        allow.push(Rule::new(Effect::Allow, &["ipc-posix-shm*"], vec![]));
    }
    if policy.ipc.sysv {
        ledger.outcome(Construct::SysvIpc, Outcome::Exact, None, "");
        allow.push(Rule::new(Effect::Allow, &["ipc-sysv*"], vec![]));
    }
    ledger.outcome(Construct::Hygiene, Outcome::Exact, None, "");
    if policy.base == Base::V1 {
        ledger.outcome(Construct::BaseV1, Outcome::Exact, None, "");
        allow.extend(crate::base::macos_v1(policy.tty));
    }

    if let Some(layer) = &policy.seatbelt {
        ledger.outcome(Construct::SeatbeltLayer, Outcome::Exact, None, "");
        for raw in &layer.rules {
            let ops: Vec<&str> = raw.ops.iter().map(|op| op.as_str()).collect();
            let filters = raw.filters.iter().flat_map(raw_filter).collect();
            let (block, effect) = match raw.effect {
                Effect::Allow => (&mut allow, Effect::Allow),
                Effect::Deny => (&mut within, Effect::Deny),
            };
            push(
                &mut ledger,
                block,
                Construct::SeatbeltLayer,
                None,
                Rule::new(effect, &ops, filters),
            );
        }
    }
    if policy.linux.is_some() {
        ledger.outcome(
            Construct::LinuxLayer,
            Outcome::Approximated,
            None,
            "the Linux layer is ignored on macOS",
        );
    }

    for &class in HardDenyClass::ALL {
        if policy.waive.contains(&class) {
            continue;
        }
        if ledger.outcome(Construct::of_class(class), class_outcome(class), None, "") {
            hard.extend(hard_deny(class, policy));
        }
    }

    let degradations = ledger.finish()?;

    let mut rules = Vec::with_capacity(allow.len() + within.len() + hard.len());
    for mut block in [allow, within, hard] {
        block.sort();
        block.dedup();
        rules.extend(block);
    }
    let mut merged = false;
    if rules.len() > options.max_rules {
        rules = sbpl::merge_adjacent(rules, sbpl::MAX_MERGED_FILTERS);
        merged = true;
        if rules.len() > options.max_rules {
            return Err(LowerError::LimitExceeded {
                limit: options.max_rules,
                rules: rules.len(),
            });
        }
    }

    // Every value was checked by `push` or comes from a validated name, so
    // rendering cannot fail; a failure here is still reported, never ignored.
    let rendered = sbpl::write_profile(options.tag.as_ref(), &rules).map_err(|e| {
        LowerError::Gaps(vec![super::CapabilityGap {
            construct: Construct::Hygiene,
            target: Target::MacOs,
            kind: GapKind::Unrepresentable(e),
            subject: None,
        }])
    })?;

    Ok(SeatbeltPlan {
        profile: rendered.text,
        params: rendered.params,
        grants,
        rule_count: rules.len(),
        merged,
        degradations,
        waivers: policy.waive.iter().copied().collect(),
        hygiene: Hygiene::of(policy),
    })
}
