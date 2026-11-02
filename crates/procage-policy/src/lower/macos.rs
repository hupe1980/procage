//! Lowering to a Seatbelt profile.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;

use super::{
    Construct, GapKind, GrantSlot, Hygiene, Ledger, LowerError, LowerOptions, Outcome,
    SeatbeltPlan, Target, fs_construct, subject_of,
};
use crate::explain::Decider;
use crate::policy::{
    Access, Base, Exec, FsTarget, HardDenyClass, Lifetime, Network, Policy, Ports, Signals,
};
use crate::sbpl::{self, DenyReason, Filter, Rule};
use crate::seatbelt::{self, Effect};

/// A rule and where it came from.
pub(crate) type Tagged = (Rule, Decider);

/// The rules of a profile before rendering, in blocks of one effect each
/// (the marker block excepted), in profile order: quiet denies, allows,
/// denies inside allowed trees, the hard-deny tier, the run marker.
pub(crate) struct Emitted {
    pub(crate) blocks: [Vec<Tagged>; 5],
    grants: Vec<GrantSlot>,
    degradations: Vec<super::Degradation>,
}

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
    block: &mut Vec<Tagged>,
    construct: Construct,
    subject: Option<String>,
    rule: Rule,
    by: Decider,
) {
    for value in rule.values() {
        if let Err(e) = sbpl::quote(value) {
            ledger.gap(construct, GapKind::Unrepresentable(e), subject);
            return;
        }
    }
    block.push((rule, by));
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
            // Another process's arguments and environment (`KERN_PROCARGS2`)
            // pass if either `sysctl-read` or `process-info-pidinfo` allows
            // them, and only unfiltered or prefix rules match the numeric
            // query (measured on macOS 26.6.2): the argument sysctls are
            // denied by prefix here, and pidinfo outside the sandbox by the
            // early deny `process_access_early` adds.
            deny(
                &["sysctl-read"],
                vec![Filter::SysctlNamePrefix("kern.procargs".into())],
            ),
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
        // A path filter on a network operation matches Unix-socket addresses
        // only, by the socket a path resolves to.
        HardDenyClass::ContainerEngines => vec![deny(&["network-outbound"], folded(class))],
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

/// The tagged rules of `policy`, or its gaps.
pub(crate) fn emit(policy: &Policy, options: &LowerOptions) -> Result<Emitted, LowerError> {
    let mut ledger = Ledger::new(Target::MacOs, options);
    // Quiet denies come first, so every later allow wins over them.
    let mut quiet = Vec::new();
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
        let mut r = Rule::new(effect, ops(rule.access), vec![path_filter(&rule.target)]);
        match rule.access {
            Access::Protect => r = r.because(DenyReason::Protect),
            Access::Hide => r = r.because(DenyReason::Hide),
            _ => {}
        }
        push(
            &mut ledger,
            block,
            construct,
            subject,
            r,
            Decider::Rule(rule.clone()),
        );
    }

    let mut grants = Vec::new();
    for grant in &policy.grants {
        ledger.outcome(Construct::Grant, Outcome::Exact, None, "");
        let class = format!("procage.{}", grant.name);
        allow.push((
            Rule::new(
                Effect::Allow,
                ops(grant.access),
                vec![Filter::Extension(class.clone())],
            ),
            Decider::Grant(grant.name.clone()),
        ));
        grants.push(GrantSlot {
            name: grant.name.clone(),
            class,
            access: grant.access,
        });
    }
    grants.sort();

    let net = |rule: Rule| (rule, Decider::Setting("network"));
    let socket = || net(Rule::new(Effect::Allow, &["system-socket"], vec![]));
    match &policy.net {
        Network::None => {
            ledger.outcome(Construct::NetNone, Outcome::Exact, None, "");
        }
        Network::Loopback(ports) => {
            ledger.outcome(Construct::NetLoopback, Outcome::Exact, None, "");
            let addrs = loopback(ports);
            allow.push(net(Rule::new(
                Effect::Allow,
                &["network-outbound"],
                addrs.iter().cloned().map(Filter::RemoteIp).collect(),
            )));
            allow.push(net(Rule::new(
                Effect::Allow,
                &["network-bind", "network-inbound"],
                addrs.into_iter().map(Filter::LocalIp).collect(),
            )));
            allow.push(socket());
        }
        Network::Proxy { http, socks } => {
            ledger.outcome(Construct::NetProxy, Outcome::Exact, None, "");
            let filters = http
                .iter()
                .chain(socks.iter())
                .map(|p| Filter::RemoteIp(format!("localhost:{p}")))
                .collect();
            allow.push(net(Rule::new(
                Effect::Allow,
                &["network-outbound"],
                filters,
            )));
            allow.push(socket());
        }
        Network::All => {
            ledger.outcome(Construct::NetAll, Outcome::Exact, None, "");
            allow.push(net(Rule::new(Effect::Allow, &["network*"], vec![])));
            allow.push(socket());
        }
    }

    match policy.process.exec {
        Exec::Granted => {}
        Exec::Any => {
            ledger.outcome(Construct::ExecAny, Outcome::Exact, None, "");
            allow.push((
                Rule::new(
                    Effect::Allow,
                    &["process-exec*", "file-map-executable"],
                    vec![],
                ),
                Decider::Setting("exec"),
            ));
        }
        Exec::Never => {
            ledger.outcome(Construct::ExecNever, Outcome::Exact, None, "");
        }
    }
    // The run-marker block, last so no other rule overrides it: the run's
    // processes allow looking up the marker and deny every other name with
    // the prefix (see `RUN_MARKER_PARAM`).
    let mut marker = Vec::new();
    if policy.process.fork {
        allow.push((
            Rule::new(Effect::Allow, &["process-fork"], vec![]),
            Decider::Setting("fork"),
        ));
        let construct = match policy.process.lifetime {
            Lifetime::Run => Construct::LifetimeRun,
            Lifetime::Tree => Construct::LifetimeTree,
        };
        ledger.outcome(construct, Outcome::Exact, None, "");
        marker.push((
            Rule::new(
                Effect::Deny,
                &["mach-lookup"],
                vec![Filter::GlobalNamePrefixParam(super::RUN_PREFIX_PARAM)],
            ),
            Decider::Setting("lifetime"),
        ));
        marker.push((
            Rule::new(
                Effect::Allow,
                &["mach-lookup"],
                vec![Filter::GlobalNameParam(super::RUN_MARKER_PARAM)],
            ),
            Decider::Setting("lifetime"),
        ));
    } else {
        ledger.outcome(Construct::ForkDenied, Outcome::Exact, None, "");
    }
    match policy.process.signals {
        Signals::SelfAndChildren => {
            ledger.outcome(Construct::SignalsSelfAndChildren, Outcome::Exact, None, "");
            allow.push((
                Rule::new(
                    Effect::Allow,
                    &["signal"],
                    vec![Filter::Target("self"), Filter::Target("children")],
                ),
                Decider::Setting("signals"),
            ));
        }
        // `hd-process-access` still denies signals to processes outside
        // the sandbox: its block comes after this one.
        Signals::SameUser => {
            ledger.outcome(Construct::SignalsSameUser, Outcome::Exact, None, "");
            allow.push((
                Rule::new(Effect::Allow, &["signal"], vec![]),
                Decider::Setting("signals"),
            ));
        }
        Signals::None => {
            ledger.outcome(Construct::SignalsNone, Outcome::Exact, None, "");
        }
    }
    if policy.ipc.posix_shm {
        ledger.outcome(Construct::PosixShm, Outcome::Exact, None, "");
        allow.push((
            Rule::new(Effect::Allow, &["ipc-posix-shm*"], vec![]),
            Decider::Setting("ipc"),
        ));
    }
    if policy.ipc.sysv {
        ledger.outcome(Construct::SysvIpc, Outcome::Exact, None, "");
        allow.push((
            Rule::new(Effect::Allow, &["ipc-sysv*"], vec![]),
            Decider::Setting("ipc"),
        ));
    }
    // A path filter on the network operations matches Unix-socket
    // addresses only, so IP stays as the network setting says.
    const UNIX_OPS: [&str; 3] = ["network-bind", "network-inbound", "network-outbound"];
    if !policy.ipc.unix_sockets.is_empty() {
        ledger.outcome(Construct::IpcUnixSockets, Outcome::Exact, None, "");
        allow.push((
            Rule::new(Effect::Allow, &["system-socket"], vec![]),
            Decider::Setting("ipc.unix_sockets"),
        ));
        for path in &policy.ipc.unix_sockets {
            let r = Rule::new(
                Effect::Allow,
                &UNIX_OPS,
                vec![Filter::Subpath(path.as_bytes().to_vec())],
            );
            push(
                &mut ledger,
                &mut allow,
                Construct::IpcUnixSockets,
                Some(path.to_string()),
                r,
                Decider::Setting("ipc.unix_sockets"),
            );
        }
        // A hidden path stays unreachable through its sockets too.
        for rule in policy.fs.iter().filter(|r| r.access == Access::Hide) {
            let filter = match &rule.target {
                FsTarget::Subpath(p) => Filter::Subpath(p.as_bytes().to_vec()),
                FsTarget::Literal(p) => Filter::Literal(p.as_bytes().to_vec()),
                FsTarget::Glob(_) => continue,
            };
            within.push((
                Rule::new(Effect::Deny, &UNIX_OPS, vec![filter]).because(DenyReason::Hide),
                Decider::Rule(rule.clone()),
            ));
        }
    }
    ledger.outcome(Construct::Hygiene, Outcome::Exact, None, "");
    let base = |rules: Vec<Rule>| rules.into_iter().map(|r| (r, Decider::Base(policy.base)));
    match policy.base {
        Base::None => {}
        Base::V1 => {
            ledger.outcome(Construct::BaseV1, Outcome::Exact, None, "");
            allow.extend(base(crate::base::macos_v1(policy.tty)));
        }
        Base::V2 | Base::V3 => {
            if policy.base == Base::V3 {
                ledger.outcome(Construct::BaseV3, Outcome::Exact, None, "");
                quiet.extend(base(crate::base::macos_v3_quiet()));
            } else {
                ledger.outcome(Construct::BaseV2, Outcome::Exact, None, "");
            }
            allow.extend(base(crate::base::macos_v2(policy.tty)));
            let paths = policy
                .fs
                .iter()
                .filter_map(|r| match &r.target {
                    FsTarget::Subpath(p) | FsTarget::Literal(p) => Some(p),
                    FsTarget::Glob(_) => None,
                })
                .chain(&policy.ipc.unix_sockets);
            allow.extend(base(
                crate::base::macos_v2_ancestors(paths).into_iter().collect(),
            ));
        }
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
            let mut r = Rule::new(effect, &ops, filters);
            if effect == Effect::Deny {
                r = r.because(DenyReason::Layer);
            }
            push(
                &mut ledger,
                block,
                Construct::SeatbeltLayer,
                None,
                r,
                Decider::Layer,
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
            hard.extend(hard_deny(class, policy).into_iter().map(|r| {
                (
                    r.because(DenyReason::HardDeny(class)),
                    Decider::HardDeny(class),
                )
            }));
            if class == HardDenyClass::ProcessAccess {
                // An explicit, unfiltered deny first (the default deny does
                // not hold the argument query), then process information
                // for the run's own sandbox again.
                let by = Decider::HardDeny(class);
                quiet.push((
                    Rule::new(Effect::Deny, &["process-info-pidinfo"], vec![]).quietly(),
                    by.clone(),
                ));
                allow.push((
                    Rule::new(
                        Effect::Allow,
                        &["process-info-pidinfo"],
                        vec![Filter::Target("same-sandbox")],
                    ),
                    by,
                ));
            }
        }
    }

    let degradations = ledger.finish()?;
    Ok(Emitted {
        blocks: [quiet, allow, within, hard, marker],
        grants,
        degradations,
    })
}

pub(super) fn lower(policy: &Policy, options: &LowerOptions) -> Result<SeatbeltPlan, LowerError> {
    let Emitted {
        blocks: [quiet, allow, within, hard, marker],
        grants,
        degradations,
    } = emit(policy, options)?;
    let strip = |block: Vec<Tagged>| block.into_iter().map(|(r, _)| r).collect::<Vec<_>>();
    let marker = strip(marker);
    let run_marker = !marker.is_empty();
    let mut rules =
        Vec::with_capacity(quiet.len() + allow.len() + within.len() + hard.len() + marker.len());
    for block in [quiet, allow, within, hard] {
        let mut block = strip(block);
        if !options.violations {
            // Without reporting, reasons must not keep apart rules that would
            // otherwise be deduplicated or merged.
            for rule in &mut block {
                rule.reason = None;
            }
        }
        block.sort();
        block.dedup();
        rules.extend(block);
    }
    rules.extend(marker);
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
    let marker = options.violations.then_some(super::RUN_MARKER_PARAM);
    let rendered = sbpl::write_profile(marker, &rules).map_err(|e| {
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
        run_marker,
    })
}
