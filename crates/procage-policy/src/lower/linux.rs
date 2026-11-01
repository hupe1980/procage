//! Lowering to a Linux plan for tier T1 or T2.

use alloc::string::ToString;
use alloc::vec;
use alloc::vec::Vec;

use super::{
    Construct, Hygiene, Ledger, LowerError, LowerOptions, Outcome, Target, Tier, fs_construct,
    subject_of,
};
use crate::linux::{
    AF_NETLINK, AF_UNIX, AF_VSOCK, AccessFs, Action, ClassPaths, Condition, Landlock, LandlockRule,
    LinuxNetwork, LinuxPlan, Mount, Namespaces, RuleTarget, Scopes, SeccompRule, Syscall,
    TIOCLINUX, TIOCSTI, handled_fs, handled_net, may_overlap, rights, scopes,
};
use crate::path::AbsPath;
use crate::policy::{
    Access, Base, Exec, FsTarget, HardDenyClass, Lifetime, Network, Policy, Signals,
};
use crate::sbpl::DenyReason;

fn deny(syscall: Syscall) -> SeccompRule {
    SeccompRule {
        syscall,
        condition: Condition::Always,
        action: Action::Eperm,
        reason: None,
    }
}

fn deny_if(syscall: Syscall, condition: Condition) -> SeccompRule {
    SeccompRule {
        syscall,
        condition,
        action: Action::Eperm,
        reason: None,
    }
}

fn enosys(syscall: Syscall) -> SeccompRule {
    SeccompRule {
        syscall,
        condition: Condition::Always,
        action: Action::Enosys,
        reason: None,
    }
}

/// `rule`, refused for `reason`.
fn because(mut rule: SeccompRule, reason: DenyReason) -> SeccompRule {
    rule.reason = Some(reason);
    rule
}

fn class_rules(class: HardDenyClass) -> Vec<SeccompRule> {
    match class {
        HardDenyClass::ProcessAccess => vec![
            deny(Syscall::Ptrace),
            deny(Syscall::ProcessVmReadv),
            deny(Syscall::ProcessVmWritev),
            deny(Syscall::PidfdGetfd),
            deny(Syscall::Kcmp),
        ],
        HardDenyClass::TerminalInjection => {
            vec![deny_if(
                Syscall::Ioctl,
                Condition::IoctlCommand(vec![TIOCSTI, TIOCLINUX]),
            )]
        }
        HardDenyClass::KernelSurface => vec![
            deny(Syscall::IoUringSetup),
            deny(Syscall::IoUringEnter),
            deny(Syscall::IoUringRegister),
            deny(Syscall::Bpf),
            deny(Syscall::PerfEventOpen),
            deny(Syscall::Userfaultfd),
            deny(Syscall::Keyctl),
            deny(Syscall::AddKey),
            deny(Syscall::RequestKey),
        ],
        HardDenyClass::Namespaces => vec![
            deny(Syscall::Unshare),
            deny(Syscall::Setns),
            deny_if(Syscall::Clone, Condition::CloneNewNamespace),
            enosys(Syscall::Clone3),
            deny(Syscall::Mount),
            deny(Syscall::Umount2),
            deny(Syscall::PivotRoot),
            deny(Syscall::OpenTree),
            deny(Syscall::MoveMount),
            deny(Syscall::Fsopen),
            deny(Syscall::Fsmount),
        ],
        HardDenyClass::SocketFamilies => {
            vec![deny_if(
                Syscall::Socket,
                Condition::SocketFamily(vec![AF_NETLINK, AF_VSOCK]),
            )]
        }
        // Privilege: `no_new_privs` is always set. RenameAnchors: REFER is
        // never granted and T1 protect/hide targets are mountpoints.
        HardDenyClass::Privilege | HardDenyClass::RenameAnchors => vec![],
        // Socket classes are found and handled by the backend (see
        // `service_sockets` in `lower`).
        HardDenyClass::FcntlModify
        | HardDenyClass::ServiceHandoff
        | HardDenyClass::ContainerEngines => vec![],
        // Masked at spawn (T1) or enforced by Landlock's default deny where
        // no rule reaches them (see `covered`).
        HardDenyClass::Secrets | HardDenyClass::TrustHandoff | HardDenyClass::Persistence => vec![],
    }
}

fn class_outcome(class: HardDenyClass) -> Outcome {
    match class {
        HardDenyClass::FcntlModify => Outcome::NotApplicable,
        _ => Outcome::Exact,
    }
}

/// Whether a rule of `policy` can reach a path of the class: a file rule or
/// raw Landlock rule with an access that matters for the class whose path
/// overlaps one of its patterns, or, for names in any directory, a grant
/// with that access (a grant's path is known only at spawn).
fn covered(policy: &Policy, paths: &ClassPaths, write_only: bool) -> bool {
    let matters = |access: Access| match access {
        Access::Read | Access::Exec => paths.hide && !write_only,
        Access::Write => true,
        Access::Protect | Access::Hide => false,
    };
    let patterns = paths.patterns();
    let reaches = |path: &AbsPath| patterns.iter().any(|p| may_overlap(p, path.as_bytes()));
    let fs = policy.fs.iter().any(|rule| {
        matters(rule.access)
            && match &rule.target {
                FsTarget::Subpath(p) | FsTarget::Literal(p) => reaches(p),
                FsTarget::Glob(_) => true,
            }
    });
    let extra = policy.linux.as_ref().is_some_and(|layer| {
        layer
            .landlock_extra
            .iter()
            .any(|(p, access)| matters(*access) && reaches(p))
    });
    let grants = (!paths.anywhere.is_empty() || paths.pin_git)
        && policy.grants.iter().any(|g| matters(g.access));
    fs || extra || grants
}

/// Whether a write rule of `policy` (a file rule or a raw Landlock rule)
/// reaches `hidden`: its path is `hidden` or contains it. Landlock grants
/// creating and removing entries beneath a directory, so a hidden path inside
/// a writable tree cannot be kept out piecewise.
fn written_around(policy: &Policy, hidden: &AbsPath) -> bool {
    let fs = policy.fs.iter().any(|rule| {
        rule.access == Access::Write
            && match &rule.target {
                FsTarget::Subpath(p) | FsTarget::Literal(p) => hidden.starts_with_path(p),
                FsTarget::Glob(_) => true,
            }
    });
    let extra = policy.linux.as_ref().is_some_and(|layer| {
        layer
            .landlock_extra
            .iter()
            .any(|(p, access)| *access == Access::Write && hidden.starts_with_path(p))
    });
    fs || extra
}

/// The note for hiding by piecewise grants on tier T2.
const PIECEWISE: &str = "the trees around the hidden path are granted entry by entry as \
    listed at spawn: entries added later on the way are denied, the directories on the way \
    cannot be listed, and the hidden path's metadata stays visible";

pub(super) fn lower(
    policy: &Policy,
    tier: Tier,
    abi: u8,
    options: &LowerOptions,
) -> Result<LinuxPlan, LowerError> {
    let target = Target::Linux {
        tier,
        landlock_abi: abi,
    };
    let t1 = tier == Tier::T1;
    let mut ledger = Ledger::new(target, options);
    let mut handled = handled_fs(abi);
    if policy.process.exec == Exec::Any {
        handled = handled.without(AccessFs::EXECUTE);
    }
    let mut landlock = Landlock {
        handled_fs: handled,
        ..Landlock::default()
    };
    let mut mounts = Vec::new();
    let mut seccomp = Vec::new();
    let mut hide_by_siblings: Vec<AbsPath> = Vec::new();
    let mut namespaces = t1.then_some(Namespaces {
        user: true,
        mount: true,
        net: true,
        // No PID namespace: it would need a reaper and a fresh /proc.
        pid: false,
        ipc: true,
        uts: true,
    });

    for rule in &policy.fs {
        let construct = fs_construct(rule);
        let subject = Some(subject_of(&rule.target));
        match (rule.access, &rule.target) {
            (Access::Protect | Access::Hide, FsTarget::Glob(_)) => {
                ledger.outcome(Construct::FsGlob, Outcome::Unsupported, subject, "");
            }
            (Access::Protect, FsTarget::Subpath(p) | FsTarget::Literal(p)) => {
                let outcome = if t1 {
                    Outcome::Exact
                } else {
                    Outcome::Unsupported
                };
                if ledger.outcome(construct, outcome, subject, "") {
                    mounts.push(Mount::ReadOnlyBind(p.clone()));
                }
            }
            (Access::Hide, FsTarget::Subpath(p) | FsTarget::Literal(p)) if t1 => {
                if ledger.outcome(construct, Outcome::Exact, subject, "") {
                    mounts.push(Mount::Mask(p.clone()));
                }
            }
            (Access::Hide, FsTarget::Subpath(p) | FsTarget::Literal(p)) => {
                if written_around(policy, p) {
                    ledger.outcome(
                        construct,
                        Outcome::Unsupported,
                        subject,
                        "a write rule reaches the hidden path",
                    );
                } else if ledger.outcome(construct, Outcome::Approximated, subject, PIECEWISE) {
                    hide_by_siblings.push(p.clone());
                }
            }
            (access, FsTarget::Subpath(p)) => {
                ledger.outcome(construct, Outcome::Exact, subject, "");
                landlock.rules.push(LandlockRule {
                    target: RuleTarget::Path(p.clone()),
                    access: rights(access, handled),
                });
            }
            (access, FsTarget::Literal(p)) => {
                if ledger.outcome(
                    construct,
                    Outcome::Approximated,
                    subject,
                    "bound to the file's inode at spawn; a rename-replace loses the rule",
                ) {
                    landlock.rules.push(LandlockRule {
                        target: RuleTarget::Path(p.clone()),
                        access: rights(access, handled).intersect(AccessFs::FILE_RIGHTS),
                    });
                }
            }
            // Expanding globs at spawn is not implemented.
            (_, FsTarget::Glob(_)) => {
                ledger.outcome(construct, Outcome::Unsupported, subject, "");
            }
        }
    }

    for grant in &policy.grants {
        ledger.outcome(Construct::Grant, Outcome::Exact, None, "");
        landlock.rules.push(LandlockRule {
            target: RuleTarget::Grant(grant.name.clone()),
            access: rights(grant.access, handled),
        });
    }

    let net_handled = handled_net(abi);
    let network = match &policy.net {
        Network::None => {
            ledger.outcome(Construct::NetNone, Outcome::Exact, None, "");
            seccomp.push(if policy.ipc.unix_sockets.is_empty() {
                deny(Syscall::Socket)
            } else {
                deny_if(
                    Syscall::Socket,
                    Condition::SocketFamilyExcept(vec![AF_UNIX]),
                )
            });
            landlock.handled_net = net_handled;
            if t1 {
                LinuxNetwork::Isolated
            } else {
                LinuxNetwork::NoNamespace
            }
        }
        // Both need a relay into the network namespace (T1), which is not
        // implemented, and T2 cannot restrict ports to loopback.
        Network::Loopback(ports) => {
            ledger.outcome(Construct::NetLoopback, Outcome::Unsupported, None, "");
            LinuxNetwork::LoopbackRelay {
                ports: ports.clone(),
            }
        }
        Network::Proxy { http, socks } => {
            ledger.outcome(Construct::NetProxy, Outcome::Unsupported, None, "");
            LinuxNetwork::ProxyBridge {
                ports: http.iter().chain(socks.iter()).copied().collect(),
            }
        }
        Network::All => {
            ledger.outcome(Construct::NetAll, Outcome::Exact, None, "");
            if let Some(ns) = namespaces.as_mut() {
                ns.net = false;
            }
            LinuxNetwork::NoNamespace
        }
    };

    let mut mask_unix_sockets = false;
    let mut unix_socket_paths = Vec::new();
    if !policy.ipc.unix_sockets.is_empty() {
        let paths = &policy.ipc.unix_sockets;
        let construct = Construct::IpcUnixSockets;
        if policy.net == Network::All {
            // Every socket is reachable anyway.
            ledger.outcome(construct, Outcome::Exact, None, "");
        } else if abi >= 9 {
            if ledger.outcome(construct, Outcome::Exact, None, "") {
                landlock.scopes = Scopes(landlock.scopes.0 | Scopes::ABSTRACT_UNIX_SOCKET.0);
                for path in paths {
                    landlock.rules.push(LandlockRule {
                        target: RuleTarget::PathIfExists(path.clone()),
                        access: AccessFs::RESOLVE_UNIX,
                    });
                }
            }
        } else if t1 {
            // Pathname sockets cross network namespaces; abstract ones do not.
            if ledger.outcome(
                construct,
                Outcome::Approximated,
                None,
                "listening sockets outside the paths that exist at spawn are masked; sockets \
                 bound later, or in another network namespace, stay reachable",
            ) {
                if abi >= 6 {
                    landlock.scopes = Scopes(landlock.scopes.0 | Scopes::ABSTRACT_UNIX_SOCKET.0);
                }
                mask_unix_sockets = true;
                unix_socket_paths.clone_from(paths);
            }
        } else {
            ledger.outcome(
                construct,
                Outcome::Unsupported,
                None,
                "below Landlock ABI 9 only a mount namespace can keep other sockets out",
            );
        }
    }

    match policy.process.exec {
        Exec::Granted => {}
        Exec::Any => {
            ledger.outcome(Construct::ExecAny, Outcome::Exact, None, "");
        }
        Exec::Never => {
            ledger.outcome(Construct::ExecNever, Outcome::Exact, None, "");
        }
    }
    if !policy.process.fork {
        ledger.outcome(Construct::ForkDenied, Outcome::Exact, None, "");
        seccomp.push(deny(Syscall::Fork));
        seccomp.push(deny(Syscall::Vfork));
        seccomp.push(deny_if(Syscall::Clone, Condition::CloneWithoutThread));
        seccomp.push(enosys(Syscall::Clone3));
    } else {
        match policy.process.lifetime {
            // Fork keeps the process group; only these calls leave it. The
            // child's own session or group is started before the filter.
            Lifetime::Run => {
                ledger.outcome(Construct::LifetimeRun, Outcome::Exact, None, "");
                seccomp.push(because(deny(Syscall::Setsid), DenyReason::Lifetime));
                seccomp.push(because(deny(Syscall::Setpgid), DenyReason::Lifetime));
            }
            Lifetime::Tree => {
                ledger.outcome(Construct::LifetimeTree, Outcome::Exact, None, "");
            }
        }
    }
    match policy.process.signals {
        // Landlock's signal scope (ABI 6); there is no PID namespace.
        Signals::SelfAndChildren => {
            let outcome = if abi >= 6 {
                Outcome::Exact
            } else {
                Outcome::Unsupported
            };
            ledger.outcome(Construct::SignalsSelfAndChildren, outcome, None, "");
            if abi >= 6 {
                landlock.scopes = Scopes(landlock.scopes.0 | Scopes::SIGNAL.0);
            }
        }
        // The kernel's own permission check decides.
        Signals::SameUser => {
            ledger.outcome(Construct::SignalsSameUser, Outcome::Exact, None, "");
        }
        Signals::None => {
            ledger.outcome(Construct::SignalsNone, Outcome::Exact, None, "");
            for syscall in [
                Syscall::Kill,
                Syscall::Tkill,
                Syscall::Tgkill,
                Syscall::RtSigqueueinfo,
                Syscall::RtTgsigqueueinfo,
                Syscall::PidfdSendSignal,
            ] {
                seccomp.push(deny(syscall));
            }
        }
    }
    landlock.scopes = Scopes(landlock.scopes.0 | (scopes(abi).0 & Scopes::ABSTRACT_UNIX_SOCKET.0));
    if abi < 3 {
        // Landlock cannot deny truncation below ABI 3: `truncate` and an
        // `open` with `O_TRUNC` but no write access would empty any readable
        // file. This refuses them everywhere, inside writable paths too.
        let guard = DenyReason::OlderKernel;
        seccomp.push(because(deny(Syscall::Truncate), guard));
        seccomp.push(because(
            deny_if(Syscall::Open, Condition::TruncWithoutWrite { flags_arg: 1 }),
            guard,
        ));
        seccomp.push(because(
            deny_if(
                Syscall::Openat,
                Condition::TruncWithoutWrite { flags_arg: 2 },
            ),
            guard,
        ));
        // Its flags sit in a structure seccomp cannot read.
        seccomp.push(enosys(Syscall::Openat2));
    }

    let dev_shm = AbsPath::new("/dev/shm").unwrap_or_else(|_| AbsPath::root());
    if policy.ipc.posix_shm {
        let outcome = if t1 {
            Outcome::Exact
        } else {
            Outcome::Approximated
        };
        if ledger.outcome(
            Construct::PosixShm,
            outcome,
            None,
            "the host's /dev/shm is shared",
        ) {
            if t1 {
                mounts.push(Mount::PrivateDevShm);
            }
            landlock.rules.push(LandlockRule {
                target: RuleTarget::Path(dev_shm),
                access: rights(Access::Write, handled),
            });
        }
    }
    if policy.ipc.sysv {
        let outcome = if t1 {
            Outcome::Exact
        } else {
            Outcome::Approximated
        };
        ledger.outcome(
            Construct::SysvIpc,
            outcome,
            None,
            "the host's System V IPC is shared",
        );
    } else {
        for syscall in [
            Syscall::Shmget,
            Syscall::Shmat,
            Syscall::Shmctl,
            Syscall::Shmdt,
            Syscall::Semget,
            Syscall::Semop,
            Syscall::Semtimedop,
            Syscall::Semctl,
            Syscall::Msgget,
            Syscall::Msgsnd,
            Syscall::Msgrcv,
            Syscall::Msgctl,
        ] {
            seccomp.push(deny(syscall));
        }
    }
    ledger.outcome(Construct::Hygiene, Outcome::Exact, None, "");
    match policy.base {
        Base::None => {}
        Base::V1 => {
            ledger.outcome(Construct::BaseV1, Outcome::Exact, None, "");
            landlock
                .rules
                .extend(crate::base::linux_v1(policy.tty, handled));
        }
        Base::V2 | Base::V3 => {
            let construct = if policy.base == Base::V3 {
                Construct::BaseV3
            } else {
                Construct::BaseV2
            };
            ledger.outcome(construct, Outcome::Exact, None, "");
            landlock
                .rules
                .extend(crate::base::linux_v2(policy.tty, handled));
        }
    }

    if policy.seatbelt.is_some() {
        ledger.outcome(
            Construct::SeatbeltLayer,
            Outcome::Approximated,
            None,
            "the Seatbelt layer is ignored on Linux",
        );
    }
    if let Some(layer) = &policy.linux {
        ledger.outcome(Construct::LinuxLayer, Outcome::Exact, None, "");
        for syscall in &layer.syscalls_deny {
            seccomp.push(because(deny(syscall.clone()), DenyReason::Layer));
        }
        for (path, access) in &layer.landlock_extra {
            landlock.rules.push(LandlockRule {
                target: RuleTarget::Path(path.clone()),
                access: rights(*access, handled),
            });
        }
    }

    let mut classes = Vec::new();
    let mut service_sockets = Vec::new();
    // With the network off and no `ipc.unix_sockets`, seccomp refuses every
    // socket, so the socket classes hold without help; any other setting
    // leaves Unix connects to the backend.
    let unix_reachable = policy.net != Network::None || !policy.ipc.unix_sockets.is_empty();
    for &class in HardDenyClass::ALL {
        if policy.waive.contains(&class) {
            continue;
        }
        if let Some(paths) = crate::presets::linux_socket_paths(class) {
            // Whether a socket exists (a gap on T2, an approximation on T1)
            // is known only at spawn; the backend reports it.
            if ledger.outcome(
                Construct::of_class(class),
                Outcome::Exact,
                Some(class.to_string()),
                "",
            ) && unix_reachable
            {
                service_sockets.push(paths);
            }
            continue;
        }
        if let Some(paths) = crate::presets::linux_class_paths(class) {
            // On T2 a hidden class reached only by read rules is hidden
            // piecewise, like `Access::Hide`.
            let (outcome, note) = match (covered(policy, &paths, false), t1) {
                (false, _) => (Outcome::Exact, ""),
                (true, true) => (
                    Outcome::Approximated,
                    "paths that exist at spawn are masked; paths created later are not covered",
                ),
                (true, false) if paths.hide && !covered(policy, &paths, true) => {
                    (Outcome::Approximated, PIECEWISE)
                }
                (true, false) => (Outcome::Unsupported, ""),
            };
            if ledger.outcome(
                Construct::of_class(class),
                outcome,
                Some(class.to_string()),
                note,
            ) {
                classes.push(paths);
            }
            continue;
        }
        if ledger.outcome(
            Construct::of_class(class),
            class_outcome(class),
            Some(class.to_string()),
            "",
        ) {
            seccomp.extend(
                class_rules(class)
                    .into_iter()
                    .map(|r| because(r, DenyReason::HardDeny(class))),
            );
        }
    }

    let degradations = ledger.finish()?;

    mounts.sort();
    mounts.dedup();
    landlock.rules.sort();
    landlock.rules.dedup();
    landlock.net_rules.sort();
    landlock.net_rules.dedup();
    seccomp.sort();
    // One rule per call and condition, as before reasons existed (the filter
    // stays the same); a specific reason wins over "not granted".
    seccomp.dedup_by(|next, kept| {
        let same = next.syscall == kept.syscall
            && next.condition == kept.condition
            && next.action == kept.action;
        if same && kept.reason.is_none() {
            kept.reason = next.reason;
        }
        same
    });
    hide_by_siblings.sort();
    hide_by_siblings.dedup();
    unix_socket_paths.sort();
    unix_socket_paths.dedup();

    Ok(LinuxPlan {
        tier,
        landlock_abi: abi,
        namespaces,
        mounts,
        landlock,
        seccomp,
        network,
        no_new_privs: true,
        mask_unix_sockets,
        unix_socket_paths,
        hide_by_siblings,
        degradations,
        waivers: policy.waive.iter().copied().collect(),
        classes,
        service_sockets,
        hygiene: Hygiene::of(policy),
    })
}
