//! Lowering to a Linux plan for tier T1 or T2.

use alloc::string::ToString;
use alloc::vec;
use alloc::vec::Vec;

use super::{
    Construct, Hygiene, Ledger, LowerError, LowerOptions, Outcome, Target, Tier, fs_construct,
    subject_of,
};
use crate::linux::{
    AF_NETLINK, AF_UNIX, AF_VSOCK, AccessFs, AccessNet, Action, Condition, Landlock, LandlockRule,
    LinuxNetwork, LinuxPlan, Mount, Namespaces, NetRule, RuleTarget, Scopes, SeccompRule, Syscall,
    TIOCLINUX, TIOCSTI, handled_fs, handled_net, rights, scopes,
};
use crate::path::AbsPath;
use crate::policy::{Access, Base, Exec, FsTarget, HardDenyClass, Network, Policy, Ports, Signals};

fn deny(syscall: Syscall) -> SeccompRule {
    SeccompRule {
        syscall,
        condition: Condition::Always,
        action: Action::Eperm,
    }
}

fn deny_if(syscall: Syscall, condition: Condition) -> SeccompRule {
    SeccompRule {
        syscall,
        condition,
        action: Action::Eperm,
    }
}

fn enosys(syscall: Syscall) -> SeccompRule {
    SeccompRule {
        syscall,
        condition: Condition::Always,
        action: Action::Enosys,
    }
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
        HardDenyClass::FcntlModify | HardDenyClass::ServiceHandoff => vec![],
        // Not expressible in a Linux plan yet (see the lowering table).
        HardDenyClass::Secrets | HardDenyClass::TrustHandoff | HardDenyClass::Persistence => vec![],
    }
}

fn class_outcome(class: HardDenyClass) -> Outcome {
    match class {
        HardDenyClass::FcntlModify
        | HardDenyClass::ServiceHandoff
        | HardDenyClass::Secrets
        | HardDenyClass::TrustHandoff
        | HardDenyClass::Persistence => Outcome::NotApplicable,
        _ => Outcome::Exact,
    }
}

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
    let mut hide_by_siblings = Vec::new();
    let mut mask_unix_sockets = false;
    let mut namespaces = t1.then_some(Namespaces {
        user: true,
        mount: true,
        net: true,
        pid: true,
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
            (Access::Hide, FsTarget::Subpath(p) | FsTarget::Literal(p)) => {
                if t1 {
                    ledger.outcome(construct, Outcome::Exact, subject, "");
                    mounts.push(Mount::Mask(p.clone()));
                } else if ledger.outcome(
                    construct,
                    Outcome::Approximated,
                    subject,
                    "hidden by allowing its siblings as listed at spawn",
                ) {
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
            (access, FsTarget::Glob(g)) => {
                if ledger.outcome(
                    construct,
                    Outcome::Approximated,
                    subject,
                    "expanded at spawn; files created later are not covered",
                ) {
                    landlock.rules.push(LandlockRule {
                        target: RuleTarget::ExpandGlob(g.clone()),
                        access: rights(access, handled),
                    });
                }
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
    let tcp = AccessNet(AccessNet::BIND_TCP.0 | AccessNet::CONNECT_TCP.0);
    let network = match &policy.net {
        Network::None => {
            ledger.outcome(Construct::NetNone, Outcome::Exact, None, "");
            seccomp.push(deny(Syscall::Socket));
            landlock.handled_net = net_handled;
            if t1 {
                LinuxNetwork::Isolated
            } else {
                LinuxNetwork::NoNamespace
            }
        }
        Network::Loopback(ports) => {
            let outcome = if t1 {
                Outcome::Approximated
            } else {
                Outcome::Unsupported
            };
            if ledger.outcome(
                Construct::NetLoopback,
                outcome,
                None,
                "host loopback ports are relayed into the network namespace",
            ) && let Ports::List(list) = ports
            {
                landlock.handled_net = net_handled;
                for &port in list {
                    landlock.net_rules.push(NetRule {
                        port,
                        access: AccessNet(tcp.0 & net_handled.0),
                    });
                }
            }
            LinuxNetwork::LoopbackRelay {
                ports: ports.clone(),
            }
        }
        Network::UnixSockets(paths) => {
            let outcome = match (abi >= 9, t1) {
                (true, _) => Outcome::Exact,
                (false, true) => Outcome::Approximated,
                (false, false) => Outcome::Unsupported,
            };
            if ledger.outcome(
                Construct::NetUnixSockets,
                outcome,
                None,
                "unix sockets found under granted paths at spawn are masked",
            ) {
                seccomp.push(deny_if(
                    Syscall::Socket,
                    Condition::SocketFamilyExcept(vec![AF_UNIX]),
                ));
                landlock.handled_net = net_handled;
                if abi >= 9 {
                    for path in paths {
                        landlock.rules.push(LandlockRule {
                            target: RuleTarget::Path(path.clone()),
                            access: AccessFs::RESOLVE_UNIX,
                        });
                    }
                } else {
                    mask_unix_sockets = true;
                }
            }
            if t1 {
                LinuxNetwork::Isolated
            } else {
                LinuxNetwork::NoNamespace
            }
        }
        Network::Proxy { http, socks } => {
            let outcome = if t1 {
                Outcome::Exact
            } else {
                Outcome::Unsupported
            };
            let ports: Vec<_> = http.iter().chain(socks.iter()).copied().collect();
            if ledger.outcome(Construct::NetProxy, outcome, None, "") {
                landlock.handled_net = net_handled;
                for &port in &ports {
                    landlock.net_rules.push(NetRule {
                        port,
                        access: AccessNet(AccessNet::CONNECT_TCP.0 & net_handled.0),
                    });
                }
            }
            LinuxNetwork::ProxyBridge { ports }
        }
        Network::All => {
            ledger.outcome(Construct::NetAll, Outcome::Exact, None, "");
            if let Some(ns) = namespaces.as_mut() {
                ns.net = false;
            }
            LinuxNetwork::NoNamespace
        }
    };

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
    }
    match policy.process.signals {
        Signals::SelfAndChildren => {
            let outcome = if t1 || abi >= 6 {
                Outcome::Exact
            } else {
                Outcome::Unsupported
            };
            ledger.outcome(Construct::SignalsSelfAndChildren, outcome, None, "");
            if abi >= 6 {
                landlock.scopes = Scopes(landlock.scopes.0 | Scopes::SIGNAL.0);
            }
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
    if policy.base == Base::V1 {
        ledger.outcome(Construct::BaseV1, Outcome::Exact, None, "");
        landlock
            .rules
            .extend(crate::base::linux_v1(policy.tty, handled));
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
            seccomp.push(deny(syscall.clone()));
        }
        for (path, access) in &layer.landlock_extra {
            landlock.rules.push(LandlockRule {
                target: RuleTarget::Path(path.clone()),
                access: rights(*access, handled),
            });
        }
    }

    for &class in HardDenyClass::ALL {
        if policy.waive.contains(&class) {
            continue;
        }
        if ledger.outcome(
            Construct::of_class(class),
            class_outcome(class),
            Some(class.to_string()),
            "",
        ) {
            seccomp.extend(class_rules(class));
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
    seccomp.dedup();
    hide_by_siblings.sort();
    hide_by_siblings.dedup();

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
        hide_by_siblings,
        degradations,
        waivers: policy.waive.iter().copied().collect(),
        hygiene: Hygiene::of(policy),
    })
}
