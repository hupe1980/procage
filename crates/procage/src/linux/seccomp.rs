//! The seccomp filter, built in the parent from the plan's denies for the
//! native architecture.
//!
//! The program checks the architecture first and kills the process on any
//! other (32-bit compat calls), and on x86_64 also kills x32 calls. Then it
//! has one block per deny: load the syscall number, compare, test the
//! condition on an argument, return the deny's errno. Blocks are independent,
//! so every jump stays short. Everything else is allowed.

use procage_policy::linux::{
    Action, CLONE_NEW_ANY, CLONE_THREAD, Condition, O_ACCMODE, O_TRUNC, SeccompRule, Syscall,
};

/// One classic BPF instruction (`struct sock_filter`).
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Insn {
    pub(crate) code: u16,
    pub(crate) jt: u8,
    pub(crate) jf: u8,
    pub(crate) k: u32,
}

const LD_W_ABS: u16 = 0x20;
const JMP_JA: u16 = 0x05;
const JEQ_K: u16 = 0x15;
const JGE_K: u16 = 0x35;
const JSET_K: u16 = 0x45;
const ALU_AND_K: u16 = 0x54;
const RET_K: u16 = 0x06;

pub(crate) const RET_KILL_PROCESS: u32 = 0x8000_0000;
pub(crate) const RET_ERRNO: u32 = 0x0005_0000;
pub(crate) const RET_ALLOW: u32 = 0x7fff_0000;

/// Offsets in `struct seccomp_data`.
const NR: u32 = 0;
const ARCH: u32 = 4;
/// The low 32 bits of argument `n` (little-endian).
const fn arg(n: u32) -> u32 {
    16 + 8 * n
}

/// `__X32_SYSCALL_BIT`.
const X32_BIT: u32 = 0x4000_0000;

/// An architecture: its audit value, whether x32 calls must be killed, and
/// its syscall numbers.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Arch {
    pub(crate) audit: u32,
    pub(crate) kill_x32: bool,
    /// `Ok(None)`: the syscall does not exist on this architecture.
    pub(crate) number: fn(&Syscall) -> Result<Option<u32>, ()>,
}

/// The architecture procage was built for.
#[cfg(target_arch = "x86_64")]
pub(crate) const NATIVE: Arch = Arch {
    audit: 0xc000_003e,
    kill_x32: true,
    number: native_number,
};

/// The architecture procage was built for.
#[cfg(target_arch = "aarch64")]
pub(crate) const NATIVE: Arch = Arch {
    audit: 0xc000_00b7,
    kill_x32: false,
    number: native_number,
};

/// The syscall's number on the native architecture.
fn native_number(call: &Syscall) -> Result<Option<u32>, ()> {
    use libc::*;
    let nr: c_long = match call {
        Syscall::AddKey => SYS_add_key,
        Syscall::Bpf => SYS_bpf,
        Syscall::Clone => SYS_clone,
        Syscall::Clone3 => SYS_clone3,
        Syscall::Execve => SYS_execve,
        Syscall::Execveat => SYS_execveat,
        #[cfg(target_arch = "x86_64")]
        Syscall::Fork => SYS_fork,
        #[cfg(target_arch = "x86_64")]
        Syscall::Vfork => SYS_vfork,
        #[cfg(not(target_arch = "x86_64"))]
        Syscall::Fork | Syscall::Vfork => return Ok(None),
        Syscall::Fsmount => SYS_fsmount,
        Syscall::Fsopen => SYS_fsopen,
        Syscall::Ioctl => SYS_ioctl,
        Syscall::IoUringEnter => SYS_io_uring_enter,
        Syscall::IoUringRegister => SYS_io_uring_register,
        Syscall::IoUringSetup => SYS_io_uring_setup,
        Syscall::Kcmp => SYS_kcmp,
        Syscall::Keyctl => SYS_keyctl,
        Syscall::Kill => SYS_kill,
        Syscall::Mount => SYS_mount,
        Syscall::MoveMount => SYS_move_mount,
        Syscall::Msgctl => SYS_msgctl,
        Syscall::Msgget => SYS_msgget,
        Syscall::Msgrcv => SYS_msgrcv,
        Syscall::Msgsnd => SYS_msgsnd,
        #[cfg(target_arch = "x86_64")]
        Syscall::Open => SYS_open,
        #[cfg(not(target_arch = "x86_64"))]
        Syscall::Open => return Ok(None),
        Syscall::OpenTree => SYS_open_tree,
        Syscall::Openat => SYS_openat,
        Syscall::Openat2 => SYS_openat2,
        Syscall::PerfEventOpen => SYS_perf_event_open,
        Syscall::PidfdGetfd => SYS_pidfd_getfd,
        Syscall::PidfdSendSignal => SYS_pidfd_send_signal,
        Syscall::PivotRoot => SYS_pivot_root,
        Syscall::ProcessVmReadv => SYS_process_vm_readv,
        Syscall::ProcessVmWritev => SYS_process_vm_writev,
        Syscall::Ptrace => SYS_ptrace,
        Syscall::RequestKey => SYS_request_key,
        Syscall::RtSigqueueinfo => SYS_rt_sigqueueinfo,
        Syscall::RtTgsigqueueinfo => SYS_rt_tgsigqueueinfo,
        Syscall::Semctl => SYS_semctl,
        Syscall::Semget => SYS_semget,
        Syscall::Semop => SYS_semop,
        Syscall::Semtimedop => SYS_semtimedop,
        Syscall::Setns => SYS_setns,
        Syscall::Setpgid => SYS_setpgid,
        Syscall::Setsid => SYS_setsid,
        Syscall::Shmat => SYS_shmat,
        Syscall::Shmctl => SYS_shmctl,
        Syscall::Shmdt => SYS_shmdt,
        Syscall::Shmget => SYS_shmget,
        Syscall::Socket => SYS_socket,
        Syscall::Tgkill => SYS_tgkill,
        Syscall::Tkill => SYS_tkill,
        Syscall::Truncate => SYS_truncate,
        Syscall::Umount2 => SYS_umount2,
        Syscall::Unshare => SYS_unshare,
        Syscall::Userfaultfd => SYS_userfaultfd,
        _ => return Err(()),
    };
    u32::try_from(nr).map(Some).map_err(|_| ())
}

const fn insn(code: u16, jt: u8, jf: u8, k: u32) -> Insn {
    Insn { code, jt, jf, k }
}

const fn ld(offset: u32) -> Insn {
    insn(LD_W_ABS, 0, 0, offset)
}

const fn ret(k: u32) -> Insn {
    insn(RET_K, 0, 0, k)
}

/// The return value of a deny; with `notify`, an `EPERM` deny goes to the
/// supervisor, which answers `EPERM` and records it. A `Supervise` rule
/// always goes to the supervisor.
fn verdict(action: Action, notify: bool) -> u32 {
    let errno = match action {
        Action::Supervise => return libc::SECCOMP_RET_USER_NOTIF,
        Action::Eperm if notify => return libc::SECCOMP_RET_USER_NOTIF,
        Action::Eperm => libc::EPERM,
        Action::Enosys => libc::ENOSYS,
    };
    RET_ERRNO | (errno as u32 & 0xffff)
}

/// A jump offset; blocks are built from short lists, so it always fits.
fn offset(n: usize) -> Result<u8, String> {
    u8::try_from(n).map_err(|_| "a seccomp rule with too many values".to_string())
}

/// The block after `ld nr; jeq nr`: the condition and the deny.
fn body(condition: &Condition, deny: Insn) -> Result<Vec<Insn>, String> {
    let any_of = |n: u32, values: &[u32]| -> Result<Vec<Insn>, String> {
        // `ld arg; jeq v -> deny ...; ja over the deny; deny`
        let mut out = vec![ld(arg(n))];
        for (i, &v) in values.iter().enumerate() {
            out.push(insn(JEQ_K, offset(values.len() - i)?, 0, v));
        }
        out.push(insn(JMP_JA, 0, 0, 1));
        out.push(deny);
        Ok(out)
    };
    Ok(match condition {
        Condition::Always => vec![deny],
        Condition::SocketFamily(families) => any_of(0, families)?,
        Condition::SocketFamilyExcept(families) => {
            // `ld arg; jeq v -> past the deny ...; deny`
            let mut out = vec![ld(arg(0))];
            for (i, &v) in families.iter().enumerate() {
                out.push(insn(JEQ_K, offset(families.len() - i)?, 0, v));
            }
            out.push(deny);
            out
        }
        Condition::IoctlCommand(commands) => {
            // The kernel takes the command as 32 bits, so the high half is
            // ignored here too.
            let low: Vec<u32> = commands.iter().map(|&c| c as u32).collect();
            any_of(1, &low)?
        }
        Condition::CloneWithoutThread => vec![ld(arg(0)), insn(JSET_K, 1, 0, CLONE_THREAD), deny],
        Condition::CloneNewNamespace => vec![ld(arg(0)), insn(JSET_K, 0, 1, CLONE_NEW_ANY), deny],
        Condition::TruncWithoutWrite { flags_arg } => {
            // `ld flags; and O_TRUNC|O_ACCMODE; jeq O_TRUNC (read-only) or
            // O_TRUNC|3 (no access) -> deny`
            vec![
                ld(arg(u32::from(*flags_arg))),
                insn(ALU_AND_K, 0, 0, O_TRUNC | O_ACCMODE),
                insn(JEQ_K, 2, 0, O_TRUNC),
                insn(JEQ_K, 1, 0, O_TRUNC | O_ACCMODE),
                insn(JMP_JA, 0, 0, 1),
                deny,
            ]
        }
    })
}

/// The filter for `rules` on `arch`; with `notify`, `EPERM` denies are
/// reported to a supervisor (see [`verdict`]). Fails with the name of a
/// syscall that has no number.
pub(crate) fn build(rules: &[SeccompRule], arch: &Arch, notify: bool) -> Result<Vec<Insn>, String> {
    let mut prog = vec![
        ld(ARCH),
        insn(JEQ_K, 1, 0, arch.audit),
        ret(RET_KILL_PROCESS),
    ];
    if arch.kill_x32 {
        prog.extend([ld(NR), insn(JGE_K, 0, 1, X32_BIT), ret(RET_KILL_PROCESS)]);
    }
    for rule in rules {
        let Some(nr) = (arch.number)(&rule.syscall).map_err(|()| rule.syscall.to_string())? else {
            continue;
        };
        let body = body(&rule.condition, ret(verdict(rule.action, notify)))?;
        prog.push(ld(NR));
        prog.push(insn(JEQ_K, 0, offset(body.len())?, nr));
        prog.extend(body);
    }
    prog.push(ret(RET_ALLOW));
    Ok(prog)
}

#[cfg(test)]
mod tests {
    use super::*;
    use procage_policy::linux::{AF_NETLINK, AF_UNIX, AF_VSOCK, TIOCSTI};

    /// The input of a filter (`struct seccomp_data`).
    struct Data {
        nr: u32,
        arch: u32,
        args: [u64; 6],
    }

    /// Runs `prog` on `data`: the subset `build` emits.
    fn run(prog: &[Insn], data: &Data) -> u32 {
        let word = |offset: u32| -> u32 {
            match offset {
                NR => data.nr,
                ARCH => data.arch,
                o => {
                    let i = ((o - 16) / 8) as usize;
                    let v = data.args[i];
                    if (o - 16) % 8 == 0 {
                        v as u32
                    } else {
                        (v >> 32) as u32
                    }
                }
            }
        };
        let (mut pc, mut a) = (0usize, 0u32);
        loop {
            let i = prog[pc];
            pc += 1;
            match i.code {
                LD_W_ABS => a = word(i.k),
                ALU_AND_K => a &= i.k,
                JMP_JA => pc += i.k as usize,
                JEQ_K | JGE_K | JSET_K => {
                    let taken = match i.code {
                        JEQ_K => a == i.k,
                        JGE_K => a >= i.k,
                        _ => a & i.k != 0,
                    };
                    pc += usize::from(if taken { i.jt } else { i.jf });
                }
                RET_K => return i.k,
                other => panic!("unexpected opcode {other:#x}"),
            }
        }
    }

    fn call(syscall: Syscall, args: [u64; 6]) -> Data {
        Data {
            nr: (NATIVE.number)(&syscall).unwrap().unwrap(),
            arch: NATIVE.audit,
            args,
        }
    }

    fn rule(syscall: Syscall, condition: Condition) -> SeccompRule {
        SeccompRule {
            syscall,
            condition,
            action: Action::Eperm,
            reason: None,
        }
    }

    const EPERM: u32 = RET_ERRNO | libc::EPERM as u32;

    #[test]
    fn every_condition_gives_its_verdict() {
        let rules = vec![
            rule(Syscall::Ptrace, Condition::Always),
            rule(
                Syscall::Socket,
                Condition::SocketFamily(vec![AF_NETLINK, AF_VSOCK]),
            ),
            rule(
                Syscall::Ioctl,
                Condition::IoctlCommand(vec![TIOCSTI, 0x541c]),
            ),
            rule(Syscall::Clone, Condition::CloneNewNamespace),
            SeccompRule {
                syscall: Syscall::Clone3,
                condition: Condition::Always,
                action: Action::Enosys,
                reason: None,
            },
        ];
        let prog = build(&rules, &NATIVE, false).unwrap();
        let v = |s: Syscall, args: [u64; 6]| run(&prog, &call(s, args));
        assert_eq!(v(Syscall::Ptrace, [0; 6]), EPERM);
        assert_eq!(
            v(Syscall::Socket, [u64::from(AF_NETLINK), 0, 0, 0, 0, 0]),
            EPERM
        );
        assert_eq!(
            v(Syscall::Socket, [u64::from(AF_VSOCK), 0, 0, 0, 0, 0]),
            EPERM
        );
        assert_eq!(v(Syscall::Socket, [2, 1, 0, 0, 0, 0]), RET_ALLOW);
        assert_eq!(v(Syscall::Ioctl, [0, TIOCSTI, 0, 0, 0, 0]), EPERM);
        // The kernel ignores the high half of the command; so does the filter.
        assert_eq!(
            v(Syscall::Ioctl, [0, (1 << 32) | TIOCSTI, 0, 0, 0, 0]),
            EPERM
        );
        assert_eq!(v(Syscall::Ioctl, [0, 0x5401, 0, 0, 0, 0]), RET_ALLOW);
        assert_eq!(v(Syscall::Clone, [0x1000_0000, 0, 0, 0, 0, 0]), EPERM);
        assert_eq!(v(Syscall::Clone, [0x0001_0f00, 0, 0, 0, 0, 0]), RET_ALLOW);
        assert_eq!(v(Syscall::Clone3, [0; 6]), RET_ERRNO | libc::ENOSYS as u32);
        assert_eq!(v(Syscall::Kill, [0; 6]), RET_ALLOW);
    }

    #[test]
    fn truncation_needs_write_access() {
        let rules = vec![rule(
            Syscall::Openat,
            Condition::TruncWithoutWrite { flags_arg: 2 },
        )];
        let prog = build(&rules, &NATIVE, false).unwrap();
        let v = |flags: i32| {
            let flags = u64::from(flags as u32);
            run(&prog, &call(Syscall::Openat, [0, 0, flags, 0, 0, 0]))
        };
        let (rd, wr, rw) = (libc::O_RDONLY, libc::O_WRONLY, libc::O_RDWR);
        let trunc = libc::O_TRUNC;
        assert_eq!(trunc as u32, O_TRUNC);
        assert_eq!(v(rd | trunc), EPERM);
        assert_eq!(v(3 | trunc), EPERM);
        assert_eq!(v(rd | trunc | libc::O_CLOEXEC | libc::O_NOFOLLOW), EPERM);
        assert_eq!(v(wr | trunc | libc::O_CREAT), RET_ALLOW);
        assert_eq!(v(rw | trunc), RET_ALLOW);
        assert_eq!(v(rd | libc::O_CLOEXEC), RET_ALLOW);
        assert_eq!(v(3), RET_ALLOW);
    }

    #[test]
    fn processes_and_unix_sockets() {
        let rules = vec![
            rule(Syscall::Clone, Condition::CloneWithoutThread),
            rule(
                Syscall::Socket,
                Condition::SocketFamilyExcept(vec![AF_UNIX]),
            ),
        ];
        let prog = build(&rules, &NATIVE, false).unwrap();
        let v = |s: Syscall, args: [u64; 6]| run(&prog, &call(s, args));
        assert_eq!(v(Syscall::Clone, [0x11, 0, 0, 0, 0, 0]), EPERM);
        assert_eq!(
            v(Syscall::Clone, [u64::from(CLONE_THREAD), 0, 0, 0, 0, 0]),
            RET_ALLOW
        );
        assert_eq!(
            v(Syscall::Socket, [u64::from(AF_UNIX), 0, 0, 0, 0, 0]),
            RET_ALLOW
        );
        assert_eq!(v(Syscall::Socket, [2, 0, 0, 0, 0, 0]), EPERM);
    }

    #[test]
    fn a_foreign_architecture_is_killed() {
        let prog = build(&[], &NATIVE, false).unwrap();
        let mut data = call(Syscall::Kill, [0; 6]);
        assert_eq!(run(&prog, &data), RET_ALLOW);
        data.arch = 0x4000_0003; // i386
        assert_eq!(run(&prog, &data), RET_KILL_PROCESS);
    }

    #[test]
    fn x32_calls_are_killed_where_they_exist() {
        let prog = build(&[], &NATIVE, false).unwrap();
        let data = Data {
            nr: X32_BIT | 39,
            arch: NATIVE.audit,
            args: [0; 6],
        };
        let expected = if NATIVE.kill_x32 {
            RET_KILL_PROCESS
        } else {
            RET_ALLOW
        };
        assert_eq!(run(&prog, &data), expected);
    }

    /// x86_64, whatever the host: its x32 check runs on aarch64 builds too.
    const X86_64: Arch = Arch {
        audit: 0xc000_003e,
        kill_x32: true,
        number: native_number,
    };

    #[test]
    fn an_x86_64_filter_kills_x32_and_i386_calls() {
        let prog = build(&[], &X86_64, false).unwrap();
        let x32 = Data {
            nr: X32_BIT | 39,
            arch: X86_64.audit,
            args: [0; 6],
        };
        assert_eq!(run(&prog, &x32), RET_KILL_PROCESS);
        let i386 = Data {
            nr: 26,
            arch: 0x4000_0003,
            args: [0; 6],
        };
        assert_eq!(run(&prog, &i386), RET_KILL_PROCESS);
        let native = Data {
            nr: 39,
            arch: X86_64.audit,
            args: [0; 6],
        };
        assert_eq!(run(&prog, &native), RET_ALLOW);
    }

    /// The filter of every policy denies the hard-deny syscalls, including
    /// the mount family, whose kernel errno cannot be told apart from a
    /// missing privilege.
    /// Policies that together use every rule origin and condition.
    fn varied_plans() -> Vec<Vec<SeccompRule>> {
        use procage_policy::{
            Lifetime, LowerOptions, Network, Plan, Policy, Signals, Target, Tier, lower,
        };
        let mut policies = vec![Policy::default()];
        let mut p = Policy::default();
        p.process.fork = true;
        p.process.lifetime = Lifetime::Run;
        p.process.signals = Signals::None;
        p.net = Network::None;
        p.ipc
            .unix_sockets
            .push(procage_policy::AbsPath::new("/run/x.sock").unwrap());
        policies.push(p);
        let mut out = Vec::new();
        for policy in &policies {
            for tier in [Tier::T1, Tier::T2] {
                for abi in [1, 2, 6, 8] {
                    let target = Target::Linux {
                        tier,
                        landlock_abi: abi,
                    };
                    let options = LowerOptions::default().accept_spawn_snapshot();
                    if let Ok(Plan::Linux(plan)) = lower(policy, target, &options) {
                        out.push(plan.seccomp);
                    }
                }
            }
        }
        assert!(out.len() >= 8, "{}", out.len());
        out
    }

    /// The notifying filter is the plain one with every `EPERM` verdict
    /// replaced, and nothing else.
    #[test]
    fn notifying_changes_only_eperm_verdicts() {
        let mut replaced = 0;
        for rules in varied_plans() {
            let plain = build(&rules, &NATIVE, false).unwrap();
            let notify = build(&rules, &NATIVE, true).unwrap();
            assert_eq!(plain.len(), notify.len());
            for (p, n) in plain.iter().zip(&notify) {
                if p != n {
                    assert_eq!((p.code, p.k), (RET_K, EPERM));
                    assert_eq!((n.code, n.k), (RET_K, libc::SECCOMP_RET_USER_NOTIF));
                    replaced += 1;
                }
            }
            assert!(
                notify
                    .iter()
                    .all(|i| i.k != RET_ERRNO | libc::EPERM as u32 || i.code != RET_K)
            );
        }
        assert!(replaced > 0);
    }

    /// `Condition::matches`, which names the rule behind a notification,
    /// decides exactly as the filter on edge and pseudo-random arguments.
    #[test]
    fn matches_agrees_with_the_filter() {
        let mut seed = 0x9e37_79b9_7f4a_7c15u64;
        let mut next = move || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        let edges = [
            0u64,
            1,
            2,
            3,
            TIOCSTI,
            u64::from(O_TRUNC),
            u64::from(O_TRUNC | 1),
            u64::from(O_TRUNC | 2),
            u64::from(O_TRUNC | 3),
            u64::from(CLONE_THREAD),
            u64::from(CLONE_NEW_ANY),
            0x1000_0000,
            1 << 32,
            u64::MAX,
        ];
        let mut checked = 0;
        for rules in varied_plans() {
            for rule in rules.iter().filter(|r| r.action == Action::Eperm) {
                let Ok(Some(_)) = (NATIVE.number)(&rule.syscall) else {
                    continue;
                };
                let prog = build(std::slice::from_ref(rule), &NATIVE, false).unwrap();
                for i in 0..200 {
                    let mut args = [0u64; 6];
                    for a in &mut args {
                        *a = if i < edges.len() * 2 {
                            edges[(i + checked) % edges.len()]
                        } else {
                            next()
                        };
                    }
                    let filtered = run(&prog, &call(rule.syscall.clone(), args)) == EPERM;
                    assert_eq!(
                        rule.condition.matches(&args),
                        filtered,
                        "{rule:?} {args:x?}"
                    );
                    checked += 1;
                }
            }
        }
        assert!(checked > 1000, "{checked}");
    }

    #[test]
    fn every_policy_denies_the_hard_deny_syscalls() {
        use procage_policy::{LowerOptions, Plan, Policy, Target, Tier, lower};
        for tier in [Tier::T1, Tier::T2] {
            let target = Target::Linux {
                tier,
                landlock_abi: 8,
            };
            let Plan::Linux(plan) =
                lower(&Policy::default(), target, &LowerOptions::default()).unwrap()
            else {
                panic!("a Linux plan");
            };
            let prog = build(&plan.seccomp, &NATIVE, false).unwrap();
            for name in [
                "mount",
                "umount2",
                "pivot_root",
                "open_tree",
                "move_mount",
                "fsopen",
                "fsmount",
                "unshare",
                "setns",
                "ptrace",
                "process_vm_readv",
                "process_vm_writev",
                "pidfd_getfd",
                "kcmp",
                "io_uring_setup",
                "io_uring_enter",
                "io_uring_register",
                "bpf",
                "perf_event_open",
                "userfaultfd",
                "keyctl",
                "add_key",
                "request_key",
            ] {
                let s = Syscall::from_name(name).unwrap();
                assert_eq!(run(&prog, &call(s, [0; 6])), EPERM, "{tier}: {name}");
            }
            assert_eq!(
                run(&prog, &call(Syscall::Clone, [0x1000_0000, 0, 0, 0, 0, 0])),
                EPERM,
                "{tier}: clone(CLONE_NEWUSER)"
            );
            assert_eq!(
                run(&prog, &call(Syscall::Clone3, [0; 6])),
                RET_ERRNO | libc::ENOSYS as u32,
                "{tier}: clone3"
            );
            assert_eq!(
                run(&prog, &call(Syscall::Ioctl, [0, TIOCSTI, 0, 0, 0, 0])),
                EPERM,
                "{tier}: TIOCSTI"
            );
        }
    }

    #[test]
    fn an_unknown_syscall_is_named() {
        let other = Syscall::from_name("acct").unwrap();
        assert_eq!(
            build(&[rule(other, Condition::Always)], &NATIVE, false),
            Err("acct".to_string())
        );
    }

    #[test]
    fn every_known_syscall_has_a_number_or_none() {
        for name in [
            "add_key",
            "bpf",
            "clone",
            "clone3",
            "fork",
            "fsmount",
            "fsopen",
            "ioctl",
            "io_uring_enter",
            "io_uring_register",
            "io_uring_setup",
            "kcmp",
            "keyctl",
            "kill",
            "mount",
            "move_mount",
            "msgctl",
            "msgget",
            "msgrcv",
            "msgsnd",
            "open_tree",
            "perf_event_open",
            "pidfd_getfd",
            "pidfd_send_signal",
            "pivot_root",
            "process_vm_readv",
            "process_vm_writev",
            "ptrace",
            "request_key",
            "rt_sigqueueinfo",
            "rt_tgsigqueueinfo",
            "semctl",
            "semget",
            "semop",
            "semtimedop",
            "setns",
            "setpgid",
            "setsid",
            "shmat",
            "shmctl",
            "shmdt",
            "shmget",
            "socket",
            "tgkill",
            "tkill",
            "umount2",
            "unshare",
            "userfaultfd",
            "vfork",
        ] {
            let s = Syscall::from_name(name).unwrap();
            assert!((NATIVE.number)(&s).is_ok(), "{name}");
        }
    }
}
