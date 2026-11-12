//! The Linux side: the typed Linux layer and the plan a Linux lowering
//! produces.
//!
//! A [`LinuxPlan`] states what the spawn backend is to set up: namespaces and
//! mounts (tier T1), Landlock rights for the given ABI, seccomp denies by
//! syscall name, and the network mode. It is data. Building BPF for an
//! architecture, opening rule file descriptors and applying anything happen
//! in `procage`.

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

use crate::glob::Glob;
use crate::lower::{Degradation, Hygiene, Tier};
use crate::name::{GrantName, Port, SyscallName};
use crate::path::AbsPath;
use crate::policy::{Access, HardDenyClass, Ports};
use crate::sbpl::DenyReason;

/// The newest Landlock ABI this crate knows. A higher ABI is treated as this
/// one: no later right is assumed.
pub const NEWEST_KNOWN_ABI: u8 = 12;

/// Landlock filesystem rights.
///
/// Bit positions follow the kernel's uapi for the rights of ABI 1 to 5.
/// `RESOLVE_UNIX` (ABI 9) uses this crate's own position; the backend uses
/// rights up to ABI 8.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AccessFs(pub u64);

impl AccessFs {
    /// Execute a file.
    pub const EXECUTE: AccessFs = AccessFs(1 << 0);
    /// Open a file for writing.
    pub const WRITE_FILE: AccessFs = AccessFs(1 << 1);
    /// Open a file for reading.
    pub const READ_FILE: AccessFs = AccessFs(1 << 2);
    /// List a directory.
    pub const READ_DIR: AccessFs = AccessFs(1 << 3);
    /// Remove a directory.
    pub const REMOVE_DIR: AccessFs = AccessFs(1 << 4);
    /// Remove a file.
    pub const REMOVE_FILE: AccessFs = AccessFs(1 << 5);
    /// Create a character device.
    pub const MAKE_CHAR: AccessFs = AccessFs(1 << 6);
    /// Create a directory.
    pub const MAKE_DIR: AccessFs = AccessFs(1 << 7);
    /// Create a regular file.
    pub const MAKE_REG: AccessFs = AccessFs(1 << 8);
    /// Create a Unix socket file.
    pub const MAKE_SOCK: AccessFs = AccessFs(1 << 9);
    /// Create a FIFO.
    pub const MAKE_FIFO: AccessFs = AccessFs(1 << 10);
    /// Create a block device.
    pub const MAKE_BLOCK: AccessFs = AccessFs(1 << 11);
    /// Create a symlink.
    pub const MAKE_SYM: AccessFs = AccessFs(1 << 12);
    /// Link or rename across directories (ABI 2). Never granted by procage.
    pub const REFER: AccessFs = AccessFs(1 << 13);
    /// Truncate a file (ABI 3).
    pub const TRUNCATE: AccessFs = AccessFs(1 << 14);
    /// ioctl on a device (ABI 5).
    pub const IOCTL_DEV: AccessFs = AccessFs(1 << 15);
    /// Connect to a pathname Unix socket (ABI 9).
    pub const RESOLVE_UNIX: AccessFs = AccessFs(1 << 16);

    /// Rights that apply to a file (rather than a directory).
    pub const FILE_RIGHTS: AccessFs = AccessFs(
        Self::EXECUTE.0
            | Self::WRITE_FILE.0
            | Self::READ_FILE.0
            | Self::TRUNCATE.0
            | Self::IOCTL_DEV.0,
    );

    /// No right.
    pub const NONE: AccessFs = AccessFs(0);

    /// Both sets.
    pub const fn union(self, other: AccessFs) -> AccessFs {
        AccessFs(self.0 | other.0)
    }

    /// The rights in both sets.
    pub const fn intersect(self, other: AccessFs) -> AccessFs {
        AccessFs(self.0 & other.0)
    }

    /// `self` without `other`.
    pub const fn without(self, other: AccessFs) -> AccessFs {
        AccessFs(self.0 & !other.0)
    }

    /// Whether every right of `other` is in `self`.
    pub const fn contains(self, other: AccessFs) -> bool {
        self.0 & other.0 == other.0
    }
}

/// Landlock network rights.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AccessNet(pub u64);

impl AccessNet {
    /// Bind a TCP port (ABI 4).
    pub const BIND_TCP: AccessNet = AccessNet(1 << 0);
    /// Connect to a TCP port (ABI 4).
    pub const CONNECT_TCP: AccessNet = AccessNet(1 << 1);
    /// Bind a UDP port (ABI 10).
    pub const BIND_UDP: AccessNet = AccessNet(1 << 2);
    /// Connect or send to a UDP port (ABI 10).
    pub const CONNECT_SEND_UDP: AccessNet = AccessNet(1 << 3);
    /// No right.
    pub const NONE: AccessNet = AccessNet(0);
}

/// Landlock scopes (ABI 6).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Scopes(pub u64);

impl Scopes {
    /// Abstract Unix sockets outside the domain.
    pub const ABSTRACT_UNIX_SOCKET: Scopes = Scopes(1 << 0);
    /// Signals to processes outside the domain.
    pub const SIGNAL: Scopes = Scopes(1 << 1);
    /// No scope.
    pub const NONE: Scopes = Scopes(0);
}

fn effective(abi: u8) -> u8 {
    abi.min(NEWEST_KNOWN_ABI)
}

/// The filesystem rights Landlock handles at `abi`.
pub fn handled_fs(abi: u8) -> AccessFs {
    let abi = effective(abi);
    if abi == 0 {
        return AccessFs::NONE;
    }
    let mut rights = AccessFs((1 << 13) - 1);
    if abi >= 2 {
        rights = rights.union(AccessFs::REFER);
    }
    if abi >= 3 {
        rights = rights.union(AccessFs::TRUNCATE);
    }
    if abi >= 5 {
        rights = rights.union(AccessFs::IOCTL_DEV);
    }
    if abi >= 9 {
        rights = rights.union(AccessFs::RESOLVE_UNIX);
    }
    rights
}

/// The network rights Landlock handles at `abi`.
pub fn handled_net(abi: u8) -> AccessNet {
    let abi = effective(abi);
    let mut rights = AccessNet::NONE;
    if abi >= 4 {
        rights = AccessNet(AccessNet::BIND_TCP.0 | AccessNet::CONNECT_TCP.0);
    }
    if abi >= 10 {
        rights = AccessNet(rights.0 | AccessNet::BIND_UDP.0 | AccessNet::CONNECT_SEND_UDP.0);
    }
    rights
}

/// The scopes Landlock supports at `abi`.
pub fn scopes(abi: u8) -> Scopes {
    if effective(abi) >= 6 {
        Scopes(Scopes::ABSTRACT_UNIX_SOCKET.0 | Scopes::SIGNAL.0)
    } else {
        Scopes::NONE
    }
}

/// The Landlock rights for an access kind, limited to what `handled` covers.
///
/// `Write` includes `REFER`, so files move and link between directories of
/// the writable trees. Landlock refuses a move or link that would give the
/// file a right it lacks where it is, and one out of a tree without `REFER`
/// (any read-only tree); on tier T1 protected and hidden targets are separate
/// mounts, which no move or link crosses.
pub fn rights(access: Access, handled: AccessFs) -> AccessFs {
    let read = AccessFs::READ_FILE.union(AccessFs::READ_DIR);
    let rights = match access {
        Access::Read => read,
        Access::Exec => read.union(AccessFs::EXECUTE),
        Access::Write => read
            .union(AccessFs::WRITE_FILE)
            .union(AccessFs::REMOVE_FILE)
            .union(AccessFs::REMOVE_DIR)
            .union(AccessFs::MAKE_REG)
            .union(AccessFs::MAKE_DIR)
            .union(AccessFs::MAKE_SOCK)
            .union(AccessFs::MAKE_FIFO)
            .union(AccessFs::MAKE_SYM)
            .union(AccessFs::TRUNCATE)
            .union(AccessFs::REFER),
        Access::Protect | Access::Hide => AccessFs::NONE,
    };
    rights.intersect(handled)
}

macro_rules! syscalls {
    ($($variant:ident => $name:literal,)*) => {
        /// A Linux syscall, by name. The number is architecture-specific and
        /// is resolved by the Linux backend.
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
        #[cfg_attr(
            feature = "serde",
            derive(serde::Serialize, serde::Deserialize),
            serde(try_from = "alloc::string::String", into = "alloc::string::String")
        )]
        #[non_exhaustive]
        pub enum Syscall {
            $(
                #[doc = concat!("`", $name, "`")]
                $variant,
            )*
            /// Any other syscall.
            Other(SyscallName),
        }

        impl Syscall {
            /// The syscall's name.
            pub fn as_str(&self) -> &str {
                match self {
                    $(Syscall::$variant => $name,)*
                    Syscall::Other(name) => name.as_str(),
                }
            }

            /// The syscall with this name.
            pub fn from_name(name: &str) -> Result<Syscall, crate::name::NameError> {
                match name {
                    $($name => Ok(Syscall::$variant),)*
                    other => SyscallName::new(other).map(Syscall::Other),
                }
            }
        }
    };
}

syscalls! {
    AddKey => "add_key",
    Bpf => "bpf",
    Clone => "clone",
    Clone3 => "clone3",
    Execve => "execve",
    Execveat => "execveat",
    Fork => "fork",
    Fsmount => "fsmount",
    Fsopen => "fsopen",
    Ioctl => "ioctl",
    IoUringEnter => "io_uring_enter",
    IoUringRegister => "io_uring_register",
    IoUringSetup => "io_uring_setup",
    Kcmp => "kcmp",
    Keyctl => "keyctl",
    Kill => "kill",
    Mount => "mount",
    MoveMount => "move_mount",
    Msgctl => "msgctl",
    Msgget => "msgget",
    Msgrcv => "msgrcv",
    Msgsnd => "msgsnd",
    Open => "open",
    OpenTree => "open_tree",
    Openat => "openat",
    Openat2 => "openat2",
    PerfEventOpen => "perf_event_open",
    PidfdGetfd => "pidfd_getfd",
    PidfdSendSignal => "pidfd_send_signal",
    PivotRoot => "pivot_root",
    ProcessVmReadv => "process_vm_readv",
    ProcessVmWritev => "process_vm_writev",
    Ptrace => "ptrace",
    RequestKey => "request_key",
    RtSigqueueinfo => "rt_sigqueueinfo",
    RtTgsigqueueinfo => "rt_tgsigqueueinfo",
    Semctl => "semctl",
    Semget => "semget",
    Semop => "semop",
    Semtimedop => "semtimedop",
    Setns => "setns",
    Setpgid => "setpgid",
    Setsid => "setsid",
    Shmat => "shmat",
    Shmctl => "shmctl",
    Shmdt => "shmdt",
    Shmget => "shmget",
    Socket => "socket",
    Tgkill => "tgkill",
    Tkill => "tkill",
    Truncate => "truncate",
    Umount2 => "umount2",
    Unshare => "unshare",
    Userfaultfd => "userfaultfd",
    Vfork => "vfork",
}

impl TryFrom<alloc::string::String> for Syscall {
    type Error = crate::name::NameError;

    fn try_from(name: alloc::string::String) -> Result<Self, Self::Error> {
        Syscall::from_name(&name)
    }
}

impl From<Syscall> for alloc::string::String {
    fn from(syscall: Syscall) -> alloc::string::String {
        syscall.as_str().into()
    }
}

impl fmt::Display for Syscall {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// `AF_UNIX`.
pub const AF_UNIX: u32 = 1;
/// `AF_INET`.
pub const AF_INET: u32 = 2;
/// `AF_INET6`.
pub const AF_INET6: u32 = 10;
/// `AF_NETLINK`.
pub const AF_NETLINK: u32 = 16;
/// `AF_VSOCK`.
pub const AF_VSOCK: u32 = 40;
/// `O_ACCMODE`.
pub const O_ACCMODE: u32 = 0o3;
/// `O_TRUNC`.
pub const O_TRUNC: u32 = 0o1000;
/// The `CLONE_NEW*` flags `clone` accepts (`CLONE_NEWTIME` is not one: its
/// bit is part of the exit signal there).
pub const CLONE_NEW_ANY: u32 = 0x0002_0000 // NEWNS
    | 0x0200_0000 // NEWCGROUP
    | 0x0400_0000 // NEWUTS
    | 0x0800_0000 // NEWIPC
    | 0x1000_0000 // NEWUSER
    | 0x2000_0000 // NEWPID
    | 0x4000_0000; // NEWNET
/// `CLONE_THREAD`.
pub const CLONE_THREAD: u32 = 0x0001_0000;
/// The rights on a terminal device the child may use (`Tty::Inherit`'s
/// terminals, `Tty::NewPty`'s own device and `/dev/tty`): read, write and
/// device ioctls.
pub const TERMINAL_ACCESS: AccessFs = AccessFs::READ_FILE
    .union(AccessFs::WRITE_FILE)
    .union(AccessFs::IOCTL_DEV);
/// `TIOCSTI`.
pub const TIOCSTI: u64 = 0x5412;
/// `TIOCLINUX`.
pub const TIOCLINUX: u64 = 0x541c;

/// When a seccomp deny applies.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Condition {
    /// Every call.
    Always,
    /// `socket` with one of these families.
    SocketFamily(Vec<u32>),
    /// `socket` with any family except these.
    SocketFamilyExcept(Vec<u32>),
    /// `ioctl` with one of these commands.
    IoctlCommand(Vec<u64>),
    /// `clone` without `CLONE_THREAD` (creating a process).
    CloneWithoutThread,
    /// `clone` with any `CLONE_NEW*` flag.
    CloneNewNamespace,
    /// An `open`-like call whose argument `flags_arg` has `O_TRUNC` and an
    /// access mode that is neither `O_WRONLY` nor `O_RDWR`: a truncation
    /// Landlock does not check below ABI 3.
    TruncWithoutWrite {
        /// The index of the flags argument.
        flags_arg: u8,
    },
}

impl Condition {
    /// Whether a call with `args` meets the condition, decided exactly as the
    /// filter decides it: on the low 32 bits of each argument, which is all
    /// the filter loads.
    pub fn matches(&self, args: &[u64; 6]) -> bool {
        let low = |n: usize| args[n] as u32;
        match self {
            Condition::Always => true,
            Condition::SocketFamily(families) => families.contains(&low(0)),
            Condition::SocketFamilyExcept(families) => !families.contains(&low(0)),
            Condition::IoctlCommand(commands) => commands.iter().any(|&c| c as u32 == low(1)),
            Condition::CloneWithoutThread => low(0) & CLONE_THREAD == 0,
            Condition::CloneNewNamespace => low(0) & CLONE_NEW_ANY != 0,
            Condition::TruncWithoutWrite { flags_arg } => {
                let flags = low(usize::from(*flags_arg)) & (O_TRUNC | O_ACCMODE);
                flags == O_TRUNC || flags == O_TRUNC | O_ACCMODE
            }
        }
    }
}

/// What a seccomp deny returns.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Action {
    /// Fail with `EPERM`.
    Eperm,
    /// Fail with `ENOSYS`, so libc falls back to an older call that can be
    /// filtered (used for `clone3`).
    Enosys,
    /// Ask the run's supervisor, whatever the reporting setting
    /// (`SECCOMP_RET_USER_NOTIF`). Used for `execve` and `execveat` under
    /// [`Exec::Never`](crate::Exec::Never): the supervisor lets through the
    /// exec that starts the program and refuses every later one with
    /// `EPERM`.
    Supervise,
}

/// One seccomp deny.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SeccompRule {
    /// The syscall.
    pub syscall: Syscall,
    /// When it is denied.
    pub condition: Condition,
    /// What the call returns.
    pub action: Action,
    /// Why the call is refused; `None`: the policy does not grant it.
    pub reason: Option<DenyReason>,
}

/// A mount the T1 backend sets up in the child's mount namespace.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Mount {
    /// Bind the path over itself read-only.
    ReadOnlyBind(AbsPath),
    /// Cover the path with an empty, inaccessible mount.
    Mask(AbsPath),
    /// A private, empty `/dev/shm`.
    PrivateDevShm,
    /// Bind the path over itself, so it cannot be renamed or removed.
    Pin(AbsPath),
}

/// The Linux paths of a data-driven hard-deny class, matched at spawn on
/// tier T1 and checked against grants on tier T2.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ClassPaths {
    /// The class.
    pub class: HardDenyClass,
    /// `true`: the paths are hidden (no read, no write); `false`: they are
    /// read-only.
    pub hide: bool,
    /// Paths relative to every home.
    pub home: Vec<String>,
    /// Names relative to any directory (matched under writable trees).
    pub anywhere: Vec<String>,
    /// Absolute paths.
    pub system: Vec<AbsPath>,
    /// Whether every `.git` directory under a writable tree is pinned.
    pub pin_git: bool,
}

impl ClassPaths {
    /// The patterns these paths stand for, with homes as `/home/*` and
    /// `/root`, for checking whether a rule can reach them.
    pub fn patterns(&self) -> Vec<String> {
        let mut out = Vec::new();
        for home in crate::presets::LINUX_HOMES {
            out.extend(self.home.iter().map(|rel| alloc::format!("{home}/{rel}")));
        }
        out.extend(self.anywhere.iter().map(|n| alloc::format!("/**/{n}")));
        out.extend(
            self.system
                .iter()
                .map(|p| String::from_utf8_lossy(p.as_bytes()).into_owned()),
        );
        if self.pin_git {
            out.push("/**/.git".into());
        }
        out
    }
}

/// Whether a rule on `path` reaches other processes' entries under `/proc`:
/// `/`, `/proc` or a path below it other than `/proc/self` and
/// `/proc/thread-self`. Without a PID namespace such a rule is the
/// approximation `proc-other-processes`.
pub fn reaches_other_processes(path: &[u8]) -> bool {
    let own = |p: &[u8]| {
        [b"/proc/self".as_slice(), b"/proc/thread-self"]
            .iter()
            .any(|o| p == *o || (p.starts_with(o) && p.get(o.len()) == Some(&b'/')))
    };
    path == b"/" || path == b"/proc" || (path.starts_with(b"/proc/") && !own(path))
}

/// What the approximation `proc-other-processes` does.
pub const PROC_OTHER_PROCESSES_NOTE: &str =
    "other processes' command lines are readable under /proc (no PID namespace)";

/// The Linux sockets of a socket hard-deny class (`service-handoff`,
/// `container-engines`), found and covered at spawn. Landlock cannot refuse
/// one Unix socket inside an allowed tree, so the backend looks for these at
/// cage creation and at each spawn: tier T1 covers what it finds, tier T2
/// reports a gap.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SocketPaths {
    /// The class.
    pub class: HardDenyClass,
    /// Socket paths.
    pub system: Vec<AbsPath>,
    /// Directories the class owns as a whole (covered entirely on T1, so
    /// sockets bound in them later stay out of reach).
    pub system_dirs: Vec<AbsPath>,
    /// Socket paths relative to each runtime directory (`/run/user/<uid>`,
    /// `XDG_RUNTIME_DIR`).
    pub runtime: Vec<String>,
    /// Directories relative to each runtime directory that the class owns.
    pub runtime_dirs: Vec<String>,
    /// Prefixes of abstract socket names (without the leading NUL).
    pub abstract_prefixes: Vec<String>,
}

/// Whether some path matching `pattern` (absolute; `*` is one component,
/// `**` any number) equals, contains or lies inside `path`. Components with
/// other wildcard characters match any one component, which can only
/// over-report.
pub fn may_overlap(pattern: &str, path: &[u8]) -> bool {
    fn go(pat: &[&[u8]], path: &[&[u8]]) -> bool {
        match (pat.first(), path.first()) {
            // One side is a prefix of the other.
            (None, _) | (_, None) => true,
            (Some(&b"**"), _) => go(&pat[1..], path) || go(pat, &path[1..]),
            (Some(p), Some(c)) => {
                let wild = p.iter().any(|b| b"*?[{".contains(b));
                (wild || p == c) && go(&pat[1..], &path[1..])
            }
        }
    }
    fn split(s: &[u8]) -> Vec<&[u8]> {
        s.split(|&b| b == b'/').filter(|c| !c.is_empty()).collect()
    }
    go(&split(pattern.as_bytes()), &split(path))
}

/// The namespaces of a T1 child.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Namespaces {
    /// User namespace.
    pub user: bool,
    /// Mount namespace.
    pub mount: bool,
    /// Network namespace.
    pub net: bool,
    /// PID namespace.
    pub pid: bool,
    /// IPC namespace.
    pub ipc: bool,
    /// UTS namespace.
    pub uts: bool,
}

/// What a Landlock path rule applies to.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RuleTarget {
    /// A path known when the policy was lowered.
    Path(AbsPath),
    /// A system path that the backend skips when it does not exist on the
    /// host (for example `/lib64`).
    PathIfExists(AbsPath),
    /// The path bound to this grant at spawn.
    Grant(GrantName),
    /// Every path the glob matches at spawn (an approximation: later files
    /// are not covered).
    ExpandGlob(Glob),
    /// The program of this spawn, as `execvp` finds it, and the ELF
    /// interpreter the kernel loads for it ([`Exec::Never`](crate::Exec::Never)
    /// and [`Exec::Program`](crate::Exec::Program)).
    Program,
}

/// A Landlock path-beneath rule.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LandlockRule {
    /// What it applies to.
    pub target: RuleTarget,
    /// The rights granted.
    pub access: AccessFs,
}

/// A Landlock network port rule.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NetRule {
    /// The port.
    pub port: Port,
    /// The rights granted.
    pub access: AccessNet,
}

/// The Landlock part of a plan.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
pub struct Landlock {
    /// Filesystem rights that are denied unless a rule grants them.
    pub handled_fs: AccessFs,
    /// Network rights that are denied unless a rule grants them.
    pub handled_net: AccessNet,
    /// Scopes that are restricted.
    pub scopes: Scopes,
    /// Path rules.
    pub rules: Vec<LandlockRule>,
    /// Port rules.
    pub net_rules: Vec<NetRule>,
}

/// How the child reaches the network.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum LinuxNetwork {
    /// No network namespace: the host's interfaces, restricted by seccomp and
    /// Landlock as the plan says.
    NoNamespace,
    /// A network namespace with nothing reachable.
    Isolated,
    /// A network namespace bridged to proxy ports on the host's loopback.
    ProxyBridge {
        /// The proxy ports.
        ports: Vec<Port>,
    },
    /// A network namespace whose loopback ports are relayed to the host's
    /// (an approximation of loopback access).
    LoopbackRelay {
        /// The relayed ports.
        ports: Ports,
    },
}

/// The plan for a Linux child.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxPlan {
    /// The tier the plan is for.
    pub tier: Tier,
    /// The Landlock ABI the plan is for.
    pub landlock_abi: u8,
    /// Namespaces to create (T1 only).
    pub namespaces: Option<Namespaces>,
    /// Mounts to set up before Landlock (T1 only).
    pub mounts: Vec<Mount>,
    /// The Landlock ruleset.
    pub landlock: Landlock,
    /// seccomp denies.
    pub seccomp: Vec<SeccompRule>,
    /// How the child reaches the network.
    pub network: LinuxNetwork,
    /// Set `no_new_privs` before applying (always true).
    pub no_new_privs: bool,
    /// Mask the listening Unix sockets outside `unix_socket_paths` at spawn
    /// (tier T1 below ABI 9).
    pub mask_unix_sockets: bool,
    /// The paths of `ipc.unix_sockets`, for the masks.
    pub unix_socket_paths: Vec<AbsPath>,
    /// Paths hidden by allowing their siblings as listed at spawn
    /// (approximation for hide on T2).
    pub hide_by_siblings: Vec<AbsPath>,
    /// Allowed approximations.
    pub degradations: Vec<Degradation>,
    /// Hard-deny classes the policy waived.
    pub waivers: Vec<HardDenyClass>,
    /// The data-driven hard-deny classes in force (not waived), whose paths
    /// the backend handles at spawn.
    pub classes: Vec<ClassPaths>,
    /// The socket hard-deny classes in force that the policy can reach (the
    /// network is `Network::All`, or `ipc.unix_sockets` is set), found and handled by
    /// the backend at cage creation and at each spawn.
    pub service_sockets: Vec<SocketPaths>,
    /// Environment, limits and terminal, unchanged from the policy.
    pub hygiene: Hygiene,
}

/// Raw Linux additions to a policy.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(deny_unknown_fields)
)]
pub struct Layer {
    /// Syscalls denied with `EPERM`.
    pub syscalls_deny: Vec<Syscall>,
    /// Extra Landlock path rules (read, write or exec).
    pub landlock_extra: Vec<(AbsPath, Access)>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rights_per_abi() {
        assert_eq!(handled_fs(0), AccessFs::NONE);
        assert!(!handled_fs(1).contains(AccessFs::REFER));
        assert!(handled_fs(2).contains(AccessFs::REFER));
        assert!(handled_fs(3).contains(AccessFs::TRUNCATE));
        assert!(!handled_fs(4).contains(AccessFs::IOCTL_DEV));
        assert!(handled_fs(5).contains(AccessFs::IOCTL_DEV));
        assert!(!handled_fs(8).contains(AccessFs::RESOLVE_UNIX));
        assert!(handled_fs(9).contains(AccessFs::RESOLVE_UNIX));
        assert_eq!(handled_fs(200), handled_fs(NEWEST_KNOWN_ABI));
        assert_eq!(handled_net(3), AccessNet::NONE);
        assert_eq!(handled_net(4).0, 0b11);
        assert_eq!(handled_net(10).0, 0b1111);
        assert_eq!(scopes(5), Scopes::NONE);
        assert_eq!(scopes(6).0, 0b11);
    }

    #[test]
    fn what_reaches_other_processes() {
        for p in [
            "/",
            "/proc",
            "/proc/1",
            "/proc/1/cmdline",
            "/proc/sys",
            "/proc/selfish",
        ] {
            assert!(reaches_other_processes(p.as_bytes()), "{p}");
        }
        for p in [
            "/proc/self",
            "/proc/self/environ",
            "/proc/thread-self",
            "/proc/thread-self/fd",
            "/home",
            "/procfs",
            "/tmp/proc",
        ] {
            assert!(!reaches_other_processes(p.as_bytes()), "{p}");
        }
    }

    #[test]
    fn refer_comes_only_with_write() {
        for access in [Access::Read, Access::Exec, Access::Protect, Access::Hide] {
            assert!(!rights(access, handled_fs(12)).contains(AccessFs::REFER));
        }
        assert!(rights(Access::Write, handled_fs(2)).contains(AccessFs::REFER));
        assert!(!rights(Access::Write, handled_fs(1)).contains(AccessFs::REFER));
        assert!(!rights(Access::Write, handled_fs(2)).contains(AccessFs::TRUNCATE));
    }

    #[test]
    fn overlap() {
        assert!(may_overlap("/home/*/.ssh", b"/"));
        assert!(may_overlap("/home/*/.ssh", b"/home"));
        assert!(may_overlap("/home/*/.ssh", b"/home/u"));
        assert!(may_overlap("/home/*/.ssh", b"/home/u/.ssh/id"));
        assert!(!may_overlap("/home/*/.ssh", b"/home/u/ws"));
        assert!(!may_overlap("/home/*/.ssh", b"/usr"));
        assert!(may_overlap("/**/.git/hooks", b"/srv/ws"));
        assert!(may_overlap("/root/.aws", b"/root"));
        assert!(!may_overlap("/etc/cron.d", b"/etc/ssl"));
        assert!(may_overlap("/etc/cron.d", b"/etc"));
    }

    #[test]
    fn syscall_names() {
        assert_eq!(
            Syscall::from_name("io_uring_setup").unwrap(),
            Syscall::IoUringSetup
        );
        assert_eq!(Syscall::from_name("acct").unwrap().as_str(), "acct");
        assert!(Syscall::from_name("a b").is_err());
    }
}
