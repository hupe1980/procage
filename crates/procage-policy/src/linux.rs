//! The Linux side: the typed Linux layer and the plan a Linux lowering
//! produces.
//!
//! A [`LinuxPlan`] states what the spawn backend is to set up: namespaces and
//! mounts (tier T1), Landlock rights for the given ABI, seccomp denies by
//! syscall name, and the network mode. It is data. Building BPF for an
//! architecture, opening rule file descriptors and applying anything happen
//! in `procage`.

use alloc::vec::Vec;
use core::fmt;

use crate::glob::Glob;
use crate::lower::{Degradation, Hygiene, Tier};
use crate::name::{GrantName, Port, SyscallName};
use crate::path::AbsPath;
use crate::policy::{Access, HardDenyClass, Ports};

/// The newest Landlock ABI this crate knows. A higher ABI is treated as this
/// one: no later right is assumed.
pub const NEWEST_KNOWN_ABI: u8 = 12;

/// Landlock filesystem rights.
///
/// Bit positions follow the kernel's uapi for the rights of ABI 1 to 5.
/// `RESOLVE_UNIX` (ABI 9) uses this crate's own position until the Linux
/// backend maps it.
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
    /// Create a unix socket file.
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
    /// Connect to a pathname unix socket (ABI 9).
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
    /// Abstract unix sockets outside the domain.
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
/// `REFER` is never part of it.
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
            .union(AccessFs::TRUNCATE),
        Access::Protect | Access::Hide => AccessFs::NONE,
    };
    rights.intersect(handled).without(AccessFs::REFER)
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
    OpenTree => "open_tree",
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
    Shmat => "shmat",
    Shmctl => "shmctl",
    Shmdt => "shmdt",
    Shmget => "shmget",
    Socket => "socket",
    Tgkill => "tgkill",
    Tkill => "tkill",
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
/// `AF_NETLINK`.
pub const AF_NETLINK: u32 = 16;
/// `AF_VSOCK`.
pub const AF_VSOCK: u32 = 40;
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
}

/// What a seccomp deny returns.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Action {
    /// Fail with `EPERM`.
    Eperm,
    /// Fail with `ENOSYS`, so libc falls back to an older call that can be
    /// filtered (used for `clone3`).
    Enosys,
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
    /// Mask the unix sockets found under granted paths at spawn
    /// (approximation for unix-socket allowlists below ABI 9).
    pub mask_unix_sockets: bool,
    /// Paths hidden by allowing their siblings as listed at spawn
    /// (approximation for hide on T2).
    pub hide_by_siblings: Vec<AbsPath>,
    /// Allowed approximations.
    pub degradations: Vec<Degradation>,
    /// Hard-deny classes the policy waived.
    pub waivers: Vec<HardDenyClass>,
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
    fn refer_is_never_granted() {
        for access in [Access::Read, Access::Write, Access::Exec] {
            assert!(!rights(access, handled_fs(12)).contains(AccessFs::REFER));
        }
        assert!(!rights(Access::Write, handled_fs(2)).contains(AccessFs::TRUNCATE));
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
