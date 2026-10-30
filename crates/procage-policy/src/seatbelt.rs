//! The typed Seatbelt layer: raw rules for macOS, as an opt-in escape hatch.
//!
//! A rule has an effect, one or more operations from a closed list, and typed
//! filters. There is no modifier field, so no value of this layer can produce
//! `(with no-sandbox)`, `(with no-profile)` or any other `(with …)` form;
//! the only modifier procage emits is the run tag on `(deny default)`.
//!
//! When lowered, raw allows land before every deny-within-allow rule and
//! before the hard-deny tier, so a raw allow can never override them.

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

use crate::glob::Glob;
#[cfg(feature = "unstable-operations")]
use crate::name::OperationName;
use crate::name::{GrantName, Name};
use crate::path::AbsPath;
use crate::policy::Ports;

/// Allow or deny.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "kebab-case")
)]
pub enum Effect {
    /// `allow`.
    Allow,
    /// `deny`.
    Deny,
}

/// An operation name that is not in the closed list (and, without the
/// feature `unstable-operations`, any name that is not).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnknownOperation(pub String);

impl fmt::Display for UnknownOperation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "unknown Seatbelt operation {:?}", self.0)
    }
}

impl core::error::Error for UnknownOperation {}

macro_rules! operations {
    ($($variant:ident => $name:literal,)*) => {
        /// A Seatbelt operation.
        ///
        /// The stable variants are the 112 names that compiled as
        /// `(allow <name>)` under `(deny default)` with libsandbox on macOS
        /// 26.6.2. `default` is not among them: a policy cannot allow by
        /// default.
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
        #[cfg_attr(
            feature = "serde",
            derive(serde::Serialize, serde::Deserialize),
            serde(try_from = "String", into = "String")
        )]
        #[non_exhaustive]
        pub enum Operation {
            $(
                #[doc = concat!("`", $name, "`")]
                $variant,
            )*
            /// A name outside the closed list, checked against `[a-z0-9*-]{1,64}`.
            #[cfg(feature = "unstable-operations")]
            Other(OperationName),
        }

        impl Operation {
            /// Every operation of the closed list.
            pub const ALL: &'static [Operation] = &[$(Operation::$variant),*];

            /// The SBPL name.
            pub fn as_str(&self) -> &str {
                match self {
                    $(Operation::$variant => $name,)*
                    #[cfg(feature = "unstable-operations")]
                    Operation::Other(name) => name.as_str(),
                }
            }

            /// The operation with this name. Names outside the closed list are
            /// accepted only with the feature `unstable-operations`.
            pub fn from_name(name: &str) -> Result<Operation, UnknownOperation> {
                match name {
                    $($name => Ok(Operation::$variant),)*
                    #[cfg(feature = "unstable-operations")]
                    other => OperationName::new(other)
                        .map(Operation::Other)
                        .map_err(|_| UnknownOperation(other.into())),
                    #[cfg(not(feature = "unstable-operations"))]
                    other => Err(UnknownOperation(other.into())),
                }
            }
        }
    };
}

operations! {
    FileAll => "file*",
    FileReadAll => "file-read*",
    FileReadData => "file-read-data",
    FileReadMetadata => "file-read-metadata",
    FileReadXattr => "file-read-xattr",
    FileWriteAll => "file-write*",
    FileWriteCreate => "file-write-create",
    FileWriteData => "file-write-data",
    FileWriteUnlink => "file-write-unlink",
    FileWriteMode => "file-write-mode",
    FileWriteOwner => "file-write-owner",
    FileWriteFlags => "file-write-flags",
    FileWriteTimes => "file-write-times",
    FileWriteXattr => "file-write-xattr",
    FileWriteAcl => "file-write-acl",
    FileWriteSetugid => "file-write-setugid",
    FileWriteFinderinfo => "file-write-finderinfo",
    FileIoctl => "file-ioctl",
    FileLink => "file-link",
    FileLock => "file-lock",
    FileMapExecutable => "file-map-executable",
    FileMknod => "file-mknod",
    FileMount => "file-mount",
    FileUnmount => "file-unmount",
    FileClone => "file-clone",
    FileSearch => "file-search",
    FileTestExistence => "file-test-existence",
    FileIssueExtension => "file-issue-extension",
    FileChroot => "file-chroot",
    FileRevoke => "file-revoke",
    FsRename => "fs-rename",
    NetworkAll => "network*",
    NetworkOutbound => "network-outbound",
    NetworkInbound => "network-inbound",
    NetworkBind => "network-bind",
    SystemSocket => "system-socket",
    SocketIoctl => "socket-ioctl",
    MachAll => "mach*",
    MachLookup => "mach-lookup",
    MachRegister => "mach-register",
    MachBootstrap => "mach-bootstrap",
    MachCrossDomainLookup => "mach-cross-domain-lookup",
    MachPrivHostPort => "mach-priv-host-port",
    MachPrivTaskPort => "mach-priv-task-port",
    MachTaskName => "mach-task-name",
    MachTaskInspect => "mach-task-inspect",
    MachTaskRead => "mach-task-read",
    MachIssueExtension => "mach-issue-extension",
    ProcessAll => "process*",
    ProcessExecAll => "process-exec*",
    ProcessExec => "process-exec",
    ProcessExecInterpreter => "process-exec-interpreter",
    ProcessFork => "process-fork",
    ProcessInfoAll => "process-info*",
    ProcessInfoListpids => "process-info-listpids",
    ProcessInfoPidinfo => "process-info-pidinfo",
    ProcessInfoPidfdinfo => "process-info-pidfdinfo",
    ProcessInfoRusage => "process-info-rusage",
    ProcessInfoCodesignature => "process-info-codesignature",
    ProcessInfoSetcontrol => "process-info-setcontrol",
    ProcessCodesigningAll => "process-codesigning*",
    Signal => "signal",
    IokitAll => "iokit*",
    IokitOpen => "iokit-open",
    IokitOpenUserClient => "iokit-open-user-client",
    IokitOpenService => "iokit-open-service",
    IokitGetProperties => "iokit-get-properties",
    IokitSetProperties => "iokit-set-properties",
    IpcAll => "ipc*",
    IpcPosixAll => "ipc-posix*",
    IpcPosixShmAll => "ipc-posix-shm*",
    IpcPosixShmReadData => "ipc-posix-shm-read-data",
    IpcPosixShmReadMetadata => "ipc-posix-shm-read-metadata",
    IpcPosixShmWriteCreate => "ipc-posix-shm-write-create",
    IpcPosixShmWriteData => "ipc-posix-shm-write-data",
    IpcPosixShmWriteUnlink => "ipc-posix-shm-write-unlink",
    IpcPosixSemAll => "ipc-posix-sem*",
    IpcSysvAll => "ipc-sysv*",
    IpcSysvMsg => "ipc-sysv-msg",
    IpcSysvSem => "ipc-sysv-sem",
    IpcSysvShm => "ipc-sysv-shm",
    SysctlAll => "sysctl*",
    SysctlRead => "sysctl-read",
    SysctlWrite => "sysctl-write",
    NvramAll => "nvram*",
    UserPreferenceAll => "user-preference*",
    UserPreferenceRead => "user-preference-read",
    UserPreferenceWrite => "user-preference-write",
    ManagedPreferenceRead => "managed-preference-read",
    AppleeventSend => "appleevent-send",
    Lsopen => "lsopen",
    DarwinNotificationPost => "darwin-notification-post",
    DistributedNotificationPost => "distributed-notification-post",
    PseudoTty => "pseudo-tty",
    HidControl => "hid-control",
    DeviceCamera => "device-camera",
    DeviceMicrophone => "device-microphone",
    DynamicCodeGeneration => "dynamic-code-generation",
    LoadUnsignedCode => "load-unsigned-code",
    SystemAll => "system*",
    SystemFsctl => "system-fsctl",
    SystemFcntl => "system-fcntl",
    SystemInfo => "system-info",
    SystemPrivilege => "system-privilege",
    SystemMacSyscall => "system-mac-syscall",
    SystemSched => "system-sched",
    SystemSetTime => "system-set-time",
    SystemAudit => "system-audit",
    SystemReboot => "system-reboot",
    SystemKextAll => "system-kext*",
    JobCreation => "job-creation",
    QtnUser => "qtn-user",
}

impl TryFrom<String> for Operation {
    type Error = UnknownOperation;

    fn try_from(name: String) -> Result<Self, UnknownOperation> {
        Operation::from_name(&name)
    }
}

impl From<Operation> for String {
    fn from(op: Operation) -> String {
        op.as_str().into()
    }
}

impl fmt::Display for Operation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A typed filter of a raw rule.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "kebab-case")
)]
pub enum Filter {
    /// `(literal "…")`: this exact path.
    Literal(AbsPath),
    /// `(subpath "…")`: this path and everything below it.
    Subpath(AbsPath),
    /// `(regex "…")` compiled from a glob.
    Glob(Glob),
    /// `(extension "procage.<name>")`: a per-spawn grant.
    Extension(GrantName),
    /// `(global-name "…")`: a Mach service.
    GlobalName(Name),
    /// `(global-name-prefix "…")`.
    GlobalNamePrefix(Name),
    /// `(target self)`.
    TargetSelf,
    /// `(target children)`.
    TargetChildren,
    /// `(target others)`.
    TargetOthers,
    /// `(remote ip "localhost:…")`.
    RemoteLoopback(Ports),
    /// `(local ip "localhost:…")`.
    LocalLoopback(Ports),
    /// `(remote unix-socket (path-literal "…"))`.
    UnixSocket(AbsPath),
}

/// A raw Seatbelt rule.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(deny_unknown_fields)
)]
pub struct Rule {
    /// Allow or deny.
    pub effect: Effect,
    /// One or more operations.
    pub ops: Vec<Operation>,
    /// Alternative filters; empty means every request of the operations.
    pub filters: Vec<Filter>,
}

/// Raw Seatbelt rules added to a policy.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(deny_unknown_fields)
)]
pub struct Layer {
    /// The rules, in any order.
    pub rules: Vec<Rule>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn closed_list() {
        assert_eq!(Operation::ALL.len(), 112);
        for op in Operation::ALL {
            assert_eq!(Operation::from_name(op.as_str()).unwrap(), *op);
        }
        assert!(Operation::from_name("default").is_err());
    }

    #[cfg(not(feature = "unstable-operations"))]
    #[test]
    fn other_names_need_the_feature() {
        assert!(Operation::from_name("file-read-future").is_err());
        assert!(Operation::from_name("mach-message-send").is_err());
    }

    #[cfg(feature = "unstable-operations")]
    #[test]
    fn other_names_are_checked() {
        assert!(Operation::from_name("file-read-future").is_ok());
        assert!(Operation::from_name("x) (with no-sandbox").is_err());
    }
}
