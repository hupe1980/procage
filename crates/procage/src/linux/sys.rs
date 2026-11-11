//! The Linux system interface: the only module of procage on Linux allowed
//! to use `unsafe`. Every unsafe block states why it is sound.
//!
//! Landlock and seccomp are called through `syscall(2)`; the parent builds
//! the ruleset and the filter. [`ChildPlan::run`] is the sequence between
//! `fork` and `execve`: system calls only, on data the parent allocated.

#![allow(unsafe_code)]

use std::ffi::{CStr, CString, c_int, c_long, c_ulong};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

use super::seccomp::Insn;

pub(crate) fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

fn check(rc: c_long) -> Result<c_long, i32> {
    if rc < 0 { Err(errno()) } else { Ok(rc) }
}

fn check_int(rc: c_int) -> Result<(), i32> {
    if rc < 0 { Err(errno()) } else { Ok(()) }
}

// ---------------------------------------------------------------- Landlock

/// `struct landlock_ruleset_attr` (ABI 6 layout; older kernels accept it as
/// long as the fields they do not know are zero).
#[repr(C)]
struct RulesetAttr {
    handled_access_fs: u64,
    handled_access_net: u64,
    scoped: u64,
}

/// `struct landlock_path_beneath_attr`, packed as in the kernel's UAPI.
#[repr(C, packed)]
struct PathBeneathAttr {
    allowed_access: u64,
    parent_fd: i32,
}

/// `struct landlock_net_port_attr`.
#[repr(C)]
struct NetPortAttr {
    allowed_access: u64,
    port: u64,
}

const CREATE_RULESET_VERSION: u32 = 1 << 0;
const CREATE_RULESET_ERRATA: u32 = 1 << 1;
const RULE_PATH_BENEATH: c_int = 1;
const RULE_NET_PORT: c_int = 2;

fn ruleset_query(flag: u32) -> Result<u32, i32> {
    // SAFETY: the documented query form: NULL attr, size 0, one flag.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            std::ptr::null::<u8>(),
            0usize,
            flag,
        )
    };
    check(rc).map(|v| u32::try_from(v).unwrap_or(0))
}

/// The Landlock ABI version, or the errno (`EOPNOTSUPP`, `ENOSYS`).
pub(crate) fn landlock_abi() -> Result<u32, i32> {
    ruleset_query(CREATE_RULESET_VERSION)
}

/// The Landlock errata bitmask (0 where the kernel has no errata query).
pub(crate) fn landlock_errata() -> u32 {
    ruleset_query(CREATE_RULESET_ERRATA).unwrap_or(0)
}

/// A new ruleset.
pub(crate) fn landlock_ruleset(fs: u64, net: u64, scoped: u64) -> Result<OwnedFd, i32> {
    let attr = RulesetAttr {
        handled_access_fs: fs,
        handled_access_net: net,
        scoped,
    };
    // SAFETY: attr is a valid struct of the stated size.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            &raw const attr,
            std::mem::size_of::<RulesetAttr>(),
            0u32,
        )
    };
    let fd = c_int::try_from(check(rc)?).map_err(|_| libc::EBADF)?;
    // SAFETY: a non-negative return is a new descriptor we own.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// Allows `access` beneath the file `parent` in `ruleset`.
pub(crate) fn landlock_allow_path(
    ruleset: &OwnedFd,
    parent: &OwnedFd,
    access: u64,
) -> Result<(), i32> {
    let attr = PathBeneathAttr {
        allowed_access: access,
        parent_fd: parent.as_raw_fd(),
    };
    // SAFETY: attr is a valid packed struct; both descriptors are open.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_landlock_add_rule,
            ruleset.as_raw_fd(),
            RULE_PATH_BENEATH,
            &raw const attr,
            0u32,
        )
    };
    check(rc).map(drop)
}

/// Allows `access` on TCP/UDP `port` in `ruleset`.
pub(crate) fn landlock_allow_port(ruleset: &OwnedFd, port: u16, access: u64) -> Result<(), i32> {
    let attr = NetPortAttr {
        allowed_access: access,
        port: u64::from(port),
    };
    // SAFETY: attr is a valid struct; the descriptor is open.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_landlock_add_rule,
            ruleset.as_raw_fd(),
            RULE_NET_PORT,
            &raw const attr,
            0u32,
        )
    };
    check(rc).map(drop)
}

/// Opens `path` with `O_PATH` (no access to its content) and says whether it
/// is a directory.
pub(crate) fn open_path(path: &CStr) -> Result<(OwnedFd, bool), i32> {
    // SAFETY: a NUL-terminated path; the descriptor is owned immediately.
    let fd = unsafe { libc::open(path.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
    if fd < 0 {
        return Err(errno());
    }
    // SAFETY: fd is a fresh descriptor we own.
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    // SAFETY: fstat fills a zeroed struct on our stack.
    let st = unsafe {
        let mut st: libc::stat = std::mem::zeroed();
        if libc::fstat(fd.as_raw_fd(), &raw mut st) != 0 {
            return Err(errno());
        }
        st
    };
    Ok((fd, st.st_mode & libc::S_IFMT == libc::S_IFDIR))
}

/// The device and inode of a planned mount path, taken with `lstat` in the
/// parent: the child mounts only on the object it planned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Identity {
    pub(crate) dev: u64,
    pub(crate) ino: u64,
}

/// `path` held as an `O_PATH` descriptor, without following a final link.
pub(crate) fn hold(path: &CStr) -> Result<OwnedFd, i32> {
    // SAFETY: open with a NUL-terminated path; the descriptor is ours.
    let fd = unsafe {
        libc::open(
            path.as_ptr(),
            libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(errno());
    }
    // SAFETY: a fresh descriptor we own.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// The identity of the object `fd` holds.
pub(crate) fn identity_of(fd: &OwnedFd) -> Result<Identity, i32> {
    // SAFETY: fstat on a descriptor we hold, into a zeroed struct.
    let st = unsafe {
        let mut st: libc::stat = std::mem::zeroed();
        if libc::fstat(fd.as_raw_fd(), &raw mut st) != 0 {
            return Err(errno());
        }
        st
    };
    Ok(Identity {
        dev: st.st_dev as u64,
        ino: st.st_ino as u64,
    })
}

/// The identity of `path` without following a final link.
pub(crate) fn identity(path: &CStr) -> Result<Identity, i32> {
    // SAFETY: lstat fills a zeroed struct on our stack.
    let st = unsafe {
        let mut st: libc::stat = std::mem::zeroed();
        if libc::lstat(path.as_ptr(), &raw mut st) != 0 {
            return Err(errno());
        }
        st
    };
    Ok(Identity {
        dev: st.st_dev as u64,
        ino: st.st_ino as u64,
    })
}

/// The real uid and gid.
pub(crate) fn ids() -> (u32, u32) {
    // SAFETY: no arguments, cannot fail.
    unsafe { (libc::getuid(), libc::getgid()) }
}

/// How many threads the calling process has (entries of `/proc/self/task`;
/// 0 when it cannot be read).
pub(crate) fn thread_count() -> usize {
    std::fs::read_dir("/proc/self/task").map_or(0, Iterator::count)
}

/// The calling process's id.
pub(crate) fn pid() -> libc::pid_t {
    // SAFETY: no arguments, cannot fail.
    unsafe { libc::getpid() }
}

/// The parent's process id.
pub(crate) fn parent_pid() -> libc::pid_t {
    // SAFETY: no arguments, cannot fail.
    unsafe { libc::getppid() }
}

// ------------------------------------------------------- the child sequence

/// Step numbers, as encoded in a step code.
pub(crate) mod steps {
    pub(crate) const SESSION: u32 = 1;
    pub(crate) const LIFETIME: u32 = 2;
    pub(crate) const NAMESPACES: u32 = 3;
    pub(crate) const ID_MAP: u32 = 4;
    pub(crate) const MOUNTS: u32 = 5;
    pub(crate) const CAPABILITIES: u32 = 6;
    pub(crate) const RLIMIT: u32 = 7;
    pub(crate) const FDS: u32 = 8;
    pub(crate) const NO_NEW_PRIVS: u32 = 9;
    pub(crate) const LANDLOCK: u32 = 10;
    pub(crate) const SECCOMP: u32 = 11;
    pub(crate) const VERIFY: u32 = 12;
    pub(crate) const LISTENER: u32 = 13;
}

const STEP_MARKER: i32 = 0x5043_0000;

/// Encodes a failed step as the errno `pre_exec` returns.
pub(crate) const fn step_code(step: u32, errno: i32) -> i32 {
    STEP_MARKER | ((step as i32 & 0xf) << 12) | (errno & 0xfff)
}

/// Decodes a step code: `(step, errno)`.
pub(crate) fn decode_step(code: i32) -> Option<(u32, i32)> {
    ((code as u32 & 0xffff_0000) == STEP_MARKER as u32)
        .then_some((((code >> 12) & 0xf) as u32, code & 0xfff))
}

/// A mount the child makes on tier T1. The child resolves every path
/// without following links, checks it is the planned object and mounts on
/// that descriptor, with the mount's flags set before it is attached.
#[derive(Debug)]
pub(crate) enum ChildMount {
    /// A clone of `source`'s tree with its submounts (a user namespace may
    /// clone no less), attached over `target`.
    Bind {
        source: CString,
        source_id: Identity,
        target: CString,
        target_id: Identity,
        /// `MOUNT_ATTR_*` flags set on the clone.
        attrs: u64,
        /// Skipped when the target no longer exists (see
        /// [`ChildMount::Tmpfs`]).
        optional: Option<OwnedFd>,
    },
    /// A new tmpfs with `mode` over `target`.
    Tmpfs {
        target: CString,
        target_id: Identity,
        attrs: u64,
        mode: CString,
        /// A cover made from the file system at spawn (a class name, a
        /// foreign socket) holds its object here (`O_PATH`), and is skipped
        /// when the object was removed before the child mounts: nothing is
        /// left to cover. An object still linked elsewhere was moved, which
        /// fails the spawn.
        optional: Option<OwnedFd>,
    },
}

impl ChildMount {
    fn optional(&self) -> Option<&OwnedFd> {
        match self {
            ChildMount::Bind { optional, .. } | ChildMount::Tmpfs { optional, .. } => {
                optional.as_ref()
            }
        }
    }

    /// Whether an optional cover's object has no name left (it was
    /// removed, not moved).
    pub(crate) fn removed(&self) -> bool {
        self.optional().is_some_and(|held| {
            // SAFETY: fstat on a descriptor we hold, into a zeroed struct.
            unsafe {
                let mut st: libc::stat = std::mem::zeroed();
                libc::fstat(held.as_raw_fd(), &raw mut st) == 0 && st.st_nlink == 0
            }
        })
    }

    /// The planned paths with their identities: the target, then a source
    /// that differs from it.
    pub(crate) fn planned(&self) -> Vec<(&CStr, Identity)> {
        match self {
            ChildMount::Bind {
                source,
                source_id,
                target,
                target_id,
                ..
            } => {
                let mut out = vec![(target.as_c_str(), *target_id)];
                if source != target {
                    out.push((source.as_c_str(), *source_id));
                }
                out
            }
            ChildMount::Tmpfs {
                target, target_id, ..
            } => vec![(target.as_c_str(), *target_id)],
        }
    }
}

pub(crate) const MOUNT_ATTR_RDONLY: u64 = 0x1;
pub(crate) const MOUNT_ATTR_NOSUID: u64 = 0x2;
pub(crate) const MOUNT_ATTR_NODEV: u64 = 0x4;
pub(crate) const MOUNT_ATTR_NOEXEC: u64 = 0x8;
const OPEN_TREE_CLONE: u64 = 0x1;
const MOVE_MOUNT_F_EMPTY_PATH: u64 = 0x4;
const MOVE_MOUNT_T_EMPTY_PATH: u64 = 0x40;
const FSOPEN_CLOEXEC: u64 = 0x1;
const FSMOUNT_CLOEXEC: u64 = 0x1;
const FSCONFIG_SET_STRING: u64 = 1;
const FSCONFIG_CMD_CREATE: u64 = 6;
const RESOLVE_NO_SYMLINKS: u64 = 0x4;

/// `struct open_how`.
#[repr(C)]
struct OpenHow {
    flags: u64,
    mode: u64,
    resolve: u64,
}

/// `struct mount_attr`.
#[repr(C)]
struct MountAttr {
    attr_set: u64,
    attr_clr: u64,
    propagation: u64,
    userns_fd: u64,
}

/// A descriptor the mount sequence closes when it is done with it.
struct Fd(c_int);

impl Drop for Fd {
    fn drop(&mut self) {
        // SAFETY: closing a descriptor this sequence opened.
        unsafe { libc::close(self.0) };
    }
}

fn syscall_fd(rc: c_long) -> Result<Fd, i32> {
    if rc < 0 {
        Err(errno())
    } else {
        Ok(Fd(rc as c_int))
    }
}

/// `path` as an `O_PATH` descriptor, resolved without following a link in
/// any component (`ELOOP` otherwise), that must be the object `id`
/// (`ESTALE` otherwise).
fn open_planned(path: &CStr, id: Identity) -> Result<Fd, i32> {
    let how = OpenHow {
        flags: (libc::O_PATH | libc::O_CLOEXEC) as u64,
        mode: 0,
        resolve: RESOLVE_NO_SYMLINKS,
    };
    // SAFETY: openat2 with a NUL-terminated path and a struct on our stack.
    let fd = syscall_fd(unsafe {
        libc::syscall(
            libc::SYS_openat2,
            libc::AT_FDCWD,
            path.as_ptr(),
            &raw const how,
            std::mem::size_of::<OpenHow>(),
        )
    })?;
    // SAFETY: fstat fills a zeroed struct on our stack.
    let st = unsafe {
        let mut st: libc::stat = std::mem::zeroed();
        if libc::fstat(fd.0, &raw mut st) != 0 {
            return Err(errno());
        }
        st
    };
    if st.st_dev as u64 != id.dev || st.st_ino as u64 != id.ino {
        return Err(libc::ESTALE);
    }
    Ok(fd)
}

fn set_attrs(mount: &Fd, attrs: u64) -> Result<(), i32> {
    if attrs == 0 {
        return Ok(());
    }
    let attr = MountAttr {
        attr_set: attrs,
        attr_clr: 0,
        propagation: 0,
        userns_fd: 0,
    };
    let flags = libc::AT_EMPTY_PATH;
    // SAFETY: mount_setattr on a descriptor we own, an empty path and a
    // struct on our stack.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_mount_setattr,
            mount.0,
            c"".as_ptr(),
            flags as c_ulong,
            &raw const attr,
            std::mem::size_of::<MountAttr>(),
        )
    };
    check(rc).map(drop)
}

fn attach(mount: &Fd, target: &Fd) -> Result<(), i32> {
    // SAFETY: move_mount between two descriptors we own, empty paths.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_move_mount,
            mount.0,
            c"".as_ptr(),
            target.0,
            c"".as_ptr(),
            (MOVE_MOUNT_F_EMPTY_PATH | MOVE_MOUNT_T_EMPTY_PATH) as c_ulong,
        )
    };
    check(rc).map(drop)
}

/// A clone of the tree at `source`, its top mount's flags set, attached over
/// `target`.
fn bind_planned(source: &Fd, target: &Fd, attrs: u64) -> Result<(), i32> {
    let flags = OPEN_TREE_CLONE as c_ulong
        | libc::O_CLOEXEC as c_ulong
        | libc::AT_EMPTY_PATH as c_ulong
        | libc::AT_RECURSIVE as c_ulong;
    // SAFETY: open_tree on a descriptor we own and an empty path.
    let rc = unsafe { libc::syscall(libc::SYS_open_tree, source.0, c"".as_ptr(), flags) };
    let tree = syscall_fd(rc)?;
    // The top mount's flags, as a bind remount set them before.
    set_attrs(&tree, attrs)?;
    attach(&tree, target)
}

/// A new tmpfs with `mode` and `attrs`, attached over `target`.
fn tmpfs_planned(target: &Fd, mode: &CStr, attrs: u64) -> Result<(), i32> {
    // SAFETY: fsopen, fsconfig and fsmount on strings with static or
    // parent-allocated storage and descriptors we own.
    unsafe {
        let fs = syscall_fd(libc::syscall(
            libc::SYS_fsopen,
            c"tmpfs".as_ptr(),
            FSOPEN_CLOEXEC as c_ulong,
        ))?;
        check(libc::syscall(
            libc::SYS_fsconfig,
            fs.0,
            FSCONFIG_SET_STRING as c_ulong,
            c"mode".as_ptr(),
            mode.as_ptr(),
            0 as c_int,
        ))?;
        check(libc::syscall(
            libc::SYS_fsconfig,
            fs.0,
            FSCONFIG_CMD_CREATE as c_ulong,
            std::ptr::null::<libc::c_char>(),
            std::ptr::null::<libc::c_char>(),
            0 as c_int,
        ))?;
        let mount = syscall_fd(libc::syscall(
            libc::SYS_fsmount,
            fs.0,
            FSMOUNT_CLOEXEC as c_ulong,
            attrs as c_ulong,
        ))?;
        attach(&mount, target)
    }
}

/// Makes one planned mount.
fn make(m: &ChildMount) -> Result<(), i32> {
    match m {
        ChildMount::Bind {
            source,
            source_id,
            target,
            target_id,
            attrs,
            ..
        } => {
            let target_fd = open_planned(target, *target_id)?;
            if source == target {
                bind_planned(&target_fd, &target_fd, *attrs)
            } else {
                let source_fd = open_planned(source, *source_id)?;
                bind_planned(&source_fd, &target_fd, *attrs)
            }
        }
        ChildMount::Tmpfs {
            target,
            target_id,
            attrs,
            mode,
            ..
        } => tmpfs_planned(&open_planned(target, *target_id)?, mode, *attrs),
    }
}

/// The namespaces and mounts of a T1 child.
#[derive(Debug)]
pub(crate) struct Isolate {
    pub(crate) flags: c_int,
    pub(crate) uid_map: Vec<u8>,
    pub(crate) gid_map: Vec<u8>,
    pub(crate) mounts: std::sync::Arc<[ChildMount]>,
}

/// What the session step does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Session {
    /// `setsid()`: a new session and process group.
    New,
    /// `setpgid(0, 0)`: a new process group in the caller's session.
    Group,
    /// Nothing: the caller's session and process group (`Cage::exec`).
    Keep,
    /// `setsid()` unless the process leads its session already
    /// (`Cage::exec_session`).
    Lead,
    /// `setsid()`, then `ioctl(0, TIOCSCTTY)`: a new session whose
    /// controlling terminal is the one on standard input (`Tty::NewPty`).
    Terminal,
}

impl Session {
    /// Whether the process is a new child (a spawn) rather than the caller
    /// itself (`Cage::exec`, which keeps what `execve` keeps).
    fn fresh(self) -> bool {
        matches!(self, Session::New | Session::Group | Session::Terminal)
    }
}

/// One past the highest signal number (`_NSIG`).
const SIGNALS: c_int = 65;

/// Resets every ignored signal to its default action. An ignored
/// disposition survives `execve`, so a caller that ignores `SIGCHLD` would
/// hand that to the child, whose `wait` then fails with `ECHILD`
/// (bubblewrap 0.11.1 fixed the same for `SIGCHLD`). Caught signals need
/// nothing: `execve` resets them. System calls only.
fn reset_ignored_signals() -> Result<(), i32> {
    for sig in 1..SIGNALS {
        if sig == libc::SIGKILL || sig == libc::SIGSTOP || !signal_ignored(sig) {
            continue;
        }
        // SAFETY: an all-zero sigaction is a valid value to fill in.
        let mut default: libc::sigaction = unsafe { std::mem::zeroed() };
        default.sa_sigaction = libc::SIG_DFL;
        // SAFETY: sigaction reads a struct on our stack.
        let rc = unsafe { libc::sigaction(sig, &raw const default, std::ptr::null_mut()) };
        check_int(rc)?;
    }
    Ok(())
}

/// Whether `sig` is ignored in the calling process. A number the C library
/// reserves for itself (glibc's 32 and 33) reads as not ignored.
pub(crate) fn signal_ignored(sig: c_int) -> bool {
    // SAFETY: an all-zero sigaction is a valid value to fill in.
    let mut old: libc::sigaction = unsafe { std::mem::zeroed() };
    // SAFETY: sigaction writes a struct on our stack.
    let rc = unsafe { libc::sigaction(sig, std::ptr::null(), &raw mut old) };
    rc == 0 && old.sa_sigaction == libc::SIG_IGN
}

/// Everything the child needs between `fork` and `execve`, prepared in the
/// parent.
pub(crate) struct ChildPlan {
    pub(crate) session: Session,
    /// The parent's pid, to detect a parent that died before the death
    /// signal was set.
    pub(crate) parent: libc::pid_t,
    /// T1 only.
    pub(crate) isolate: Option<Isolate>,
    pub(crate) limits: Vec<(c_int, u64, u64)>,
    /// Descriptors above 2 handed to the child, sorted.
    pub(crate) keep: Vec<c_int>,
    pub(crate) ruleset: OwnedFd,
    pub(crate) filter: Vec<Insn>,
    /// With violation reporting: the listener hand-over.
    pub(crate) notify: Option<Notify>,
    /// With a proxy of the cage's own (T1): the listeners to open in the
    /// child's network namespace and hand to the parent.
    pub(crate) bridge: Option<Bridge>,
}

/// The child's side of the proxy listeners: their ports, its end of the
/// socket pair, and a control buffer, all allocated in the parent.
pub(crate) struct Bridge {
    pub(crate) ports: Vec<u16>,
    pub(crate) socket: OwnedFd,
    pub(crate) control: Vec<u8>,
}

impl Bridge {
    /// The hand-over of listeners on `ports`, with the child's end `socket`.
    #[cfg(feature = "proxy")]
    pub(crate) fn new(ports: Vec<u16>, socket: OwnedFd) -> Bridge {
        // SAFETY: CMSG_SPACE only computes a size.
        let space = unsafe { libc::CMSG_SPACE(std::mem::size_of::<c_int>() as u32) } as usize;
        Bridge {
            ports,
            socket,
            control: vec![0; space],
        }
    }

    /// In the child's new network namespace: brings `lo` up, then listens on
    /// `127.0.0.1` at each port and sends each listener to the parent.
    fn open(&mut self) -> Result<(), i32> {
        let datagram = libc::SOCK_DGRAM | libc::SOCK_CLOEXEC;
        // SAFETY: socket with integer arguments.
        let control = unsafe { libc::socket(libc::AF_INET, datagram, 0) };
        if control < 0 {
            return Err(errno());
        }
        // SAFETY: an all-zero ifreq is valid; the name fits.
        let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };
        for (dst, src) in ifr.ifr_name.iter_mut().zip(b"lo") {
            *dst = *src as libc::c_char;
        }
        // SAFETY: SIOCGIFFLAGS and SIOCSIFFLAGS read and write the ifreq on
        // our stack; the flags field is the union member they use.
        let up = unsafe {
            let got = libc::ioctl(control, libc::SIOCGIFFLAGS as _, &raw mut ifr);
            if got == 0 {
                ifr.ifr_ifru.ifru_flags |= libc::IFF_UP as libc::c_short;
                libc::ioctl(control, libc::SIOCSIFFLAGS as _, &raw const ifr)
            } else {
                got
            }
        };
        let up = if up == 0 { Ok(()) } else { Err(errno()) };
        // SAFETY: closing the socket this function created.
        unsafe { libc::close(control) };
        up?;
        for &port in &self.ports {
            let stream = libc::SOCK_STREAM | libc::SOCK_CLOEXEC;
            // SAFETY: socket with integer arguments.
            let l = unsafe { libc::socket(libc::AF_INET, stream, 0) };
            if l < 0 {
                return Err(errno());
            }
            let addr = libc::sockaddr_in {
                sin_family: libc::AF_INET as libc::sa_family_t,
                sin_port: port.to_be(),
                sin_addr: libc::in_addr {
                    s_addr: u32::from(std::net::Ipv4Addr::LOCALHOST).to_be(),
                },
                sin_zero: [0; 8],
            };
            // SAFETY: bind with an IPv4 address of its size, listen with an
            // integer backlog, on the socket just created.
            let rc = unsafe {
                let rc = libc::bind(
                    l,
                    (&raw const addr).cast(),
                    std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
                );
                if rc == 0 { libc::listen(l, 128) } else { rc }
            };
            let sent = if rc == 0 {
                send(self.socket.as_raw_fd(), &[1], Some(l), &mut self.control)
            } else {
                Err(errno())
            };
            // SAFETY: closing the listener this function created; the parent
            // has its own copy.
            unsafe { libc::close(l) };
            sent?;
        }
        Ok(())
    }
}

/// The child's side of violation reporting: the notifying filter, its end
/// of the socket pair, and a control buffer for the listener, all
/// allocated in the parent.
pub(crate) struct Notify {
    pub(crate) filter: Vec<Insn>,
    pub(crate) socket: OwnedFd,
    pub(crate) control: Vec<u8>,
}

impl Notify {
    /// The hand-over for `filter`, with the child's end `socket`.
    pub(crate) fn new(filter: Vec<Insn>, socket: OwnedFd) -> Notify {
        // SAFETY: CMSG_SPACE only computes a size.
        let space = unsafe { libc::CMSG_SPACE(std::mem::size_of::<c_int>() as u32) } as usize;
        Notify {
            filter,
            socket,
            control: vec![0; space],
        }
    }
}

/// `seccomp(SET_MODE_FILTER, flags, filter)`: the listener descriptor with
/// `SECCOMP_FILTER_FLAG_NEW_LISTENER`, else 0.
fn install_filter(filter: &mut [Insn], flags: libc::c_ulong) -> Result<c_int, i32> {
    let prog = libc::sock_fprog {
        len: u16::try_from(filter.len()).map_err(|_| libc::E2BIG)?,
        filter: filter.as_mut_ptr().cast(),
    };
    // SAFETY: `Insn` has the layout of `struct sock_filter` (checked by a
    // test); prog points to the parent's buffer for the whole call.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            libc::SECCOMP_SET_MODE_FILTER,
            flags,
            &raw const prog,
        )
    };
    if rc < 0 {
        Err(errno())
    } else {
        Ok(c_int::try_from(rc).unwrap_or(-1))
    }
}

/// Sends `bytes` on `socket`, with descriptor `fd` attached when given.
/// System calls only; `control` was allocated in the parent.
fn send(socket: c_int, bytes: &[u8], fd: Option<c_int>, control: &mut [u8]) -> Result<(), i32> {
    let mut iov = libc::iovec {
        iov_base: bytes.as_ptr().cast_mut().cast(),
        iov_len: bytes.len(),
    };
    // SAFETY: a zeroed msghdr is a valid empty message.
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &raw mut iov;
    msg.msg_iovlen = 1;
    if let Some(fd) = fd {
        msg.msg_control = control.as_mut_ptr().cast();
        msg.msg_controllen = control.len() as _;
        // SAFETY: the control buffer holds CMSG_SPACE(sizeof(int)) bytes, so
        // the first header and its data fit.
        unsafe {
            let header = libc::CMSG_FIRSTHDR(&raw const msg);
            (*header).cmsg_level = libc::SOL_SOCKET;
            (*header).cmsg_type = libc::SCM_RIGHTS;
            (*header).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<c_int>() as u32) as _;
            std::ptr::write_unaligned(libc::CMSG_DATA(header).cast::<c_int>(), fd);
        }
    }
    // SAFETY: msg and everything it points to live on this frame or in the
    // parent's buffers for the whole call.
    let rc = unsafe { libc::sendmsg(socket, &raw const msg, libc::MSG_NOSIGNAL) };
    if rc < 0 { Err(errno()) } else { Ok(()) }
}

fn write_file(path: &CStr, data: &[u8]) -> Result<(), i32> {
    // SAFETY: open, write and close on a NUL-terminated path and a buffer
    // the parent allocated.
    unsafe {
        let fd = libc::open(path.as_ptr(), libc::O_WRONLY | libc::O_CLOEXEC);
        if fd < 0 {
            return Err(errno());
        }
        let n = libc::write(fd, data.as_ptr().cast(), data.len());
        let e = errno();
        libc::close(fd);
        if usize::try_from(n).ok() != Some(data.len()) {
            return Err(if n < 0 { e } else { libc::EIO });
        }
    }
    Ok(())
}

fn mount(
    source: Option<&CStr>,
    target: &CStr,
    fstype: Option<&CStr>,
    flags: c_ulong,
    data: Option<&CStr>,
) -> Result<(), i32> {
    let p = |c: Option<&CStr>| c.map_or(std::ptr::null(), CStr::as_ptr);
    // SAFETY: every pointer is a NUL-terminated string or NULL.
    let rc = unsafe { libc::mount(p(source), target.as_ptr(), p(fstype), flags, p(data).cast()) };
    check_int(rc)
}

fn prctl(option: c_int, arg: c_ulong) -> Result<c_int, i32> {
    // SAFETY: prctl with integer arguments.
    let rc = unsafe { libc::prctl(option, arg, 0 as c_ulong, 0 as c_ulong, 0 as c_ulong) };
    if rc < 0 { Err(errno()) } else { Ok(rc) }
}

/// `struct __user_cap_header_struct`.
#[repr(C)]
struct CapHeader {
    version: u32,
    pid: c_int,
}

/// `struct __user_cap_data_struct`.
#[repr(C)]
#[derive(Clone, Copy)]
struct CapData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

const CAP_VERSION_3: u32 = 0x2008_0522;

/// Empties the effective, permitted and inheritable sets and the ambient
/// set; with `bounding`, also the bounding set (needs `CAP_SETPCAP`).
fn drop_capabilities(bounding: bool) -> Result<(), i32> {
    if bounding {
        for cap in 0..64 {
            match prctl(libc::PR_CAPBSET_DROP, cap) {
                Ok(_) => {}
                Err(libc::EINVAL) => break,
                Err(e) => return Err(e),
            }
        }
    }
    match prctl(
        libc::PR_CAP_AMBIENT,
        libc::PR_CAP_AMBIENT_CLEAR_ALL as c_ulong,
    ) {
        Ok(_) | Err(libc::EINVAL) => {}
        Err(e) => return Err(e),
    }
    let header = CapHeader {
        version: CAP_VERSION_3,
        pid: 0,
    };
    let data = [CapData {
        effective: 0,
        permitted: 0,
        inheritable: 0,
    }; 2];
    // SAFETY: a version-3 header and two data structs, as capset expects.
    let rc = unsafe { libc::syscall(libc::SYS_capset, &raw const header, data.as_ptr()) };
    check(rc).map(drop)
}

/// The effective, permitted and bounding capability sets of the caller.
pub(crate) fn capabilities() -> (u64, u64, u64) {
    let mut header = CapHeader {
        version: CAP_VERSION_3,
        pid: 0,
    };
    let mut data = [CapData {
        effective: 0,
        permitted: 0,
        inheritable: 0,
    }; 2];
    // SAFETY: a version-3 header and room for two data structs.
    unsafe { libc::syscall(libc::SYS_capget, &raw mut header, data.as_mut_ptr()) };
    let join = |lo: u32, hi: u32| u64::from(lo) | (u64::from(hi) << 32);
    let mut bounding = 0u64;
    for cap in 0..64 {
        match prctl(libc::PR_CAPBSET_READ, cap) {
            Ok(1) => bounding |= 1 << cap,
            Ok(_) => {}
            Err(_) => break,
        }
    }
    (
        join(data[0].effective, data[1].effective),
        join(data[0].permitted, data[1].permitted),
        bounding,
    )
}

/// `close_range(first, last, flags)`.
fn close_range(first: u32, last: u32, flags: u32) -> c_long {
    // SAFETY: a system call with integer arguments.
    unsafe { libc::syscall(libc::SYS_close_range, first, last, flags) }
}

/// Marks every descriptor >= 3 close-on-exec except `keep` (sorted), and
/// clears the flag on `keep`, so they stay open across the exec.
fn mark_fds(keep: &[c_int]) -> Result<(), i32> {
    mark_others(keep)?;
    for &fd in keep {
        // SAFETY: fcntl on an integer descriptor.
        check_int(unsafe { libc::fcntl(fd, libc::F_SETFD, 0) })?;
    }
    Ok(())
}

/// Marks every descriptor >= 3 close-on-exec except `keep`, with
/// `close_range`; where the kernel lacks it, with `fcntl` up to the
/// open-files limit.
fn mark_others(keep: &[c_int]) -> Result<(), i32> {
    const CLOSE_RANGE_CLOEXEC: u32 = 1 << 2;
    let mut first: u32 = 3;
    let mut ranges_ok = true;
    for &fd in keep.iter().chain(std::iter::once(&-1)) {
        let last = if fd < 0 {
            u32::MAX
        } else {
            match u32::try_from(fd) {
                Ok(fd) if fd >= first => fd - 1,
                Ok(fd) => {
                    first = first.max(fd + 1);
                    continue;
                }
                Err(_) => continue,
            }
        };
        if last >= first && close_range(first, last, CLOSE_RANGE_CLOEXEC) != 0 {
            ranges_ok = false;
            break;
        }
        if fd >= 0 {
            first = u32::try_from(fd).unwrap_or(u32::MAX).saturating_add(1);
        }
    }
    if ranges_ok {
        return Ok(());
    }
    #[allow(clippy::unnecessary_cast)]
    let max = getrlimit(libc::RLIMIT_NOFILE as c_int).map_or(1024, |(soft, _)| soft.min(1 << 20));
    for fd in 3..c_int::try_from(max).unwrap_or(c_int::MAX) {
        if keep.contains(&fd) {
            continue;
        }
        // SAFETY: fcntl on an integer descriptor.
        if unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) } != 0 {
            match errno() {
                libc::EBADF => {}
                e => return Err(e),
            }
        }
    }
    Ok(())
}

impl ChildPlan {
    /// The child sequence: system calls only.
    fn run(&mut self) -> std::io::Result<()> {
        let fail =
            |step: u32, errno: i32| std::io::Error::from_raw_os_error(step_code(step, errno));
        if self.session.fresh() {
            reset_ignored_signals().map_err(|e| fail(steps::SESSION, e))?;
        }
        // SAFETY: setsid and setpgid are system calls without pointers.
        let rc = unsafe {
            match self.session {
                Session::New => libc::setsid(),
                Session::Group => libc::setpgid(0, 0),
                Session::Keep => 0,
                Session::Lead if libc::getsid(0) == libc::getpid() => 0,
                Session::Lead | Session::Terminal => libc::setsid(),
            }
        };
        check_int(rc).map_err(|e| fail(steps::SESSION, e))?;
        if self.session == Session::Terminal {
            // The request type is `c_ulong` on glibc and `c_int` on musl.
            #[allow(clippy::useless_conversion, clippy::unnecessary_cast)]
            // SAFETY: TIOCSCTTY takes an integer argument.
            let rc = unsafe { libc::ioctl(0, libc::TIOCSCTTY as _, 0) };
            check_int(rc).map_err(|e| fail(steps::SESSION, e))?;
        }
        let parent = self.parent;
        let death = move || -> std::io::Result<()> {
            prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL as c_ulong)
                .map_err(|e| fail(steps::LIFETIME, e))?;
            // SAFETY: getppid takes no arguments.
            if unsafe { libc::getppid() } != parent {
                return Err(fail(steps::LIFETIME, libc::ESRCH));
            }
            Ok(())
        };
        death()?;
        let t1 = self.isolate.is_some();
        if let Some(iso) = &self.isolate {
            // SAFETY: unshare with integer flags; the child is
            // single-threaded after fork.
            check_int(unsafe { libc::unshare(iso.flags) })
                .map_err(|e| fail(steps::NAMESPACES, e))?;
            write_file(c"/proc/self/setgroups", b"deny")
                .and_then(|()| write_file(c"/proc/self/uid_map", &iso.uid_map))
                .and_then(|()| write_file(c"/proc/self/gid_map", &iso.gid_map))
                .map_err(|e| fail(steps::ID_MAP, e))?;
            mount(None, c"/", None, libc::MS_REC | libc::MS_PRIVATE, None)
                .map_err(|e| fail(steps::MOUNTS, e))?;
            for m in iso.mounts.iter() {
                match make(m) {
                    // A removed cover's name may be gone or taken by
                    // another file or link: nothing is left to cover.
                    Err(libc::ENOENT | libc::ESTALE | libc::ELOOP) if m.removed() => {}
                    Err(libc::ENOENT) if m.optional().is_some() => {
                        return Err(fail(steps::MOUNTS, libc::ESTALE));
                    }
                    r => r.map_err(|e| fail(steps::MOUNTS, e))?,
                }
            }
        }
        // The proxy listeners, while the namespace's capabilities allow
        // bringing up its loopback.
        if let Some(bridge) = &mut self.bridge {
            bridge.open().map_err(|e| fail(steps::LISTENER, e))?;
        }
        drop_capabilities(t1).map_err(|e| fail(steps::CAPABILITIES, e))?;
        // A new user namespace grants capabilities, which clears the death
        // signal; set it again.
        if t1 {
            death()?;
        }
        for &(resource, soft, hard) in &self.limits {
            let limit = libc::rlimit {
                rlim_cur: soft,
                rlim_max: hard,
            };
            #[allow(clippy::useless_conversion, clippy::unnecessary_cast)]
            // SAFETY: setrlimit with a struct on our stack. The resource
            // type is `u32` on glibc and `i32` on musl.
            let rc = unsafe { libc::setrlimit(resource as _, &raw const limit) };
            check_int(rc).map_err(|e| fail(steps::RLIMIT, e))?;
        }
        mark_fds(&self.keep).map_err(|e| fail(steps::FDS, e))?;
        prctl(libc::PR_SET_NO_NEW_PRIVS, 1).map_err(|e| fail(steps::NO_NEW_PRIVS, e))?;
        // SAFETY: landlock_restrict_self with an open ruleset and no flags.
        let rc = unsafe {
            libc::syscall(
                libc::SYS_landlock_restrict_self,
                self.ruleset.as_raw_fd(),
                0u32,
            )
        };
        check(rc).map_err(|e| fail(steps::LANDLOCK, e))?;
        match &mut self.notify {
            // Violation reporting: the filter reports refused calls to a
            // listener, which goes to the parent before the exec; the child
            // keeps no copy. Without a listener (a filter of an outer
            // sandbox already has one), the plain filter, and the reason.
            Some(notify) => {
                let socket = notify.socket.as_raw_fd();
                match install_filter(&mut notify.filter, libc::SECCOMP_FILTER_FLAG_NEW_LISTENER) {
                    Ok(listener) => {
                        let sent = send(socket, &[1], Some(listener), &mut notify.control);
                        // SAFETY: closing the listener this sequence created.
                        unsafe { libc::close(listener) };
                        sent.map_err(|e| fail(steps::LISTENER, e))?;
                    }
                    Err(refused) => {
                        install_filter(&mut self.filter, 0).map_err(|e| fail(steps::SECCOMP, e))?;
                        let mut status = [0u8; 5];
                        status[1..].copy_from_slice(&refused.to_le_bytes());
                        send(socket, &status, None, &mut notify.control)
                            .map_err(|e| fail(steps::LISTENER, e))?;
                    }
                }
            }
            None => {
                install_filter(&mut self.filter, 0).map_err(|e| fail(steps::SECCOMP, e))?;
            }
        }
        let seccomp = prctl(libc::PR_GET_SECCOMP, 0).map_err(|e| fail(steps::VERIFY, e))?;
        let nnp = prctl(libc::PR_GET_NO_NEW_PRIVS, 0).map_err(|e| fail(steps::VERIFY, e))?;
        if seccomp != 2 || nnp != 1 {
            return Err(fail(steps::VERIFY, libc::EPERM));
        }
        Ok(())
    }

    /// Runs the plan in the child of `command`'s spawn.
    pub(crate) fn install(self, command: &mut std::process::Command) {
        use std::os::unix::process::CommandExt;
        let mut plan = self;
        // SAFETY: `run` issues only system calls (sigaction, setsid or setpgid, prctl,
        // getppid, unshare, open/write/close on /proc/self, mount, openat2,
        // fstat, open_tree, mount_setattr, fsopen, fsconfig, fsmount,
        // move_mount and close, with a proxy socket/ioctl/bind/listen/sendmsg/close,
        // capset, setrlimit, close_range or fcntl, getrlimit,
        // landlock_restrict_self, seccomp, and with reporting sendmsg and
        // close). Everything it reads was
        // allocated in the parent and is owned by the closure.
        unsafe {
            command.pre_exec(move || plan.run());
        }
    }
}

// ------------------------------------------------------------------ probe

/// A read-only bind and a tmpfs over `/tmp`, made as the T1 child makes its
/// mounts (by descriptor), succeeded after `unshare` with `flags` and
/// self-mapped ids, in a throwaway child. Returns the errno of the first
/// failure: a host without these calls has no tier T1.
pub(crate) fn probe_userns(flags: c_int) -> Result<(), i32> {
    let (uid, gid) = ids();
    let tmp = identity(c"/tmp")?;
    let uid_map = format!("{uid} {uid} 1\n").into_bytes();
    let gid_map = format!("{gid} {gid} 1\n").into_bytes();
    let mut fds = [0 as c_int; 2];
    // SAFETY: pipe2 fills two descriptors we own.
    check_int(unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) })?;
    // SAFETY: both descriptors are fresh and owned here.
    let (read, write) = unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) };
    // SAFETY: the child runs system calls only on data allocated above and
    // leaves with _exit; the parent waits for it.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(errno());
    }
    if pid == 0 {
        let result = (|| {
            // SAFETY: unshare with integer flags in a single-threaded child.
            check_int(unsafe { libc::unshare(flags) })?;
            write_file(c"/proc/self/setgroups", b"deny")?;
            write_file(c"/proc/self/uid_map", &uid_map)?;
            write_file(c"/proc/self/gid_map", &gid_map)?;
            mount(None, c"/", None, libc::MS_REC | libc::MS_PRIVATE, None)?;
            let target = open_planned(c"/tmp", tmp)?;
            bind_planned(&target, &target, MOUNT_ATTR_RDONLY)?;
            tmpfs_planned(&target, c"0700", 0)
        })();
        let code: i32 = result.err().unwrap_or(0);
        // SAFETY: write four bytes from our stack, then leave without
        // running any destructor.
        unsafe {
            libc::write(write.as_raw_fd(), (&raw const code).cast(), 4);
            libc::_exit(0);
        }
    }
    drop(write);
    let mut code: i32 = libc::EIO;
    // SAFETY: read into a 4-byte integer on our stack; then reap the child.
    unsafe {
        libc::read(read.as_raw_fd(), (&raw mut code).cast(), 4);
        let mut status = 0;
        libc::waitpid(pid, &raw mut status, 0);
    }
    if code == 0 { Ok(()) } else { Err(code) }
}

// ------------------------------------------------------- signals and limits

/// `kill(pid, SIGKILL)`, ignoring errors.
pub(crate) fn kill(pid: libc::pid_t) {
    // SAFETY: a system call with integer arguments.
    unsafe { libc::kill(pid, libc::SIGKILL) };
}

/// Whether this process leads its session, and whether it leads its
/// process group.
pub(crate) fn leads() -> (bool, bool) {
    // SAFETY: system calls without pointers.
    unsafe {
        let pid = libc::getpid();
        (libc::getsid(0) == pid, libc::getpgrp() == pid)
    }
}

/// `killpg(pgid, SIGKILL)`, ignoring errors.
pub(crate) fn killpg(pgid: libc::pid_t) {
    // SAFETY: a system call with integer arguments.
    unsafe { libc::killpg(pgid, libc::SIGKILL) };
}

/// Whether process `pid` exists (signal 0).
pub(crate) fn alive(pid: libc::pid_t) -> bool {
    // SAFETY: kill with signal 0 only checks for existence.
    unsafe { libc::kill(pid, 0) == 0 || errno() == libc::EPERM }
}

/// The soft and hard limits of `resource`.
#[allow(clippy::useless_conversion, clippy::unnecessary_cast)]
pub(crate) fn getrlimit(resource: c_int) -> Option<(u64, u64)> {
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: getrlimit fills a struct on our stack.
    (unsafe { libc::getrlimit(resource as _, &raw mut limit) } == 0)
        .then_some((limit.rlim_cur, limit.rlim_max))
}

/// Whether `fd` is open.
pub(crate) fn fd_is_open(fd: c_int) -> bool {
    // SAFETY: fcntl F_GETFD on an integer descriptor.
    unsafe { libc::fcntl(fd, libc::F_GETFD) != -1 }
}

/// Clears close-on-exec on `fd`.
pub(crate) fn clear_cloexec(fd: c_int) -> Result<(), i32> {
    // SAFETY: fcntl on an integer descriptor.
    check_int(unsafe { libc::fcntl(fd, libc::F_SETFD, 0) })
}

/// Whether the caller leads its session and its process group.
pub(crate) fn leadership() -> (bool, bool) {
    // SAFETY: getsid, getpgrp and getpid take no pointers.
    unsafe {
        let me = libc::getpid();
        (libc::getsid(0) == me, libc::getpgrp() == me)
    }
}

/// The errno of a raw system call (0 on success).
pub(crate) fn syscall_errno(nr: c_long, args: [c_long; 5]) -> i32 {
    // SAFETY: only used by procage's tests, with arguments that make the
    // kernel fail or do nothing (null pointers, invalid commands, flags 0)
    // or that point to memory the caller keeps alive across the call.
    let rc = unsafe { libc::syscall(nr, args[0], args[1], args[2], args[3], args[4]) };
    if rc < 0 { errno() } else { 0 }
}

/// Starts `/bin/sleep 30` with stdio inherited, in a new session when
/// `setsid`.
pub(crate) fn spawn_sleeper(setsid: bool) -> std::io::Result<u32> {
    use std::os::unix::process::CommandExt;
    let mut cmd = std::process::Command::new("/bin/sleep");
    cmd.arg("30");
    if setsid {
        // SAFETY: setsid is a system call.
        unsafe {
            cmd.pre_exec(|| {
                libc::setsid();
                Ok(())
            });
        }
    }
    let child = cmd.spawn()?;
    Ok(child.id())
}

/// Makes `cmd`'s child ignore `signals` before any later `pre_exec` step
/// (for procage's tests: a caller whose children inherit ignored signals).
pub(crate) fn ignore_before_spawn(cmd: &mut std::process::Command, signals: &[c_int]) {
    use std::os::unix::process::CommandExt;
    let signals = signals.to_vec();
    // SAFETY: signal is a system call; the list was allocated before the fork.
    unsafe {
        cmd.pre_exec(move || {
            for &sig in &signals {
                if libc::signal(sig, libc::SIG_IGN) == libc::SIG_ERR {
                    return Err(std::io::Error::last_os_error());
                }
            }
            Ok(())
        });
    }
}

/// Makes `cmd`'s child rename `planned` to `aside` and put `replacement` in
/// its place (a symbolic link to it, or the directory itself renamed), before
/// any later `pre_exec` step (for procage's tests: the window between a
/// cage's plan and its mounts).
pub(crate) fn plant_before_spawn(
    cmd: &mut std::process::Command,
    planned: &std::path::Path,
    aside: &std::path::Path,
    replacement: &std::path::Path,
    link: bool,
) -> std::io::Result<()> {
    use std::os::unix::process::CommandExt;
    let (from, aside, replacement) = (c_path(planned)?, c_path(aside)?, c_path(replacement)?);
    // SAFETY: rename and symlink on strings allocated before the fork.
    unsafe {
        cmd.pre_exec(move || {
            let os = std::io::Error::from_raw_os_error;
            check_int(libc::rename(from.as_ptr(), aside.as_ptr())).map_err(os)?;
            check_int(if link {
                libc::symlink(replacement.as_ptr(), from.as_ptr())
            } else {
                libc::rename(replacement.as_ptr(), from.as_ptr())
            })
            .map_err(os)?;
            Ok(())
        });
    }
    Ok(())
}

fn c_path(p: &std::path::Path) -> std::io::Result<CString> {
    use std::os::unix::ffi::OsStrExt;
    CString::new(p.as_os_str().as_bytes()).map_err(std::io::Error::other)
}

/// A new pseudo-terminal: the controller, the other end (the device) and
/// the device's path. Every descriptor is close-on-exec from the start, and
/// the window is 80 columns by 24 rows.
pub(crate) fn open_terminal() -> std::io::Result<(OwnedFd, OwnedFd, std::path::PathBuf)> {
    let last = std::io::Error::last_os_error;
    // SAFETY: a plain call with flags; the descriptor is ours.
    let fd = unsafe { libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY | libc::O_CLOEXEC) };
    if fd < 0 {
        return Err(last());
    }
    // SAFETY: a fresh descriptor we own.
    let controller = unsafe { OwnedFd::from_raw_fd(fd) };
    let mut number: c_int = 0;
    // The request type is `c_ulong` on glibc and `c_int` on musl.
    #[allow(clippy::useless_conversion, clippy::unnecessary_cast)]
    // SAFETY: plain calls on our descriptor; TIOCGPTN writes one integer on
    // this frame.
    let rc = unsafe {
        if libc::grantpt(fd) != 0 || libc::unlockpt(fd) != 0 {
            -1
        } else {
            libc::ioctl(fd, libc::TIOCGPTN as _, &raw mut number)
        }
    };
    if rc != 0 {
        return Err(last());
    }
    let path = std::path::PathBuf::from(format!("/dev/pts/{number}"));
    let c = c_path(&path)?;
    // SAFETY: open with a NUL-terminated path; the descriptor is ours.
    let device = unsafe { libc::open(c.as_ptr(), libc::O_RDWR | libc::O_NOCTTY | libc::O_CLOEXEC) };
    if device < 0 {
        return Err(last());
    }
    // SAFETY: a fresh descriptor we own.
    let device = unsafe { OwnedFd::from_raw_fd(device) };
    set_window(controller.as_raw_fd(), 24, 80)?;
    Ok((controller, device, path))
}

/// A new pseudo-terminal: the controller and the device path of the other
/// end, closed (for procage's tests).
pub(crate) fn open_pty() -> std::io::Result<(OwnedFd, std::path::PathBuf)> {
    let (controller, _, path) = open_terminal()?;
    Ok((controller, path))
}

/// Sets a terminal's window size (`TIOCSWINSZ`).
pub(crate) fn set_window(fd: c_int, rows: u16, cols: u16) -> std::io::Result<()> {
    let size = libc::winsize {
        ws_row: rows,
        ws_col: cols,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    // The request type is `c_ulong` on glibc and `c_int` on musl.
    #[allow(clippy::useless_conversion, clippy::unnecessary_cast)]
    // SAFETY: the ioctl reads the structure on this frame.
    let rc = unsafe { libc::ioctl(fd, libc::TIOCSWINSZ as _, &raw const size) };
    if rc == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

/// `ioctl(fd, TIOCSCTTY, 0)`, or with `byte`, `ioctl(fd, TIOCSTI, &byte)`;
/// the errno, or 0 (for procage's tests).
pub(crate) fn tty_ioctl_errno(fd: c_int, byte: Option<u8>) -> i32 {
    let c = byte.unwrap_or(0) as libc::c_char;
    // The request type is `c_ulong` on glibc and `c_int` on musl.
    #[allow(clippy::useless_conversion, clippy::unnecessary_cast)]
    // SAFETY: TIOCSCTTY takes an integer; TIOCSTI reads one byte from the
    // pointer.
    let rc = unsafe {
        match byte {
            None => libc::ioctl(fd, libc::TIOCSCTTY as _, 0),
            Some(_) => libc::ioctl(fd, libc::TIOCSTI as _, &raw const c),
        }
    };
    if rc == -1 { errno() } else { 0 }
}

/// Sends one byte on the UDP socket `fd` to `127.0.0.1:port`; the errno,
/// or 0 (for procage's tests).
pub(crate) fn udp_send_errno(fd: c_int, port: u16) -> i32 {
    let addr = libc::sockaddr_in {
        sin_family: libc::AF_INET as libc::sa_family_t,
        sin_port: port.to_be(),
        sin_addr: libc::in_addr {
            s_addr: u32::from(std::net::Ipv4Addr::LOCALHOST).to_be(),
        },
        sin_zero: [0; 8],
    };
    // SAFETY: one byte from a local, and a valid IPv4 address of its size.
    let rc = unsafe {
        libc::sendto(
            fd,
            b"x".as_ptr().cast(),
            1,
            0,
            (&raw const addr).cast(),
            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
        )
    };
    if rc == -1 { errno() } else { 0 }
}

/// One direct route to `127.0.0.1:port` (for procage's tests): `fastopen`
/// (TCP Fast Open data in `sendto`), `mptcp`, `raw` (an ICMP socket) or
/// `tcp6` (`::1`); the errno, or 0 when it got through.
pub(crate) fn net_errno(kind: &str, port: u16) -> i32 {
    let v4 = libc::sockaddr_in {
        sin_family: libc::AF_INET as libc::sa_family_t,
        sin_port: port.to_be(),
        sin_addr: libc::in_addr {
            s_addr: u32::from(std::net::Ipv4Addr::LOCALHOST).to_be(),
        },
        sin_zero: [0; 8],
    };
    // SAFETY: an all-zero sockaddr_in6 is valid; the fields are set below.
    let mut v6: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
    v6.sin6_family = libc::AF_INET6 as libc::sa_family_t;
    v6.sin6_port = port.to_be();
    v6.sin6_addr.s6_addr = std::net::Ipv6Addr::LOCALHOST.octets();
    let (family, kind_, protocol) = match kind {
        "fastopen" => (libc::AF_INET, libc::SOCK_STREAM, 0),
        "mptcp" => (libc::AF_INET, libc::SOCK_STREAM, libc::IPPROTO_MPTCP),
        "raw" => (libc::AF_INET, libc::SOCK_RAW, libc::IPPROTO_ICMP),
        "tcp6" => (libc::AF_INET6, libc::SOCK_STREAM, 0),
        _ => return libc::EINVAL,
    };
    // SAFETY: socket with integer arguments.
    let fd = unsafe { libc::socket(family, kind_ | libc::SOCK_CLOEXEC, protocol) };
    if fd < 0 {
        return errno();
    }
    let len = |size: usize| size as libc::socklen_t;
    // SAFETY: each call gets an address of the size it is told, and one
    // byte from a local.
    let rc = unsafe {
        match kind {
            "fastopen" => libc::sendto(
                fd,
                b"x".as_ptr().cast(),
                1,
                libc::MSG_FASTOPEN,
                (&raw const v4).cast(),
                len(std::mem::size_of::<libc::sockaddr_in>()),
            ) as c_int,
            "raw" => libc::sendto(
                fd,
                [8u8, 0, 0xf7, 0xff, 0, 0, 0, 0].as_ptr().cast(),
                8,
                0,
                (&raw const v4).cast(),
                len(std::mem::size_of::<libc::sockaddr_in>()),
            ) as c_int,
            "tcp6" => libc::connect(
                fd,
                (&raw const v6).cast(),
                len(std::mem::size_of::<libc::sockaddr_in6>()),
            ),
            _ => libc::connect(
                fd,
                (&raw const v4).cast(),
                len(std::mem::size_of::<libc::sockaddr_in>()),
            ),
        }
    };
    let result = if rc < 0 { errno() } else { 0 };
    // SAFETY: closing the socket this function created.
    unsafe { libc::close(fd) };
    result
}

// ------------------------------------------------------------------ listener

/// Sets `no_new_privs` on the calling thread and installs `filter` with a
/// listener there (for tests: an outer sandbox using notification).
pub(crate) fn install_outer_listener(mut filter: Vec<Insn>) -> Result<OwnedFd, i32> {
    prctl(libc::PR_SET_NO_NEW_PRIVS, 1)?;
    let fd = install_filter(&mut filter, libc::SECCOMP_FILTER_FLAG_NEW_LISTENER)?;
    // SAFETY: the kernel just created this descriptor for us.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// A `SOCK_SEQPACKET` pair, close-on-exec: the parent's end and the child's.
pub(crate) fn socket_pair() -> std::io::Result<(OwnedFd, OwnedFd)> {
    let mut fds = [0 as c_int; 2];
    // SAFETY: socketpair writes two descriptors into the array.
    let rc = unsafe {
        libc::socketpair(
            libc::AF_UNIX,
            libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC,
            0,
            fds.as_mut_ptr(),
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: both descriptors are new and owned here.
    Ok(unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) })
}

/// What the child sent before its exec.
pub(crate) enum HandOver {
    /// The seccomp listener.
    Listener(OwnedFd),
    /// No listener: the errno the kernel gave; the plain filter is in force.
    Refused(i32),
}

/// Reads the child's message from the parent's end, without waiting (it
/// was sent before the exec that the spawn waited for).
pub(crate) fn receive(socket: &OwnedFd) -> Result<HandOver, i32> {
    let mut bytes = [0u8; 5];
    let mut iov = libc::iovec {
        iov_base: bytes.as_mut_ptr().cast(),
        iov_len: bytes.len(),
    };
    // SAFETY: CMSG_SPACE only computes a size.
    let space = unsafe { libc::CMSG_SPACE(std::mem::size_of::<c_int>() as u32) } as usize;
    let mut control = vec![0u8; space];
    // SAFETY: a zeroed msghdr is a valid empty message.
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &raw mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.as_mut_ptr().cast();
    msg.msg_controllen = control.len() as _;
    // SAFETY: msg points to buffers on this frame for the whole call.
    let n = unsafe {
        libc::recvmsg(
            socket.as_raw_fd(),
            &raw mut msg,
            libc::MSG_DONTWAIT | libc::MSG_CMSG_CLOEXEC,
        )
    };
    if n < 1 {
        return Err(if n < 0 { errno() } else { libc::EPIPE });
    }
    // SAFETY: the kernel filled msg; CMSG_FIRSTHDR checks the length.
    let header = unsafe { libc::CMSG_FIRSTHDR(&raw const msg) };
    let fd = if header.is_null() {
        None
    } else {
        // SAFETY: a non-null header lies within the control buffer.
        let h = unsafe { &*header };
        (h.cmsg_level == libc::SOL_SOCKET && h.cmsg_type == libc::SCM_RIGHTS).then(|| {
            // SAFETY: an SCM_RIGHTS header carries at least one descriptor.
            unsafe { std::ptr::read_unaligned(libc::CMSG_DATA(header).cast::<c_int>()) }
        })
    };
    // SAFETY: the kernel installed this descriptor for us; owned at once so
    // that a malformed message does not leak it.
    let fd = fd.map(|fd| unsafe { OwnedFd::from_raw_fd(fd) });
    match (bytes[0], fd) {
        (1, Some(fd)) => Ok(HandOver::Listener(fd)),
        (0, None) if n == 5 => Ok(HandOver::Refused(i32::from_le_bytes([
            bytes[1], bytes[2], bytes[3], bytes[4],
        ]))),
        _ => Err(libc::EPROTO),
    }
}

/// What waiting on a listener found.
pub(crate) enum Wait {
    /// A notification is ready.
    Ready,
    /// No process uses the filter any more.
    HungUp,
    /// Nothing within the timeout.
    Idle,
}

/// Waits up to `timeout_ms` on `listener`.
pub(crate) fn wait_listener(listener: &OwnedFd, timeout_ms: c_int) -> Result<Wait, i32> {
    let mut pfd = libc::pollfd {
        fd: listener.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: poll on one pollfd on this frame.
    let rc = unsafe { libc::poll(&raw mut pfd, 1, timeout_ms) };
    if rc < 0 {
        let e = errno();
        return if e == libc::EINTR {
            Ok(Wait::Idle)
        } else {
            Err(e)
        };
    }
    if rc == 0 {
        return Ok(Wait::Idle);
    }
    if pfd.revents & libc::POLLIN != 0 {
        Ok(Wait::Ready)
    } else {
        Ok(Wait::HungUp)
    }
}

/// One refused call the kernel reported.
pub(crate) struct Notification {
    pub(crate) id: u64,
    pub(crate) pid: u32,
    pub(crate) nr: u32,
    pub(crate) args: [u64; 6],
}

/// Receives one notification (`SECCOMP_IOCTL_NOTIF_RECV`).
pub(crate) fn receive_notification(listener: &OwnedFd) -> Result<Notification, i32> {
    // SAFETY: the kernel requires a zeroed structure.
    let mut n: libc::seccomp_notif = unsafe { std::mem::zeroed() };
    // SAFETY: the ioctl fills the structure on this frame.
    let rc = unsafe {
        libc::ioctl(
            listener.as_raw_fd(),
            libc::SECCOMP_IOCTL_NOTIF_RECV,
            &raw mut n,
        )
    };
    if rc != 0 {
        return Err(errno());
    }
    Ok(Notification {
        id: n.id,
        pid: n.pid,
        nr: n.data.nr as u32,
        args: n.data.args,
    })
}

/// Answers notification `id`: the call fails with `EPERM`. Never anything
/// else: no value, no flags (`SECCOMP_USER_NOTIF_FLAG_CONTINUE` would let the
/// call run). `ENOENT`: the caller was interrupted and the call withdrawn.
pub(crate) fn answer_eperm(listener: &OwnedFd, id: u64) -> Result<(), i32> {
    let mut resp = libc::seccomp_notif_resp {
        id,
        val: 0,
        error: -libc::EPERM,
        flags: 0,
    };
    // SAFETY: the ioctl reads the structure on this frame.
    let rc = unsafe {
        libc::ioctl(
            listener.as_raw_fd(),
            libc::SECCOMP_IOCTL_NOTIF_SEND,
            &raw mut resp,
        )
    };
    if rc != 0 { Err(errno()) } else { Ok(()) }
}

/// Whether notification `id` is still pending (its caller still blocked).
pub(crate) fn notification_valid(listener: &OwnedFd, id: u64) -> bool {
    // SAFETY: the ioctl reads one u64 on this frame.
    unsafe {
        libc::ioctl(
            listener.as_raw_fd(),
            libc::SECCOMP_IOCTL_NOTIF_ID_VALID,
            &raw const id,
        ) == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn insn_has_the_layout_of_sock_filter() {
        assert_eq!(
            std::mem::size_of::<Insn>(),
            std::mem::size_of::<libc::sock_filter>()
        );
        assert_eq!(
            std::mem::align_of::<Insn>(),
            std::mem::align_of::<libc::sock_filter>()
        );
    }

    #[test]
    fn step_codes_round_trip() {
        assert_eq!(decode_step(step_code(steps::VERIFY, 13)), Some((12, 13)));
        assert_eq!(decode_step(13), None);
    }
}
