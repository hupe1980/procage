//! Landlock, seccomp, namespace, mount and interface calls on Linux.

use std::ffi::{CString, c_int, c_long};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

use super::errno;

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

const CREATE_RULESET_VERSION: u32 = 1 << 0;
const CREATE_RULESET_ERRATA: u32 = 1 << 1;
const RULE_PATH_BENEATH: c_int = 1;

/// `LANDLOCK_ACCESS_FS_WRITE_FILE`.
pub const FS_WRITE_FILE: u64 = 1 << 1;
/// `LANDLOCK_ACCESS_FS_MAKE_REG`.
pub const FS_MAKE_REG: u64 = 1 << 8;
/// `LANDLOCK_ACCESS_FS_TRUNCATE` (ABI 3).
pub const FS_TRUNCATE: u64 = 1 << 14;

fn check(rc: c_long) -> Result<c_long, i32> {
    if rc < 0 { Err(errno()) } else { Ok(rc) }
}

/// The Landlock ABI version, or the errno (`EOPNOTSUPP`/`ENOSYS`) when absent.
pub fn landlock_abi() -> Result<u32, i32> {
    // SAFETY: the documented version query: NULL attr, size 0.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            std::ptr::null::<u8>(),
            0usize,
            CREATE_RULESET_VERSION,
        )
    };
    check(rc).map(|v| v as u32)
}

/// The Landlock errata bitmask.
pub fn landlock_errata() -> Result<u32, i32> {
    // SAFETY: the documented errata query: NULL attr, size 0.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            std::ptr::null::<u8>(),
            0usize,
            CREATE_RULESET_ERRATA,
        )
    };
    check(rc).map(|v| v as u32)
}

/// A ruleset handling `handled_fs` accesses.
pub fn landlock_ruleset(handled_fs: u64) -> Result<OwnedFd, i32> {
    let attr = RulesetAttr {
        handled_access_fs: handled_fs,
        handled_access_net: 0,
        scoped: 0,
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
    // SAFETY: a non-negative return is a new fd we own.
    check(rc).map(|fd| unsafe { OwnedFd::from_raw_fd(fd as c_int) })
}

/// Allows `access` beneath `path` in `ruleset`.
pub fn landlock_allow(ruleset: &OwnedFd, path: &str, access: u64) -> Result<(), i32> {
    let c = CString::new(path).map_err(|_| libc::EINVAL)?;
    // SAFETY: open with O_PATH; the fd is owned immediately.
    let fd = unsafe { libc::open(c.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
    if fd < 0 {
        return Err(errno());
    }
    // SAFETY: fd is a fresh descriptor we own.
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    let attr = PathBeneathAttr {
        allowed_access: access,
        parent_fd: fd.as_raw_fd(),
    };
    // SAFETY: attr is a valid packed struct; both fds are open.
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

/// Sets no_new_privs and restricts this thread to `ruleset`.
pub fn landlock_restrict(ruleset: &OwnedFd) -> Result<(), i32> {
    no_new_privs()?;
    // SAFETY: restrict_self with an open ruleset fd and no flags.
    let rc = unsafe { libc::syscall(libc::SYS_landlock_restrict_self, ruleset.as_raw_fd(), 0u32) };
    check(rc).map(drop)
}

/// `truncate(path, 0)`.
pub fn truncate(path: &str) -> Result<(), i32> {
    let c = CString::new(path).map_err(|_| libc::EINVAL)?;
    // SAFETY: a valid C string; no memory is written.
    let rc = unsafe { libc::truncate(c.as_ptr(), 0) };
    check(rc.into()).map(drop)
}

/// `open(path, flags)`, closing the descriptor it returns.
pub fn open_close(path: &str, flags: c_int) -> Result<(), i32> {
    let c = CString::new(path).map_err(|_| libc::EINVAL)?;
    // SAFETY: a valid C string; the fd is owned immediately.
    let fd = unsafe { libc::open(c.as_ptr(), flags | libc::O_CLOEXEC) };
    if fd < 0 {
        return Err(errno());
    }
    // SAFETY: fd is a fresh descriptor we own.
    drop(unsafe { OwnedFd::from_raw_fd(fd) });
    Ok(())
}

/// `prctl(PR_SET_NO_NEW_PRIVS, 1)`.
pub fn no_new_privs() -> Result<(), i32> {
    // SAFETY: prctl with integer arguments.
    let rc = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    check(rc.into()).map(drop)
}

/// Installs a one-instruction seccomp filter that allows everything.
pub fn seccomp_allow_all() -> Result<(), i32> {
    no_new_privs()?;
    let mut filter = [libc::sock_filter {
        code: (libc::BPF_RET | libc::BPF_K) as u16,
        jt: 0,
        jf: 0,
        k: libc::SECCOMP_RET_ALLOW,
    }];
    let prog = libc::sock_fprog {
        len: 1,
        filter: filter.as_mut_ptr(),
    };
    // SAFETY: prog points to one valid instruction for the duration of the call.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            libc::SECCOMP_SET_MODE_FILTER,
            0u32,
            &raw const prog,
        )
    };
    check(rc).map(drop)
}

/// `unshare(flags)`.
pub fn unshare(flags: c_int) -> Result<(), i32> {
    // SAFETY: integer flags; the process is single-threaded when a user
    // namespace is requested (each step is a fresh process).
    let rc = unsafe { libc::unshare(flags) };
    check(rc.into()).map(drop)
}

/// `mount(2)`; `None` arguments are passed as NULL.
pub fn mount(
    source: Option<&str>,
    target: &str,
    fstype: Option<&str>,
    flags: libc::c_ulong,
) -> Result<(), i32> {
    let s = source.map(|s| CString::new(s).expect("source"));
    let t = CString::new(target).map_err(|_| libc::EINVAL)?;
    let f = fstype.map(|s| CString::new(s).expect("fstype"));
    let p = |c: &Option<CString>| c.as_ref().map_or(std::ptr::null(), |c| c.as_ptr());
    // SAFETY: all pointers are NUL-terminated strings or NULL.
    let rc = unsafe { libc::mount(p(&s), t.as_ptr(), p(&f), flags, std::ptr::null()) };
    check(rc.into()).map(drop)
}

/// `umount2(target, 0)`.
pub fn umount(target: &str) -> Result<(), i32> {
    let t = CString::new(target).map_err(|_| libc::EINVAL)?;
    // SAFETY: NUL-terminated path.
    let rc = unsafe { libc::umount2(t.as_ptr(), 0) };
    check(rc.into()).map(drop)
}

/// `ST_RELATIME` (missing from libc's musl bindings).
const ST_RELATIME: libc::c_ulong = 0x1000;

/// The mount flags of the mount containing `path` that a bind remount must
/// keep (the kernel locks them when the mount came from a more privileged
/// namespace).
pub fn locked_flags(path: &str) -> Result<libc::c_ulong, i32> {
    let c = CString::new(path).map_err(|_| libc::EINVAL)?;
    // SAFETY: statvfs fills a zeroed struct on our stack.
    let st = unsafe {
        let mut st: libc::statvfs = std::mem::zeroed();
        if libc::statvfs(c.as_ptr(), &raw mut st) != 0 {
            return Err(errno());
        }
        st
    };
    let map = [
        (libc::ST_NOSUID, libc::MS_NOSUID),
        (libc::ST_NODEV, libc::MS_NODEV),
        (libc::ST_NOEXEC, libc::MS_NOEXEC),
        (libc::ST_NOATIME, libc::MS_NOATIME),
        (libc::ST_NODIRATIME, libc::MS_NODIRATIME),
        (ST_RELATIME, libc::MS_RELATIME),
    ];
    Ok(map
        .iter()
        .filter(|(st_flag, _)| st.f_flag & st_flag != 0)
        .fold(0, |acc, (_, ms)| acc | ms))
}

/// The real uid and gid.
pub fn ids() -> (u32, u32) {
    // SAFETY: no arguments, cannot fail.
    unsafe { (libc::getuid(), libc::getgid()) }
}

/// Whether interface `name` has `IFF_UP`, via `SIOCGIFFLAGS`.
pub fn interface_up(name: &str) -> Result<bool, i32> {
    // SAFETY: a datagram socket owned immediately; the ifreq is zeroed and
    // its name NUL-terminated within IFNAMSIZ.
    unsafe {
        let s = libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0);
        if s < 0 {
            return Err(errno());
        }
        let s = OwnedFd::from_raw_fd(s);
        let mut req: libc::ifreq = std::mem::zeroed();
        for (dst, src) in req
            .ifr_name
            .iter_mut()
            .zip(name.bytes().take(libc::IFNAMSIZ - 1))
        {
            *dst = src as libc::c_char;
        }
        // The request type is `c_ulong` on glibc and `c_int` on musl.
        #[allow(clippy::useless_conversion, clippy::unnecessary_cast)]
        if libc::ioctl(s.as_raw_fd(), libc::SIOCGIFFLAGS as _, &raw mut req) != 0 {
            return Err(errno());
        }
        Ok(c_int::from(req.ifr_ifru.ifru_flags) & libc::IFF_UP != 0)
    }
}

/// What one round of seccomp user notification showed (KF-L15).
pub struct NotifyRound {
    /// The errno of installing a second filter with a listener (0: allowed).
    pub second_listener_errno: i32,
    /// The errno the notified call returned in the child.
    pub child_errno: i32,
    /// Notifications the parent received.
    pub notified: u32,
    /// Whether the listener reported POLLHUP after the child exited.
    pub hung_up: bool,
}

/// Forks a child that installs a filter notifying `getppid` with a listener,
/// tries a second listener, hands the first to this process and calls
/// `getppid`; this process answers EPERM and waits for the hang-up.
pub fn seccomp_notify_round() -> Result<NotifyRound, String> {
    let mut sv = [0 as c_int; 2];
    // SAFETY: socketpair writes two descriptors.
    if unsafe {
        libc::socketpair(
            libc::AF_UNIX,
            libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC,
            0,
            sv.as_mut_ptr(),
        )
    } != 0
    {
        return Err(format!("socketpair errno {}", errno()));
    }
    let mut report = [0 as c_int; 2];
    // SAFETY: pipe2 writes two descriptors.
    if unsafe { libc::pipe2(report.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return Err(format!("pipe errno {}", errno()));
    }
    // SAFETY: the probe is single-threaded; the child below only makes
    // system calls and exits.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(format!("fork errno {}", errno()));
    }
    if pid == 0 {
        // SAFETY: system calls on descriptors and buffers of this frame.
        unsafe {
            let mut filter = [
                libc::sock_filter {
                    code: (libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as u16,
                    jt: 0,
                    jf: 0,
                    k: 0,
                },
                libc::sock_filter {
                    code: (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16,
                    jt: 0,
                    jf: 1,
                    k: libc::SYS_getppid as u32,
                },
                libc::sock_filter {
                    code: (libc::BPF_RET | libc::BPF_K) as u16,
                    jt: 0,
                    jf: 0,
                    k: libc::SECCOMP_RET_USER_NOTIF,
                },
                libc::sock_filter {
                    code: (libc::BPF_RET | libc::BPF_K) as u16,
                    jt: 0,
                    jf: 0,
                    k: libc::SECCOMP_RET_ALLOW,
                },
            ];
            let prog = libc::sock_fprog {
                len: 4,
                filter: filter.as_mut_ptr(),
            };
            libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
            let flags = libc::SECCOMP_FILTER_FLAG_NEW_LISTENER;
            let l = libc::syscall(
                libc::SYS_seccomp,
                libc::SECCOMP_SET_MODE_FILTER,
                flags,
                &raw const prog,
            );
            if l < 0 {
                libc::_exit(10);
            }
            let l2 = libc::syscall(
                libc::SYS_seccomp,
                libc::SECCOMP_SET_MODE_FILTER,
                flags,
                &raw const prog,
            );
            let second = if l2 < 0 { errno() } else { 0 };
            // Hand the listener over.
            let byte = 1u8;
            let mut iov = libc::iovec {
                iov_base: (&raw const byte).cast_mut().cast(),
                iov_len: 1,
            };
            let mut control = [0u8; 64];
            let mut msg: libc::msghdr = std::mem::zeroed();
            msg.msg_iov = &raw mut iov;
            msg.msg_iovlen = 1;
            msg.msg_control = control.as_mut_ptr().cast();
            msg.msg_controllen = libc::CMSG_SPACE(4) as _;
            let h = libc::CMSG_FIRSTHDR(&raw const msg);
            (*h).cmsg_level = libc::SOL_SOCKET;
            (*h).cmsg_type = libc::SCM_RIGHTS;
            (*h).cmsg_len = libc::CMSG_LEN(4) as _;
            std::ptr::write_unaligned(libc::CMSG_DATA(h).cast::<c_int>(), l as c_int);
            if libc::sendmsg(sv[1], &raw const msg, 0) < 0 {
                libc::_exit(11);
            }
            libc::close(l as c_int);
            let rc = libc::syscall(libc::SYS_getppid);
            let e = if rc < 0 { errno() } else { 0 };
            let out = [second, e];
            libc::write(report[1], out.as_ptr().cast(), 8);
            libc::_exit(0);
        }
    }
    // SAFETY: closing the child's ends in the parent.
    unsafe {
        libc::close(sv[1]);
        libc::close(report[1]);
    }
    // SAFETY: the parent's ends are owned here from now on.
    let (sock, report) = unsafe { (OwnedFd::from_raw_fd(sv[0]), OwnedFd::from_raw_fd(report[0])) };
    let mut byte = 0u8;
    let mut iov = libc::iovec {
        iov_base: (&raw mut byte).cast(),
        iov_len: 1,
    };
    let mut control = [0u8; 64];
    // SAFETY: a zeroed msghdr pointing to buffers of this frame.
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &raw mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.as_mut_ptr().cast();
    msg.msg_controllen = control.len() as _;
    // SAFETY: recvmsg into the buffers above.
    if unsafe { libc::recvmsg(sock.as_raw_fd(), &raw mut msg, libc::MSG_CMSG_CLOEXEC) } < 1 {
        let mut status = 0;
        // SAFETY: reaping our child.
        unsafe { libc::waitpid(pid, &raw mut status, 0) };
        return Err(format!("no listener (child status {status:#x})"));
    }
    // SAFETY: an SCM_RIGHTS message with one descriptor arrived.
    let listener = unsafe {
        OwnedFd::from_raw_fd(std::ptr::read_unaligned(
            libc::CMSG_DATA(libc::CMSG_FIRSTHDR(&raw const msg)).cast::<c_int>(),
        ))
    };
    let mut notified = 0;
    let mut hung_up = false;
    for _ in 0..50 {
        let mut pfd = libc::pollfd {
            fd: listener.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: poll on one descriptor.
        let n = unsafe { libc::poll(&raw mut pfd, 1, 100) };
        if n > 0 && pfd.revents & libc::POLLIN != 0 {
            // SAFETY: zeroed as the kernel requires; the ioctls use this frame.
            unsafe {
                let mut req: libc::seccomp_notif = std::mem::zeroed();
                if libc::ioctl(
                    listener.as_raw_fd(),
                    libc::SECCOMP_IOCTL_NOTIF_RECV,
                    &raw mut req,
                ) == 0
                {
                    notified += 1;
                    let mut resp = libc::seccomp_notif_resp {
                        id: req.id,
                        val: 0,
                        error: -libc::EPERM,
                        flags: 0,
                    };
                    libc::ioctl(
                        listener.as_raw_fd(),
                        libc::SECCOMP_IOCTL_NOTIF_SEND,
                        &raw mut resp,
                    );
                }
            }
        } else if n > 0 && pfd.revents & libc::POLLHUP != 0 {
            hung_up = true;
            break;
        }
    }
    let mut out = [0 as c_int; 2];
    // SAFETY: reading 8 bytes into the array.
    unsafe { libc::read(report.as_raw_fd(), out.as_mut_ptr().cast(), 8) };
    let mut status = 0;
    // SAFETY: reaping our child.
    unsafe { libc::waitpid(pid, &raw mut status, 0) };
    Ok(NotifyRound {
        second_listener_errno: out[0],
        child_errno: out[1],
        notified,
        hung_up,
    })
}
