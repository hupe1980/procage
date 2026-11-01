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

/// `ST_RELATIME` (missing from libc's musl bindings).
const ST_RELATIME: c_ulong = 0x1000;

/// The flags of the mount holding `path` that a bind remount must keep (the
/// kernel locks them when the mount came from a more privileged namespace).
pub(crate) fn locked_flags(path: &CStr) -> Result<c_ulong, i32> {
    // SAFETY: statvfs fills a zeroed struct on our stack.
    let st = unsafe {
        let mut st: libc::statvfs = std::mem::zeroed();
        if libc::statvfs(path.as_ptr(), &raw mut st) != 0 {
            return Err(errno());
        }
        st
    };
    let map = [
        (libc::ST_RDONLY, libc::MS_RDONLY),
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

/// A mount the child makes on tier T1.
#[derive(Debug)]
pub(crate) enum ChildMount {
    /// `mount(source, target, NULL, MS_BIND[|MS_REC])`.
    Bind {
        source: CString,
        target: CString,
        recursive: bool,
    },
    /// `mount(NULL, target, NULL, MS_BIND|MS_REMOUNT|flags)`.
    Remount { target: CString, flags: c_ulong },
    /// `mount("tmpfs", target, "tmpfs", flags, data)`.
    Tmpfs {
        target: CString,
        flags: c_ulong,
        data: CString,
    },
}

/// The namespaces and mounts of a T1 child.
#[derive(Debug)]
pub(crate) struct Isolate {
    pub(crate) flags: c_int,
    pub(crate) uid_map: Vec<u8>,
    pub(crate) gid_map: Vec<u8>,
    pub(crate) mounts: Vec<ChildMount>,
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

/// Marks every descriptor >= 3 close-on-exec except `keep` (sorted), with
/// `close_range`; where the kernel lacks it, with `fcntl` up to the
/// open-files limit.
fn mark_fds(keep: &[c_int]) -> Result<(), i32> {
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
    /// The child sequence (plan.md): system calls only.
    fn run(&mut self) -> std::io::Result<()> {
        let fail =
            |step: u32, errno: i32| std::io::Error::from_raw_os_error(step_code(step, errno));
        // SAFETY: setsid and setpgid are system calls without pointers.
        let rc = unsafe {
            match self.session {
                Session::New => libc::setsid(),
                Session::Group => libc::setpgid(0, 0),
                Session::Keep => 0,
            }
        };
        check_int(rc).map_err(|e| fail(steps::SESSION, e))?;
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
            for m in &iso.mounts {
                match m {
                    ChildMount::Bind {
                        source,
                        target,
                        recursive,
                    } => {
                        let rec = if *recursive { libc::MS_REC } else { 0 };
                        mount(Some(source), target, None, libc::MS_BIND | rec, None)
                    }
                    ChildMount::Remount { target, flags } => mount(
                        None,
                        target,
                        None,
                        libc::MS_BIND | libc::MS_REMOUNT | flags,
                        None,
                    ),
                    ChildMount::Tmpfs {
                        target,
                        flags,
                        data,
                    } => mount(Some(c"tmpfs"), target, Some(c"tmpfs"), *flags, Some(data)),
                }
                .map_err(|e| fail(steps::MOUNTS, e))?;
            }
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
        let prog = libc::sock_fprog {
            len: u16::try_from(self.filter.len()).map_err(|_| fail(steps::SECCOMP, libc::E2BIG))?,
            filter: self.filter.as_mut_ptr().cast(),
        };
        // SAFETY: `Insn` has the layout of `struct sock_filter` (checked by a
        // test); prog points to the parent's buffer for the whole call.
        let rc = unsafe {
            libc::syscall(
                libc::SYS_seccomp,
                libc::SECCOMP_SET_MODE_FILTER,
                0u32,
                &raw const prog,
            )
        };
        check(rc).map_err(|e| fail(steps::SECCOMP, e))?;
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
        // SAFETY: `run` issues only system calls (setsid or setpgid, prctl,
        // getppid, unshare, open/write/close on /proc/self, mount,
        // capset, setrlimit, close_range or fcntl, getrlimit,
        // landlock_restrict_self, seccomp). Everything it reads was
        // allocated in the parent and is owned by the closure.
        unsafe {
            command.pre_exec(move || plan.run());
        }
    }
}

// ------------------------------------------------------------------ probe

/// `mount("tmpfs", "/tmp", …)` succeeded after `unshare` with `flags` and
/// self-mapped ids, in a throwaway child. Returns the errno of the first
/// failure.
pub(crate) fn probe_userns(flags: c_int) -> Result<(), i32> {
    let (uid, gid) = ids();
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
            mount(Some(c"tmpfs"), c"/tmp", Some(c"tmpfs"), 0, Some(c""))
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

/// A new pseudo-terminal: the controller and the device path of the other
/// end (for procage's tests).
pub(crate) fn open_pty() -> std::io::Result<(OwnedFd, std::path::PathBuf)> {
    use std::os::unix::ffi::OsStrExt;
    let (mut controller, mut device) = (-1, -1);
    let mut name = [0 as libc::c_char; 128];
    // SAFETY: out-parameters on this frame; `name` holds the 128 bytes
    // openpty may write; no termios or window size.
    let rc = unsafe {
        libc::openpty(
            &raw mut controller,
            &raw mut device,
            name.as_mut_ptr(),
            std::ptr::null(),
            std::ptr::null(),
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: both descriptors are fresh and owned here; the device end is
    // closed (the caller opens it by path).
    let controller = unsafe {
        drop(OwnedFd::from_raw_fd(device));
        OwnedFd::from_raw_fd(controller)
    };
    // SAFETY: openpty wrote a NUL-terminated name.
    let name = unsafe { CStr::from_ptr(name.as_ptr()) };
    Ok((
        controller,
        std::ffi::OsStr::from_bytes(name.to_bytes()).into(),
    ))
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
