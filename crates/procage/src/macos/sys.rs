//! The macOS system interface: the only module of procage allowed to use
//! `unsafe`. Every unsafe block states why it is sound.
//!
//! libsandbox's compile, check and extension symbols and `__mac_syscall` are
//! private. They are resolved at runtime with `dlsym`, once, before any child
//! is forked; a missing symbol is a typed error, never a load failure.
//!
//! [`ChildOps`] holds plain function pointers and is the only part used
//! between `fork` and `execve`: its methods are system calls or, for
//! `sandbox_check` and `sandbox_extension_consume`, functions that issue
//! system calls without allocating or locking.

#![allow(unsafe_code)]

use std::ffi::{CStr, CString, c_char, c_int, c_void};
use std::sync::OnceLock;

/// `sandbox_profile_t` as returned by `sandbox_compile_string`.
#[repr(C)]
struct Profile {
    builtin: *mut c_char,
    data: *const u8,
    size: usize,
}

/// The argument of `__mac_syscall("Sandbox", 0, …)`: bytecode plus an
/// optional container name.
#[repr(C)]
struct ApplyArgs {
    data: *const u8,
    size: usize,
    container: *const c_char,
    container_len: usize,
}

type CompileString =
    unsafe extern "C" fn(*const c_char, *mut c_void, *mut *mut c_char) -> *mut Profile;
type FreeProfile = unsafe extern "C" fn(*mut Profile);
type CreateParams = unsafe extern "C" fn() -> *mut c_void;
type SetParam = unsafe extern "C" fn(*mut c_void, *const c_char, *const c_char) -> c_int;
type FreeParams = unsafe extern "C" fn(*mut c_void);
type MacSyscall = unsafe extern "C" fn(*const c_char, c_int, *mut c_void) -> c_int;
type Check = unsafe extern "C" fn(libc::pid_t, *const c_char, c_int, ...) -> c_int;

/// `sandbox_check`'s filter type for a mach service name.
const SANDBOX_FILTER_GLOBAL_NAME: c_int = 2;
type IssueFile = unsafe extern "C" fn(*const c_char, *const c_char, u32) -> *mut c_char;
type Consume = unsafe extern "C" fn(*const c_char) -> i64;

const LIBSANDBOX: &CStr = c"/usr/lib/libsandbox.1.dylib";

/// The resolved libsandbox interface.
pub(crate) struct Libsandbox {
    compile_string: CompileString,
    free_profile: FreeProfile,
    create_params: CreateParams,
    set_param: SetParam,
    free_params: FreeParams,
    issue_file: IssueFile,
    child: ChildOps,
}

/// Function pointers used in the child between `fork` and `execve`.
#[derive(Clone, Copy)]
pub(crate) struct ChildOps {
    mac_syscall: MacSyscall,
    check: Check,
    consume: Consume,
}

fn resolve(name: &str) -> Option<*mut c_void> {
    let cname = CString::new(name).ok()?;
    // SAFETY: dlsym with RTLD_DEFAULT and a NUL-terminated name only reads
    // the loaded images' symbol tables.
    let p = unsafe { libc::dlsym(libc::RTLD_DEFAULT, cname.as_ptr()) };
    (!p.is_null()).then_some(p)
}

/// Whether `name` resolves after libsandbox is loaded (for tests and
/// diagnostics).
pub(crate) fn has_symbol(name: &str) -> bool {
    load_libsandbox();
    resolve(name).is_some()
}

fn load_libsandbox() {
    // SAFETY: dlopen of a system library by absolute path; the handle is kept
    // for the life of the process (never dlclosed).
    unsafe { libc::dlopen(LIBSANDBOX.as_ptr(), libc::RTLD_NOW | libc::RTLD_GLOBAL) };
}

/// The value of `kern.osversion` (the build, e.g. `25G83`).
pub(crate) fn os_build() -> String {
    string_sysctl(c"kern.osversion")
}

/// The value of `kern.osproductversion` (the release, e.g. `26.6.2`).
pub(crate) fn os_release() -> String {
    string_sysctl(c"kern.osproductversion")
}

fn string_sysctl(name: &std::ffi::CStr) -> String {
    let mut buf = [0u8; 64];
    let mut len = buf.len();
    // SAFETY: sysctlbyname writes at most `len` bytes into `buf` and updates
    // `len`; no new value is set.
    let rc = unsafe {
        libc::sysctlbyname(
            name.as_ptr(),
            buf.as_mut_ptr().cast(),
            &raw mut len,
            std::ptr::null_mut(),
            0,
        )
    };
    if rc != 0 {
        return "unknown".into();
    }
    let end = buf[..len].iter().position(|&b| b == 0).unwrap_or(len);
    String::from_utf8_lossy(&buf[..end]).into_owned()
}

impl Libsandbox {
    fn load() -> Result<Self, &'static str> {
        load_libsandbox();
        let get = |name: &'static str| resolve(name).ok_or(name);
        // SAFETY: each pointer was resolved by name from Apple's libraries and
        // is transmuted to the signature Chromium and WebKit declare for it
        // (the same signatures procage's kernel facts exercise).
        unsafe {
            Ok(Self {
                compile_string: std::mem::transmute::<*mut c_void, CompileString>(get(
                    "sandbox_compile_string",
                )?),
                free_profile: std::mem::transmute::<*mut c_void, FreeProfile>(get(
                    "sandbox_free_profile",
                )?),
                create_params: std::mem::transmute::<*mut c_void, CreateParams>(get(
                    "sandbox_create_params",
                )?),
                set_param: std::mem::transmute::<*mut c_void, SetParam>(get("sandbox_set_param")?),
                free_params: std::mem::transmute::<*mut c_void, FreeParams>(get(
                    "sandbox_free_params",
                )?),
                issue_file: std::mem::transmute::<*mut c_void, IssueFile>(get(
                    "sandbox_extension_issue_file",
                )?),
                child: ChildOps {
                    mac_syscall: std::mem::transmute::<*mut c_void, MacSyscall>(get(
                        "__mac_syscall",
                    )?),
                    check: std::mem::transmute::<*mut c_void, Check>(get("sandbox_check")?),
                    consume: std::mem::transmute::<*mut c_void, Consume>(get(
                        "sandbox_extension_consume",
                    )?),
                },
            })
        }
    }

    /// The table, resolved once per process; `Err` names the first missing
    /// symbol.
    pub(crate) fn get() -> Result<&'static Libsandbox, &'static str> {
        static TABLE: OnceLock<Result<Libsandbox, &'static str>> = OnceLock::new();
        TABLE.get_or_init(Libsandbox::load).as_ref().map_err(|e| *e)
    }

    /// Compiles SBPL with `(param …)` values; `Err` holds libsandbox's error
    /// text, if it set one.
    pub(crate) fn compile(
        &self,
        sbpl: &str,
        params: &[(String, String)],
    ) -> Result<Vec<u8>, Option<String>> {
        let source =
            CString::new(sbpl).map_err(|_| Some("profile contains a NUL byte".to_string()))?;
        let owned = params
            .iter()
            .map(|(k, v)| Ok((CString::new(k.as_str())?, CString::new(v.as_str())?)))
            .collect::<Result<Vec<_>, std::ffi::NulError>>()
            .map_err(|_| Some("parameter contains a NUL byte".to_string()))?;
        let mut err: *mut c_char = std::ptr::null_mut();
        // SAFETY: the params object is created, filled with pointers into
        // `owned` (alive until after the compile) and freed here; `err` is a
        // valid out-pointer pre-set to NULL.
        let profile = unsafe {
            let p = if owned.is_empty() {
                std::ptr::null_mut()
            } else {
                (self.create_params)()
            };
            for (k, v) in &owned {
                (self.set_param)(p, k.as_ptr(), v.as_ptr());
            }
            let profile = (self.compile_string)(source.as_ptr(), p, &raw mut err);
            if !p.is_null() {
                (self.free_params)(p);
            }
            profile
        };
        if profile.is_null() {
            if err.is_null() {
                return Err(None);
            }
            // SAFETY: libsandbox sets `err` to a NUL-terminated string it
            // allocated with malloc; it is copied, then freed once.
            let text = unsafe {
                let text = CStr::from_ptr(err).to_string_lossy().into_owned();
                libc::free(err.cast());
                text
            };
            return Err(Some(text));
        }
        // SAFETY: a non-null profile points to a valid struct whose `data`
        // holds `size` bytes until sandbox_free_profile, called once here.
        unsafe {
            let p = &*profile;
            let data = if p.data.is_null() {
                Vec::new()
            } else {
                std::slice::from_raw_parts(p.data, p.size).to_vec()
            };
            (self.free_profile)(profile);
            Ok(data)
        }
    }

    /// Issues a file extension token of `class` for `path`.
    pub(crate) fn issue_file(&self, class: &str, path: &[u8]) -> Option<CString> {
        let class = CString::new(class).ok()?;
        let path = CString::new(path).ok()?;
        // SAFETY: both arguments are NUL-terminated; a non-null result is a
        // malloc'd NUL-terminated token that is copied and freed once.
        unsafe {
            let token = (self.issue_file)(class.as_ptr(), path.as_ptr(), 0);
            if token.is_null() {
                return None;
            }
            let owned = CStr::from_ptr(token).to_owned();
            libc::free(token.cast());
            Some(owned)
        }
    }

    /// Whether the calling process is sandboxed.
    pub(crate) fn is_sandboxed(&self) -> bool {
        self.child.verify().is_ok()
    }

    /// Whether the sandbox of process `pid` allows looking up the service
    /// `name`: `sandbox_check(pid, "mach-lookup", SANDBOX_FILTER_GLOBAL_NAME,
    /// name)`, an undocumented form (measured on 26.6.2). An unsandboxed
    /// process allows every name. `Err` carries errno when the call fails.
    pub(crate) fn allows_lookup(&self, pid: libc::pid_t, name: &CStr) -> Result<bool, i32> {
        // SAFETY: both strings are NUL-terminated and alive for the call; the
        // global-name filter takes exactly one string argument.
        let rc = unsafe {
            (self.child.check)(
                pid,
                c"mach-lookup".as_ptr(),
                SANDBOX_FILTER_GLOBAL_NAME,
                name.as_ptr(),
            )
        };
        match rc {
            0 => Ok(true),
            1 => Ok(false),
            _ => Err(errno()),
        }
    }

    /// The pointers the child uses.
    pub(crate) fn child_ops(&self) -> ChildOps {
        self.child
    }
}

/// The calling thread's `errno`.
fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

impl ChildOps {
    /// Applies `bytecode` to the calling process (path A). A system call.
    pub(crate) fn apply(&self, bytecode: &[u8]) -> Result<(), i32> {
        let mut args = ApplyArgs {
            data: bytecode.as_ptr(),
            size: bytecode.len(),
            container: std::ptr::null(),
            container_len: 0,
        };
        // SAFETY: `args` lives on this stack frame and points to bytecode
        // that outlives the call; the kernel copies what it needs.
        let rc = unsafe { (self.mac_syscall)(c"Sandbox".as_ptr(), 0, (&raw mut args).cast()) };
        if rc == 0 { Ok(()) } else { Err(errno()) }
    }

    /// `sandbox_check(getpid(), NULL, 0) == 1`: the calling process is
    /// sandboxed. `Err` carries errno when it is not (0 if errno is unset).
    pub(crate) fn verify(&self) -> Result<(), i32> {
        // SAFETY: getpid is a system call; the no-operation form of
        // sandbox_check takes no variadic argument.
        let rc = unsafe { (self.check)(libc::getpid(), std::ptr::null(), 0) };
        if rc == 1 { Ok(()) } else { Err(errno()) }
    }

    /// Consumes an extension token in the calling process.
    pub(crate) fn consume(&self, token: &CStr) -> Result<(), i32> {
        // SAFETY: `token` is NUL-terminated and alive for the call.
        let handle = unsafe { (self.consume)(token.as_ptr()) };
        if handle >= 0 {
            Ok(())
        } else {
            Err(errno().max(1))
        }
    }
}

/// `setsid()`.
pub(crate) fn setsid() -> Result<(), i32> {
    // SAFETY: a plain system call.
    if unsafe { libc::setsid() } < 0 {
        Err(errno())
    } else {
        Ok(())
    }
}

/// `setpgid(0, 0)`: a new process group led by the caller.
pub(crate) fn setpgid_self() -> Result<(), i32> {
    // SAFETY: a plain system call.
    if unsafe { libc::setpgid(0, 0) } == 0 {
        Ok(())
    } else {
        Err(errno())
    }
}

/// `setrlimit(resource, {cur, max})`.
pub(crate) fn setrlimit(resource: c_int, cur: u64, max: u64) -> Result<(), i32> {
    let lim = libc::rlimit {
        rlim_cur: cur,
        rlim_max: max,
    };
    // SAFETY: a plain system call with a pointer to a stack value.
    if unsafe { libc::setrlimit(resource, &raw const lim) } == 0 {
        Ok(())
    } else {
        Err(errno())
    }
}

/// `getrlimit(resource)` as `(cur, max)`.
pub(crate) fn getrlimit(resource: c_int) -> Option<(u64, u64)> {
    let mut lim = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: a plain system call writing into a stack value.
    (unsafe { libc::getrlimit(resource, &raw mut lim) } == 0)
        .then_some((lim.rlim_cur, lim.rlim_max))
}

/// Whether the calling process leads its own session.
pub(crate) fn is_session_leader() -> bool {
    // SAFETY: plain system calls.
    unsafe { libc::getsid(0) == libc::getpid() }
}

/// Whether the calling process leads its own process group.
pub(crate) fn is_group_leader() -> bool {
    // SAFETY: plain system calls.
    unsafe { libc::getpgid(0) == libc::getpid() }
}

/// Opens `path` read-only and closes it again; `Err` carries errno. A system
/// call, used by the probe's canary.
pub(crate) fn open_readonly(path: &CStr) -> Result<(), i32> {
    // SAFETY: `path` is NUL-terminated; the descriptor is closed at once.
    let fd = unsafe { libc::open(path.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
    if fd < 0 {
        return Err(errno());
    }
    // SAFETY: `fd` was just opened by this function.
    unsafe { libc::close(fd) };
    Ok(())
}

/// Marker of a step code: `0x5043_0000 | step << 12 | errno`.
pub(crate) const STEP_MARKER: i32 = 0x5043_0000;

/// A step code for the child to return through std's error channel.
pub(crate) const fn step_code(step: u32, errno: i32) -> i32 {
    STEP_MARKER | ((step as i32 & 0xf) << 12) | (errno & 0xfff)
}

/// Decodes a step code: `(step, errno)`.
pub(crate) fn decode_step(code: i32) -> Option<(u32, i32)> {
    ((code as u32 & 0xffff_0000) == STEP_MARKER as u32)
        .then_some((((code >> 12) & 0xf) as u32, code & 0xfff))
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

/// One past the highest signal number (`NSIG`).
const SIGNALS: c_int = 32;

/// Resets every ignored signal to its default action. An ignored
/// disposition survives `execve`, so a caller that ignores `SIGCHLD` would
/// hand that to the child. Caught signals need nothing: `execve` resets
/// them. System calls only.
fn reset_ignored_signals() -> Result<(), i32> {
    for sig in 1..SIGNALS {
        if sig == libc::SIGKILL || sig == libc::SIGSTOP || !signal_ignored(sig) {
            continue;
        }
        // SAFETY: an all-zero sigaction is a valid value to fill in.
        let mut default: libc::sigaction = unsafe { std::mem::zeroed() };
        default.sa_sigaction = libc::SIG_DFL;
        // SAFETY: sigaction reads a struct on our stack.
        if unsafe { libc::sigaction(sig, &raw const default, std::ptr::null_mut()) } != 0 {
            return Err(errno());
        }
    }
    Ok(())
}

/// Whether `sig` is ignored in the calling process.
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
    pub(crate) ops: ChildOps,
    pub(crate) bytecode: std::sync::Arc<[u8]>,
    pub(crate) tokens: Vec<CString>,
    pub(crate) limits: Vec<(c_int, u64, u64)>,
    pub(crate) session: Session,
    /// Descriptors handed to the child (close-on-exec cleared).
    pub(crate) keep: Vec<c_int>,
    /// Buffer for `proc_pidinfo(PROC_PIDLISTFDS)`, allocated in the parent.
    pub(crate) fd_buffer: Vec<libc::proc_fdinfo>,
}

/// Step numbers of [`ChildPlan::run`]; they match `super::Step`.
pub(crate) mod steps {
    pub(crate) const SESSION: u32 = 1;
    pub(crate) const RLIMIT: u32 = 2;
    pub(crate) const APPLY: u32 = 3;
    pub(crate) const VERIFY: u32 = 4;
    pub(crate) const CONSUME: u32 = 5;
    pub(crate) const FDS: u32 = 6;
}

/// `fcntl(fd, F_SETFD, flags)`.
fn set_fd_flags(fd: c_int, flags: c_int) -> Result<(), i32> {
    // SAFETY: a plain system call on an integer descriptor.
    if unsafe { libc::fcntl(fd, libc::F_SETFD, flags) } == 0 {
        Ok(())
    } else {
        Err(errno())
    }
}

/// Marks every descriptor >= 3 close-on-exec except `keep`, and clears the
/// flag on `keep`. Lists the open descriptors with `proc_pidinfo` into
/// `buf`; when the list fails or may be truncated, sweeps every number up to
/// `getdtablesize()`. System calls only, no allocation.
fn mark_fds(buf: &mut [libc::proc_fdinfo], keep: &[c_int]) -> Result<(), i32> {
    let mark = |fd: c_int| {
        if fd < 3 || keep.contains(&fd) {
            return Ok(());
        }
        match set_fd_flags(fd, libc::FD_CLOEXEC) {
            Err(libc::EBADF) | Ok(()) => Ok(()),
            Err(e) => Err(e),
        }
    };
    let size = std::mem::size_of_val(buf);
    // SAFETY: getpid is a system call; proc_pidinfo writes at most `size`
    // bytes into `buf`, which the parent allocated and the closure owns.
    let filled = unsafe {
        libc::proc_pidinfo(
            libc::getpid(),
            libc::PROC_PIDLISTFDS,
            0,
            buf.as_mut_ptr().cast(),
            c_int::try_from(size).unwrap_or(c_int::MAX),
        )
    };
    let entry = std::mem::size_of::<libc::proc_fdinfo>();
    match usize::try_from(filled) {
        Ok(bytes) if bytes > 0 && bytes + entry <= size => {
            for info in &buf[..bytes / entry] {
                mark(info.proc_fd)?;
            }
        }
        _ => {
            // SAFETY: a plain system call.
            let table = unsafe { libc::getdtablesize() };
            for fd in 3..table {
                mark(fd)?;
            }
        }
    }
    for &fd in keep {
        set_fd_flags(fd, 0)?;
    }
    Ok(())
}

/// A buffer for the child's descriptor listing: twice the caller's current
/// descriptor count plus 1,024 entries.
pub(crate) fn fd_buffer() -> Vec<libc::proc_fdinfo> {
    // SAFETY: with a null buffer proc_pidinfo only returns the size needed.
    let needed = unsafe {
        libc::proc_pidinfo(
            libc::getpid(),
            libc::PROC_PIDLISTFDS,
            0,
            std::ptr::null_mut(),
            0,
        )
    };
    let entries = usize::try_from(needed).unwrap_or(0) / std::mem::size_of::<libc::proc_fdinfo>();
    vec![
        libc::proc_fdinfo {
            proc_fd: 0,
            proc_fdtype: 0
        };
        entries * 2 + 1024
    ]
}

/// Whether `fd` is an open descriptor of the calling process.
pub(crate) fn fd_is_open(fd: c_int) -> bool {
    // SAFETY: a plain system call on an integer descriptor.
    unsafe { libc::fcntl(fd, libc::F_GETFD) != -1 }
}

/// Clears close-on-exec on `fd` (for tests that need an inheritable fd).
pub(crate) fn clear_cloexec(fd: c_int) -> Result<(), i32> {
    set_fd_flags(fd, 0)
}

/// Whether process `pid` exists (signal 0).
pub(crate) fn alive(pid: libc::pid_t) -> bool {
    // SAFETY: kill with signal 0 only checks for existence.
    unsafe { libc::kill(pid, 0) == 0 || errno() == libc::EPERM }
}

/// The child processes of `pid`.
fn children(pid: libc::pid_t) -> Vec<libc::pid_t> {
    let mut buf = vec![0 as libc::pid_t; 256];
    loop {
        let bytes = c_int::try_from(std::mem::size_of_val(buf.as_slice())).unwrap_or(c_int::MAX);
        // SAFETY: proc_listchildpids writes at most `bytes` bytes into `buf`.
        let n = unsafe { libc::proc_listchildpids(pid, buf.as_mut_ptr().cast(), bytes) };
        let Ok(n) = usize::try_from(n) else {
            return Vec::new();
        };
        // The call returns the number of pids on macOS.
        if n < buf.len() {
            buf.truncate(n);
            return buf;
        }
        buf.resize(buf.len() * 2, 0);
    }
}

/// Every descendant of `pid` that can be found from it, repeating the walk
/// until it is stable (at most 8 rounds).
pub(crate) fn descendants(pid: libc::pid_t) -> Vec<libc::pid_t> {
    let mut found: Vec<libc::pid_t> = Vec::new();
    for _ in 0..8 {
        let before = found.len();
        let mut queue = vec![pid];
        while let Some(p) = queue.pop() {
            for c in children(p) {
                if c > 0 && !found.contains(&c) {
                    found.push(c);
                }
                if c > 0 {
                    queue.push(c);
                }
            }
        }
        if found.len() == before {
            break;
        }
    }
    found
}

/// Every process id the kernel lists. `Err` carries errno.
pub(crate) fn all_pids() -> Result<Vec<libc::pid_t>, i32> {
    let mut buf = vec![0 as libc::pid_t; 1024];
    loop {
        let bytes = c_int::try_from(std::mem::size_of_val(buf.as_slice())).unwrap_or(c_int::MAX);
        // SAFETY: proc_listallpids writes at most `bytes` bytes into `buf`.
        let n = unsafe { libc::proc_listallpids(buf.as_mut_ptr().cast(), bytes) };
        let Ok(n) = usize::try_from(n) else {
            return Err(errno());
        };
        // The call returns the number of pids; a full buffer may be cut short.
        if n < buf.len() {
            buf.truncate(n);
            return Ok(buf);
        }
        buf.resize(buf.len() * 2, 0);
    }
}

/// Whether `pid` is a process of the calling user that is not a zombie.
/// `false` when it is gone or its information is not readable.
pub(crate) fn live_of_user(pid: libc::pid_t) -> bool {
    let size = c_int::try_from(std::mem::size_of::<libc::proc_bsdinfo>()).unwrap_or(c_int::MAX);
    // SAFETY: proc_bsdinfo is plain data, valid when zeroed.
    let mut info: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
    let buf = (&raw mut info).cast();
    // SAFETY: proc_pidinfo writes at most `size` bytes into `info`.
    let n = unsafe { libc::proc_pidinfo(pid, libc::PROC_PIDTBSDINFO, 0, buf, size) };
    // SAFETY: getuid is a system call without arguments.
    let uid = unsafe { libc::getuid() };
    n == size && info.pbi_uid == uid && info.pbi_status != libc::SZOMB
}

/// Whether the volume holding the existing path `path` tells names apart
/// by case (`pathconf(_PC_CASE_SENSITIVE)`); `None` when it cannot say.
pub(crate) fn case_sensitive(path: &CStr) -> Option<bool> {
    // SAFETY: pathconf with a NUL-terminated path.
    let rc = unsafe { libc::pathconf(path.as_ptr(), libc::_PC_CASE_SENSITIVE) };
    match rc {
        1 => Some(true),
        0 => Some(false),
        _ => None,
    }
}

/// The real uid.
pub(crate) fn uid() -> u32 {
    // SAFETY: getuid is a system call without arguments.
    unsafe { libc::getuid() }
}

/// Sends SIGKILL to `pid`.
pub(crate) fn kill(pid: libc::pid_t) {
    // SAFETY: a plain system call.
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

/// The session of `pid`, or `None` when it is gone.
pub(crate) fn session_of(pid: libc::pid_t) -> Option<libc::pid_t> {
    // SAFETY: a system call without pointers.
    let sid = unsafe { libc::getsid(pid) };
    (sid >= 0).then_some(sid)
}

/// Sends SIGKILL to process group `pgid`.
pub(crate) fn killpg(pgid: libc::pid_t) {
    // SAFETY: a plain system call.
    unsafe { libc::killpg(pgid, libc::SIGKILL) };
}

/// Whether `path` lies on a volume mounted read-only (`statfs`
/// `MNT_RDONLY`), such as the sealed system volume.
pub(crate) fn on_read_only_volume(path: &CStr) -> Result<bool, i32> {
    let mut fs = std::mem::MaybeUninit::<libc::statfs>::uninit();
    // SAFETY: `path` is NUL-terminated; statfs fills the buffer on success.
    if unsafe { libc::statfs(path.as_ptr(), fs.as_mut_ptr()) } == -1 {
        return Err(errno());
    }
    // SAFETY: statfs returned 0, so the buffer is initialised.
    let fs = unsafe { fs.assume_init() };
    Ok(fs.f_flags & libc::MNT_RDONLY as u32 != 0)
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

/// Spawns `/bin/sleep 30`, in a new session when `setsid`; returns its pid
/// (for lifetime tests).
pub(crate) fn spawn_sleeper(setsid_first: bool) -> std::io::Result<u32> {
    use std::os::unix::process::CommandExt;
    let mut command = std::process::Command::new("/bin/sleep");
    // Inherited stdio: a caged caller may not be allowed to open /dev/null.
    command.arg("30");
    if setsid_first {
        // SAFETY: the closure only calls setsid, a system call.
        unsafe {
            command.pre_exec(|| setsid().map_err(std::io::Error::from_raw_os_error));
        }
    }
    let child = command.spawn()?;
    Ok(child.id())
}

impl ChildPlan {
    /// The in-child sequence. Only system calls (and libsandbox functions
    /// that issue them without allocating or locking) on data prepared in
    /// the parent; the error value is built from integers.
    fn run(&mut self) -> std::io::Result<()> {
        let fail =
            |step: u32, errno: i32| std::io::Error::from_raw_os_error(step_code(step, errno));
        if self.session.fresh() {
            reset_ignored_signals().map_err(|e| fail(steps::SESSION, e))?;
        }
        match self.session {
            Session::New => setsid().map_err(|e| fail(steps::SESSION, e))?,
            Session::Group => setpgid_self().map_err(|e| fail(steps::SESSION, e))?,
            Session::Keep => {}
            Session::Lead => {
                if !leads().0 {
                    setsid().map_err(|e| fail(steps::SESSION, e))?;
                }
            }
            Session::Terminal => {
                setsid().map_err(|e| fail(steps::SESSION, e))?;
                match ioctl_errno(0, libc::TIOCSCTTY as _) {
                    0 => {}
                    e => return Err(fail(steps::SESSION, e)),
                }
            }
        }
        for &(resource, cur, max) in &self.limits {
            setrlimit(resource, cur, max).map_err(|e| fail(steps::RLIMIT, e))?;
        }
        mark_fds(&mut self.fd_buffer, &self.keep).map_err(|e| fail(steps::FDS, e))?;
        self.ops
            .apply(&self.bytecode)
            .map_err(|e| fail(steps::APPLY, e))?;
        self.ops.verify().map_err(|e| fail(steps::VERIFY, e))?;
        for token in &self.tokens {
            self.ops
                .consume(token)
                .map_err(|e| fail(steps::CONSUME, e))?;
        }
        Ok(())
    }

    /// Makes `command` run this plan in the child before `execve`.
    pub(crate) fn install(self, command: &mut std::process::Command) {
        use std::os::unix::process::CommandExt;
        let mut plan = self;
        // SAFETY: `run` issues only system calls (sigaction, setsid or setpgid,
        // setrlimit, proc_info through proc_pidinfo, fcntl, getdtablesize,
        // __mac_syscall, getpid) and the libsandbox functions sandbox_check
        // and sandbox_extension_consume, which issue system calls without
        // allocating or locking (verified by disassembly on 26.6.2 and by
        // the multithreaded spawn test). Everything it reads was allocated
        // in the parent and is owned by the closure.
        unsafe {
            command.pre_exec(move || plan.run());
        }
    }
}

/// Runs `check` in the child before `execve` and turns `Ok(true)` into the
/// probe marker, so the child never executes. Used by the apply-method probe.
pub(crate) fn install_probe(
    command: &mut std::process::Command,
    ops: ChildOps,
    bytecode: std::sync::Arc<[u8]>,
) {
    use std::os::unix::process::CommandExt;
    let canary = c"/private/etc/hosts";
    // SAFETY: as for `ChildPlan::install`; the canary `open` is a system call
    // on a static string.
    unsafe {
        command.pre_exec(move || {
            let fail =
                |step: u32, errno: i32| std::io::Error::from_raw_os_error(step_code(step, errno));
            ops.apply(&bytecode).map_err(|e| fail(steps::APPLY, e))?;
            ops.verify().map_err(|e| fail(steps::VERIFY, e))?;
            match open_readonly(canary) {
                Err(libc::EPERM) => Err(fail(PROBE_OK, 0)),
                Err(e) => Err(fail(PROBE_CANARY, e)),
                Ok(()) => Err(fail(PROBE_CANARY, 0)),
            }
        });
    }
}

/// Makes `command`'s child a violation fence: it applies `bytecode` (a
/// deny-default profile whose message is the fence marker), is denied
/// opening `/`, which the kernel logs, and exits with status 0 without
/// executing anything. The spawn then succeeds and gives the fence's pid.
pub(crate) fn install_fence(
    command: &mut std::process::Command,
    ops: ChildOps,
    bytecode: std::sync::Arc<[u8]>,
) {
    use std::os::unix::process::CommandExt;
    // SAFETY: as for `ChildPlan::install`: `__mac_syscall`, `open` on a
    // static string and `_exit` are system calls; the bytecode was allocated
    // in the parent and is owned by the closure.
    unsafe {
        command.pre_exec(move || {
            let code = match ops.apply(&bytecode) {
                Ok(()) => i32::from(open_readonly(c"/").is_ok()),
                Err(_) => 2,
            };
            libc::_exit(code)
        });
    }
}

/// Probe step: everything held.
pub(crate) const PROBE_OK: u32 = 0xe;
/// Probe step: the canary was not denied with EPERM.
pub(crate) const PROBE_CANARY: u32 = 0xd;

/// Loops `dlopen`/`dlsym`/`dlclose` until `stop` is set, to contend for
/// dyld's locks while another thread forks (for the multithreaded test).
pub(crate) fn dyld_churn(stop: &std::sync::atomic::AtomicBool) {
    while !stop.load(std::sync::atomic::Ordering::Relaxed) {
        // SAFETY: dlopen/dlsym/dlclose on a system library by absolute path;
        // the symbol is only compared with null, never called.
        unsafe {
            let handle = libc::dlopen(c"/usr/lib/libz.1.dylib".as_ptr(), libc::RTLD_NOW);
            if !handle.is_null() {
                let _ = libc::dlsym(handle, c"zlibVersion".as_ptr());
                libc::dlclose(handle);
            }
        }
    }
}

// ---- Probes for the escape suite (procage's tests only) ----

// SAFETY: libSystem's bootstrap and Mach declarations, with the C types of
// <servers/bootstrap.h> and <mach/mach_port.h>.
unsafe extern "C" {
    static bootstrap_port: libc::mach_port_t;
    static mach_task_self_: libc::mach_port_t;
    fn bootstrap_look_up(
        bp: libc::mach_port_t,
        name: *const c_char,
        sp: *mut libc::mach_port_t,
    ) -> libc::kern_return_t;
    fn mach_port_deallocate(
        task: libc::mach_port_t,
        name: libc::mach_port_t,
    ) -> libc::kern_return_t;
}

/// Looks up the Mach service `name`; the `kern_return_t` (0: found). The
/// port is released at once: a lookup sends nothing to the service.
pub(crate) fn mach_lookup(name: &CStr) -> i32 {
    let mut port: libc::mach_port_t = 0;
    // SAFETY: `name` is NUL-terminated; `port` is a local out-parameter;
    // the statics are set by libSystem before main.
    unsafe {
        let kr = bootstrap_look_up(bootstrap_port, name.as_ptr(), &raw mut port);
        if kr == 0 {
            mach_port_deallocate(mach_task_self_, port);
        }
        kr
    }
}

/// `fcntl(fd, cmd, 0)`; the errno, or 0 on success.
pub(crate) fn fcntl_errno(fd: c_int, cmd: c_int) -> i32 {
    // SAFETY: an integer command with a zero argument.
    if unsafe { libc::fcntl(fd, cmd, 0) } == -1 {
        errno()
    } else {
        0
    }
}

/// Reads `KERN_PROCARGS2` (argv and environment) of `pid`; the errno, or 0.
pub(crate) fn procargs_errno(pid: libc::pid_t) -> i32 {
    procargs_query_errno(libc::KERN_PROCARGS2, pid)
}

/// Reads `KERN_PROCARGS` (the older argument query) of `pid`; the errno, or 0.
pub(crate) fn procargs1_errno(pid: libc::pid_t) -> i32 {
    procargs_query_errno(libc::KERN_PROCARGS, pid)
}

/// `proc_pidinfo(pid, PROC_PIDTBSDINFO)`: 0 when it gives the process's
/// information, else the errno (EPERM when the sandbox refuses).
pub(crate) fn pidinfo_errno(pid: libc::pid_t) -> i32 {
    let mut info = std::mem::MaybeUninit::<libc::proc_bsdinfo>::uninit();
    let size = c_int::try_from(std::mem::size_of::<libc::proc_bsdinfo>()).unwrap_or(c_int::MAX);
    // SAFETY: `info` is a buffer of `size` bytes for the result.
    let n = unsafe {
        libc::proc_pidinfo(
            pid,
            libc::PROC_PIDTBSDINFO,
            0,
            info.as_mut_ptr().cast(),
            size,
        )
    };
    if n == size {
        0
    } else {
        errno().max(libc::EPERM)
    }
}

fn procargs_query_errno(query: c_int, pid: libc::pid_t) -> i32 {
    let mut mib = [libc::CTL_KERN, query, pid];
    let mut buf = vec![0u8; 1 << 20];
    let mut len = buf.len();
    // SAFETY: `mib` has three entries; `buf` is `len` bytes long.
    let rc = unsafe {
        libc::sysctl(
            mib.as_mut_ptr(),
            3,
            buf.as_mut_ptr().cast(),
            &raw mut len,
            std::ptr::null_mut(),
            0,
        )
    };
    if rc == 0 { 0 } else { errno() }
}

/// `kill(pid, sig)`; the errno, or 0.
pub(crate) fn kill_errno(pid: libc::pid_t, sig: c_int) -> i32 {
    // SAFETY: a plain system call.
    if unsafe { libc::kill(pid, sig) } == 0 {
        0
    } else {
        errno()
    }
}

/// A new pseudo-terminal: the controller, the other end (the device) and
/// the device's path. Every descriptor is close-on-exec from the start, and
/// the window is 80 columns by 24 rows.
pub(crate) fn open_terminal() -> std::io::Result<(
    std::os::fd::OwnedFd,
    std::os::fd::OwnedFd,
    std::path::PathBuf,
)> {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::os::unix::ffi::OsStrExt;
    let last = std::io::Error::last_os_error;
    // SAFETY: a plain call with flags; the descriptor is ours.
    let fd = unsafe { libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY | libc::O_CLOEXEC) };
    if fd < 0 {
        return Err(last());
    }
    // SAFETY: a fresh descriptor we own.
    let controller = unsafe { OwnedFd::from_raw_fd(fd) };
    let mut name = [0 as c_char; 128];
    // SAFETY: plain calls on our descriptor; TIOCPTYGNAME writes at most
    // 128 bytes, the size of `name`, NUL-terminated.
    let rc = unsafe {
        if libc::grantpt(fd) != 0 || libc::unlockpt(fd) != 0 {
            -1
        } else {
            libc::ioctl(fd, libc::TIOCPTYGNAME as _, name.as_mut_ptr())
        }
    };
    if rc != 0 {
        return Err(last());
    }
    // SAFETY: the name is NUL-terminated within the buffer.
    let name = unsafe { CStr::from_ptr(name.as_ptr()) };
    // SAFETY: open with a NUL-terminated path; the descriptor is ours.
    let device = unsafe {
        libc::open(
            name.as_ptr(),
            libc::O_RDWR | libc::O_NOCTTY | libc::O_CLOEXEC,
        )
    };
    if device < 0 {
        return Err(last());
    }
    // SAFETY: a fresh descriptor we own.
    let device = unsafe { OwnedFd::from_raw_fd(device) };
    set_window(controller.as_raw_fd(), 24, 80)?;
    Ok((
        controller,
        device,
        std::ffi::OsStr::from_bytes(name.to_bytes()).into(),
    ))
}

/// A new pseudo-terminal: the controller and the device path of the other
/// end (closed).
pub(crate) fn open_pty() -> std::io::Result<(std::os::fd::OwnedFd, std::path::PathBuf)> {
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
    // SAFETY: the ioctl reads the structure on this frame.
    if unsafe { libc::ioctl(fd, libc::TIOCSWINSZ, &raw const size) } == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

/// `ioctl(fd, request)` without an argument; the errno, or 0.
pub(crate) fn ioctl_errno(fd: c_int, request: libc::c_ulong) -> i32 {
    // SAFETY: requests that take no argument (TIOCSCTTY's is ignored).
    if unsafe { libc::ioctl(fd, request, 0) } == -1 {
        errno()
    } else {
        0
    }
}

/// `ioctl(fd, TIOCSTI, &byte)`: pushes one byte into a terminal's input.
pub(crate) fn tiocsti_errno(fd: c_int, byte: u8) -> i32 {
    let c = byte as c_char;
    // SAFETY: TIOCSTI reads one byte from the pointer.
    if unsafe { libc::ioctl(fd, libc::TIOCSTI, &raw const c) } == -1 {
        errno()
    } else {
        0
    }
}
