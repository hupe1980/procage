//! libsandbox, `__mac_syscall`, sysctl and terminal calls on macOS.
//!
//! The private libsandbox symbols are resolved at runtime with `dlsym`, so a
//! symbol Apple removes shows up as a named error instead of a load failure.

use std::ffi::{CStr, CString, c_char, c_int, c_void};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use super::errno;

/// `sandbox_profile_t` as returned by `sandbox_compile_*`.
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
type Apply = unsafe extern "C" fn(*mut Profile) -> c_int;
type MacSyscall = unsafe extern "C" fn(*const c_char, c_int, *mut c_void) -> c_int;
type Check = unsafe extern "C" fn(libc::pid_t, *const c_char, c_int, ...) -> c_int;
type IssueFile = unsafe extern "C" fn(*const c_char, *const c_char, u32) -> *mut c_char;
type Consume = unsafe extern "C" fn(*const c_char) -> i64;
type Release = unsafe extern "C" fn(i64) -> c_int;

/// The library the compiler lives in.
const LIBSANDBOX: &CStr = c"/usr/lib/libsandbox.1.dylib";

/// Every symbol [`Sandbox::load`] resolves, in order.
pub const SYMBOLS: &[&str] = &[
    "sandbox_compile_string",
    "sandbox_free_profile",
    "sandbox_create_params",
    "sandbox_set_param",
    "sandbox_free_params",
    "sandbox_apply",
    "__mac_syscall",
    "sandbox_check",
    "SANDBOX_CHECK_NO_REPORT",
    "sandbox_extension_issue_file",
    "sandbox_extension_consume",
    "sandbox_extension_release",
];

/// `sandbox_check` filter type for a path argument.
const FILTER_PATH: c_int = 1;
/// `sandbox_check` filter type for a global (Mach) name argument.
const FILTER_GLOBAL_NAME: c_int = 2;

/// Resolves `name` in every loaded image.
fn resolve(name: &str) -> Option<*mut c_void> {
    let cname = CString::new(name).ok()?;
    // SAFETY: dlsym with RTLD_DEFAULT and a NUL-terminated name only reads.
    let p = unsafe { libc::dlsym(libc::RTLD_DEFAULT, cname.as_ptr()) };
    (!p.is_null()).then_some(p)
}

/// Resolves `name`, or returns the name as the error.
fn require(name: &'static str) -> Result<*mut c_void, &'static str> {
    resolve(name).ok_or(name)
}

/// The names in [`SYMBOLS`] that do not resolve after loading libsandbox.
pub fn missing_symbols() -> Vec<&'static str> {
    load_libsandbox();
    SYMBOLS
        .iter()
        .copied()
        .filter(|s| resolve(s).is_none())
        .collect()
}

fn load_libsandbox() {
    // SAFETY: dlopen of a system library by absolute path; the handle is kept
    // for the life of the process (never dlclosed).
    unsafe { libc::dlopen(LIBSANDBOX.as_ptr(), libc::RTLD_NOW | libc::RTLD_GLOBAL) };
}

/// A compiled profile: the bytecode, copied out of libsandbox.
#[derive(Debug, Clone)]
pub struct Bytecode {
    /// The bytecode bytes.
    pub data: Vec<u8>,
    /// Whether the compiler returned no builtin (named) profile.
    pub builtin_null: bool,
}

/// A failed compile.
#[derive(Debug, Clone)]
pub struct CompileError {
    /// The error text, if libsandbox set one.
    pub text: Option<String>,
}

/// The resolved libsandbox interface.
pub struct Sandbox {
    compile_string: CompileString,
    free_profile: FreeProfile,
    create_params: CreateParams,
    set_param: SetParam,
    free_params: FreeParams,
    apply: Apply,
    mac_syscall: MacSyscall,
    check: Check,
    check_no_report: c_int,
    issue_file: IssueFile,
    consume: Consume,
    release: Release,
}

impl Sandbox {
    /// Loads libsandbox and resolves every symbol, or names the first missing one.
    pub fn load() -> Result<Self, &'static str> {
        load_libsandbox();
        let get = require;
        // SAFETY: each pointer was resolved by name from Apple's libraries and
        // is transmuted to the signature Chromium and WebKit declare for it.
        // SANDBOX_CHECK_NO_REPORT is an exported `int` variable, read once.
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
                apply: std::mem::transmute::<*mut c_void, Apply>(get("sandbox_apply")?),
                mac_syscall: std::mem::transmute::<*mut c_void, MacSyscall>(get("__mac_syscall")?),
                check: std::mem::transmute::<*mut c_void, Check>(get("sandbox_check")?),
                check_no_report: *(get("SANDBOX_CHECK_NO_REPORT")? as *const c_int),
                issue_file: std::mem::transmute::<*mut c_void, IssueFile>(get(
                    "sandbox_extension_issue_file",
                )?),
                consume: std::mem::transmute::<*mut c_void, Consume>(get(
                    "sandbox_extension_consume",
                )?),
                release: std::mem::transmute::<*mut c_void, Release>(get(
                    "sandbox_extension_release",
                )?),
            })
        }
    }

    /// Compiles SBPL with optional `(param …)` values.
    pub fn compile(&self, sbpl: &str, params: &[(&str, &str)]) -> Result<Bytecode, CompileError> {
        let mut err: *mut c_char = std::ptr::null_mut();
        let profile = self.compile_raw(sbpl, params, &mut err);
        self.finish(profile, err)
    }

    /// Compiles valid SBPL with the error slot pre-set to a sentinel and
    /// reports whether the sentinel survived a successful compile.
    pub fn compile_keeps_error_slot(&self, sbpl: &str) -> Option<bool> {
        static SENTINEL: u8 = 0;
        let sentinel = (&raw const SENTINEL).cast::<c_char>().cast_mut();
        let mut err = sentinel;
        let profile = self.compile_raw(sbpl, &[], &mut err);
        if profile.is_null() {
            return None;
        }
        // SAFETY: profile is the non-null result of sandbox_compile_string.
        unsafe { (self.free_profile)(profile) };
        Some(err == sentinel)
    }

    fn compile_raw(
        &self,
        sbpl: &str,
        params: &[(&str, &str)],
        err: &mut *mut c_char,
    ) -> *mut Profile {
        let source = CString::new(sbpl).expect("SBPL without NUL");
        let owned: Vec<(CString, CString)> = params
            .iter()
            .map(|(k, v)| {
                (
                    CString::new(*k).expect("key"),
                    CString::new(*v).expect("value"),
                )
            })
            .collect();
        // SAFETY: the params object is created, filled with pointers to
        // `owned` (alive until after the compile) and freed here; `err` is a
        // valid out-pointer.
        unsafe {
            let p = if owned.is_empty() {
                std::ptr::null_mut()
            } else {
                (self.create_params)()
            };
            for (k, v) in &owned {
                (self.set_param)(p, k.as_ptr(), v.as_ptr());
            }
            let profile = (self.compile_string)(source.as_ptr(), p, err);
            if !p.is_null() {
                (self.free_params)(p);
            }
            profile
        }
    }

    fn finish(&self, profile: *mut Profile, err: *mut c_char) -> Result<Bytecode, CompileError> {
        if profile.is_null() {
            let text = (!err.is_null()).then(|| {
                // SAFETY: libsandbox sets `err` to a NUL-terminated, malloc'd string.
                let s = unsafe { CStr::from_ptr(err) }
                    .to_string_lossy()
                    .into_owned();
                // SAFETY: the string was allocated by libsandbox with malloc.
                unsafe { libc::free(err.cast()) };
                s
            });
            return Err(CompileError { text });
        }
        // SAFETY: a non-null profile points to a valid struct whose `data`
        // holds `size` bytes until sandbox_free_profile.
        unsafe {
            let p = &*profile;
            let data = if p.data.is_null() {
                Vec::new()
            } else {
                std::slice::from_raw_parts(p.data, p.size).to_vec()
            };
            let builtin_null = p.builtin.is_null();
            (self.free_profile)(profile);
            Ok(Bytecode { data, builtin_null })
        }
    }

    /// Applies bytecode to the calling process via path A:
    /// `__mac_syscall("Sandbox", 0, &{data, size, NULL, 0})`.
    pub fn apply_path_a(&self, bytecode: &Bytecode) -> Result<(), i32> {
        let mut args = ApplyArgs {
            data: bytecode.data.as_ptr(),
            size: bytecode.data.len(),
            container: std::ptr::null(),
            container_len: 0,
        };
        // SAFETY: `args` points to bytecode that outlives the call.
        let rc = unsafe { (self.mac_syscall)(c"Sandbox".as_ptr(), 0, (&raw mut args).cast()) };
        if rc == 0 { Ok(()) } else { Err(errno()) }
    }

    /// Applies bytecode to the calling process via `sandbox_apply`.
    pub fn apply_lib(&self, bytecode: &Bytecode) -> (i32, i32) {
        let mut profile = Profile {
            builtin: std::ptr::null_mut(),
            data: bytecode.data.as_ptr(),
            size: bytecode.data.len(),
        };
        // SAFETY: the profile struct points to bytecode alive for the call;
        // sandbox_apply does not keep it.
        let rc = unsafe { (self.apply)(&raw mut profile) };
        (rc, if rc == 0 { 0 } else { errno() })
    }

    /// `sandbox_check(getpid(), NULL, 0)`: 1 when the process is sandboxed.
    pub fn check_self(&self) -> i32 {
        // SAFETY: the documented no-operation form of sandbox_check.
        unsafe { (self.check)(libc::getpid(), std::ptr::null(), 0) }
    }

    /// `sandbox_check` for a path operation, without reporting a violation.
    pub fn check_path(&self, operation: &str, path: &str) -> i32 {
        let op = CString::new(operation).expect("op");
        let arg = CString::new(path).expect("path");
        // SAFETY: variadic call with one `const char *` argument, matching
        // the PATH filter type.
        unsafe {
            (self.check)(
                libc::getpid(),
                op.as_ptr(),
                FILTER_PATH | self.check_no_report,
                arg.as_ptr(),
            )
        }
    }

    /// `sandbox_check` for a Mach global name, without reporting a violation.
    pub fn check_global_name(&self, operation: &str, name: &str) -> i32 {
        let op = CString::new(operation).expect("op");
        let arg = CString::new(name).expect("name");
        // SAFETY: variadic call with one `const char *` argument, matching
        // the GLOBAL_NAME filter type.
        unsafe {
            (self.check)(
                libc::getpid(),
                op.as_ptr(),
                FILTER_GLOBAL_NAME | self.check_no_report,
                arg.as_ptr(),
            )
        }
    }

    /// Issues a file extension token of `class` for `path`.
    pub fn issue_file_extension(&self, class: &str, path: &str) -> Option<String> {
        let c = CString::new(class).ok()?;
        let p = CString::new(path).ok()?;
        // SAFETY: both arguments are NUL-terminated; a non-null result is a
        // malloc'd NUL-terminated token that we copy and free.
        unsafe {
            let token = (self.issue_file)(c.as_ptr(), p.as_ptr(), 0);
            if token.is_null() {
                return None;
            }
            let s = CStr::from_ptr(token).to_string_lossy().into_owned();
            libc::free(token.cast());
            Some(s)
        }
    }

    /// Consumes an extension token; returns the handle (negative on failure).
    pub fn consume_extension(&self, token: &str) -> i64 {
        let Ok(t) = CString::new(token) else {
            return -1;
        };
        // SAFETY: NUL-terminated token string.
        unsafe { (self.consume)(t.as_ptr()) }
    }

    /// Releases a consumed extension handle.
    pub fn release_extension(&self, handle: i64) -> i32 {
        // SAFETY: plain integer argument.
        unsafe { (self.release)(handle) }
    }

    /// Prepares a child that applies `bytecode` via path A (when `apply`)
    /// and then execs `argv` with an empty environment and stdout/stderr on
    /// `/dev/null`. Everything is allocated here, before any fork.
    pub fn prepare_exec(&self, bytecode: &Bytecode, argv: &[&str], apply: bool) -> PreparedExec {
        let argv: Vec<CString> = argv
            .iter()
            .map(|a| CString::new(*a).expect("argv"))
            .collect();
        let mut argv_ptrs: Vec<*const c_char> = argv.iter().map(|a| a.as_ptr()).collect();
        argv_ptrs.push(std::ptr::null());
        // SAFETY: opening /dev/null with a static path.
        let devnull =
            unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_WRONLY | libc::O_CLOEXEC) };
        PreparedExec {
            data: bytecode.data.clone(),
            argv,
            argv_ptrs,
            envp: [std::ptr::null()],
            devnull,
            mac_syscall: self.mac_syscall,
            apply,
        }
    }
}

/// A fork-apply-exec prepared entirely in the parent.
pub struct PreparedExec {
    data: Vec<u8>,
    #[allow(dead_code)] // owns the strings argv_ptrs points into
    argv: Vec<CString>,
    argv_ptrs: Vec<*const c_char>,
    envp: [*const c_char; 1],
    devnull: RawFd,
    mac_syscall: MacSyscall,
    apply: bool,
}

impl PreparedExec {
    /// Forks. The child runs exactly `dup2`, `dup2`, `__mac_syscall`,
    /// `execve`, `_exit`: syscalls only, no allocation, no locks. Exit 126
    /// means the apply failed, 127 that exec failed.
    pub fn spawn(&self) -> Result<libc::pid_t, i32> {
        let mut args = ApplyArgs {
            data: self.data.as_ptr(),
            size: self.data.len(),
            container: std::ptr::null(),
            container_len: 0,
        };
        let args_ptr: *mut c_void = (&raw mut args).cast();
        let policy = c"Sandbox".as_ptr();
        // SAFETY: fork in a possibly multithreaded parent; the child only
        // issues the async-signal-safe calls listed above, on memory prepared
        // before the fork, and never returns into Rust code.
        unsafe {
            let pid = libc::fork();
            if pid == 0 {
                libc::dup2(self.devnull, 1);
                libc::dup2(self.devnull, 2);
                if self.apply && (self.mac_syscall)(policy, 0, args_ptr) != 0 {
                    libc::_exit(126);
                }
                libc::execve(
                    self.argv_ptrs[0],
                    self.argv_ptrs.as_ptr(),
                    self.envp.as_ptr(),
                );
                libc::_exit(127);
            }
            if pid < 0 { Err(errno()) } else { Ok(pid) }
        }
    }
}

impl Drop for PreparedExec {
    fn drop(&mut self) {
        // SAFETY: closing the fd this struct opened.
        unsafe { libc::close(self.devnull) };
    }
}

/// Waits for `pid` until `timeout`; kills it on expiry. Returns the raw wait
/// status, or `None` on timeout.
pub fn wait_with_timeout(pid: libc::pid_t, timeout: Duration) -> Option<i32> {
    let deadline = Instant::now() + timeout;
    loop {
        let mut status = 0;
        // SAFETY: waitpid on our own child with a valid out-pointer.
        let r = unsafe { libc::waitpid(pid, &raw mut status, libc::WNOHANG) };
        if r == pid {
            return Some(status);
        }
        if r < 0 || Instant::now() >= deadline {
            // SAFETY: signalling and reaping our own child.
            unsafe {
                libc::kill(pid, libc::SIGKILL);
                libc::waitpid(pid, &raw mut status, 0);
            }
            return None;
        }
        std::thread::sleep(Duration::from_millis(1));
    }
}

/// The exit code in a raw wait status, if the child exited normally.
pub fn exit_code(status: i32) -> Option<i32> {
    libc::WIFEXITED(status).then(|| libc::WEXITSTATUS(status))
}

/// Loops `dlopen`/`dlsym`/`dlclose` until `stop`, to contend dyld's locks.
pub fn dyld_churn(stop: &AtomicBool) {
    while !stop.load(Ordering::Relaxed) {
        // SAFETY: loading and unloading a system library by absolute path;
        // the symbol pointer is not called.
        unsafe {
            let h = libc::dlopen(c"/usr/lib/libz.1.dylib".as_ptr(), libc::RTLD_NOW);
            if !h.is_null() {
                libc::dlsym(h, c"zlibVersion".as_ptr());
                libc::dlclose(h);
            }
        }
    }
}

/// `sysctlbyname` for a string value.
pub fn sysctl_string(name: &str) -> Option<String> {
    let cname = CString::new(name).ok()?;
    let mut buf = [0u8; 256];
    let mut len = buf.len();
    // SAFETY: buffer and length describe valid writable memory.
    let rc = unsafe {
        libc::sysctlbyname(
            cname.as_ptr(),
            buf.as_mut_ptr().cast(),
            &raw mut len,
            std::ptr::null_mut(),
            0,
        )
    };
    if rc != 0 {
        return None;
    }
    let s = &buf[..len];
    let s = s.split(|&b| b == 0).next().unwrap_or(s);
    Some(String::from_utf8_lossy(s).into_owned())
}

/// Clears `FD_CLOEXEC` so `fd` is inherited across exec.
pub fn clear_cloexec(fd: RawFd) -> Result<(), i32> {
    // SAFETY: fcntl on an fd the caller owns.
    let rc = unsafe { libc::fcntl(fd, libc::F_SETFD, 0) };
    if rc == 0 { Ok(()) } else { Err(errno()) }
}

/// Reads `fd` to the end and returns the byte count.
pub fn read_fd_len(fd: RawFd) -> Result<usize, i32> {
    let mut buf = [0u8; 4096];
    let mut total = 0;
    loop {
        // SAFETY: reading into a stack buffer of the stated length.
        let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
        match n {
            0 => return Ok(total),
            n if n > 0 => total += n as usize,
            _ => return Err(errno()),
        }
    }
}

/// Opens a new pseudo-terminal pair; returns the master and the slave's path.
pub fn open_pty() -> Result<(OwnedFd, String), i32> {
    // SAFETY: posix_openpt/grantpt/unlockpt/ptsname on the fd we just
    // opened; ptsname's static buffer is copied before any other call.
    unsafe {
        let m = libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY);
        if m < 0 {
            return Err(errno());
        }
        let master = OwnedFd::from_raw_fd(m);
        if libc::grantpt(m) != 0 || libc::unlockpt(m) != 0 {
            return Err(errno());
        }
        let name = libc::ptsname(m);
        if name.is_null() {
            return Err(errno());
        }
        Ok((master, CStr::from_ptr(name).to_string_lossy().into_owned()))
    }
}

/// Starts a new session, detaching from any controlling terminal.
pub fn setsid() -> Result<(), i32> {
    // SAFETY: no arguments.
    if unsafe { libc::setsid() } < 0 {
        Err(errno())
    } else {
        Ok(())
    }
}

/// Opens the terminal at `path`, makes it the controlling terminal of this
/// session, and switches it to non-canonical mode without echo and with
/// non-blocking reads (VMIN = VTIME = 0).
pub fn open_controlling_tty(path: &str) -> Result<OwnedFd, i32> {
    let c = CString::new(path).map_err(|_| libc::EINVAL)?;
    // SAFETY: open/ioctl/tcgetattr/tcsetattr on the fd we open here, with a
    // termios struct on our stack.
    unsafe {
        let fd = libc::open(c.as_ptr(), libc::O_RDWR);
        if fd < 0 {
            return Err(errno());
        }
        let fd = OwnedFd::from_raw_fd(fd);
        if libc::ioctl(fd.as_raw_fd(), libc::TIOCSCTTY.into(), 0) != 0 {
            return Err(errno());
        }
        let mut t: libc::termios = std::mem::zeroed();
        if libc::tcgetattr(fd.as_raw_fd(), &raw mut t) != 0 {
            return Err(errno());
        }
        t.c_lflag &= !(libc::ICANON | libc::ECHO);
        t.c_cc[libc::VMIN] = 0;
        t.c_cc[libc::VTIME] = 0;
        if libc::tcsetattr(fd.as_raw_fd(), libc::TCSANOW, &raw const t) != 0 {
            return Err(errno());
        }
        Ok(fd)
    }
}

/// `ioctl(fd, TIOCSTI, &byte)`: pushes one byte into the terminal's input.
pub fn tiocsti(fd: &OwnedFd, byte: u8) -> Result<(), i32> {
    let b = byte as c_char;
    // SAFETY: TIOCSTI takes a pointer to one char.
    let rc = unsafe { libc::ioctl(fd.as_raw_fd(), libc::TIOCSTI, &raw const b) };
    if rc == 0 { Ok(()) } else { Err(errno()) }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An unavailable symbol is reported by its name, not as a crash.
    #[test]
    fn missing_symbol_is_named() {
        load_libsandbox();
        assert_eq!(
            require("procage_kf_no_such_symbol"),
            Err("procage_kf_no_such_symbol")
        );
        assert!(missing_symbols().is_empty(), "{:?}", missing_symbols());
        assert!(Sandbox::load().is_ok());
    }
}
