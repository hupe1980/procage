//! Linux steps and capability measurements. Each runs in a fresh,
//! single-threaded process, so `unshare(CLONE_NEWUSER)` is allowed and a
//! crash only loses this one measurement.

use std::process::{Command, Stdio};

use procage_kernel_facts::emit;
use procage_kernel_facts::sys::linux as sys;

use super::{Fail, StepResult, choice, forward, io_errno, scratch_arg, setup};

const RW: u64 = sys::FS_WRITE_FILE | sys::FS_MAKE_REG;

pub(crate) fn run(step: &str, args: &[String]) -> StepResult {
    match step {
        "osinfo" => osinfo(),
        "measure" => measure(choice(
            args,
            0,
            &[
                "landlock",
                "seccomp",
                "userns",
                "uid_map",
                "tmpfs",
                "ro_bind",
                "fresh_proc",
                "netns",
                "apparmor",
            ],
        )?),
        "proc-inner" => proc_inner(),
        "userns" => userns(),
        "ro-bind" => ro_bind(scratch_arg(args, 0)?),
        "tmpfs" => tmpfs(scratch_arg(args, 0)?),
        "landlock-write" => landlock_write(scratch_arg(args, 0)?),
        "landlock-devnull" => landlock_devnull(
            scratch_arg(args, 0)?,
            choice(args, 1, &["rule", "no-rule"])? == "rule",
        ),
        "landlock-truncate" => landlock_truncate(
            scratch_arg(args, 0)?,
            choice(args, 1, &["handled", "unhandled"])? == "handled",
        ),
        "netns" => netns(),
        "nested-undo" => nested_undo(scratch_arg(args, 0)?),
        "nested-uidmap" => nested_uidmap(scratch_arg(args, 0)?),
        "mount-after-landlock" => mount_after_landlock(scratch_arg(args, 0)?),
        "proc-mount" => proc_mount(),
        other => Err(Fail::Usage(format!("unknown step {other}"))),
    }
}

fn read_trimmed(path: &str) -> Option<String> {
    std::fs::read_to_string(path)
        .ok()
        .map(|s| s.trim().to_owned())
}

fn osinfo() -> StepResult {
    emit(
        "kernel",
        read_trimmed("/proc/sys/kernel/osrelease").unwrap_or_else(|| "unknown".into()),
    );
    emit("arch", std::env::consts::ARCH);
    Ok(())
}

/// Enters a new user namespace (plus `extra` namespaces) and maps the
/// caller's uid and gid to 0 inside it.
fn enter_userns(extra: libc::c_int) -> Result<(), i32> {
    let (uid, gid) = sys::ids();
    sys::unshare(libc::CLONE_NEWUSER | extra)?;
    let w = |path: &str, data: String| std::fs::write(path, data).map_err(|e| io_errno(&e));
    w("/proc/self/setgroups", "deny".into())?;
    w("/proc/self/uid_map", format!("0 {uid} 1"))?;
    w("/proc/self/gid_map", format!("0 {gid} 1"))
}

/// Enters user + mount namespaces and makes every mount private.
fn enter_mount_ns() -> Result<(), i32> {
    enter_userns(libc::CLONE_NEWNS)?;
    sys::mount(None, "/", None, libc::MS_REC | libc::MS_PRIVATE)
}

/// Bind-mounts `dir` onto itself and remounts it read-only, keeping the
/// flags the kernel locked on the original mount.
fn ro_bind_in_place(dir: &str) -> Result<(), i32> {
    sys::mount(Some(dir), dir, None, libc::MS_BIND | libc::MS_REC)?;
    let locked = sys::locked_flags(dir)?;
    sys::mount(
        None,
        dir,
        None,
        libc::MS_BIND | libc::MS_REMOUNT | libc::MS_RDONLY | locked,
    )
}

fn emit_result(key: &str, r: Result<(), i32>) {
    emit(key, r.err().unwrap_or(0));
}

fn write_errno(path: &str) -> i32 {
    std::fs::write(path, b"x").err().map_or(0, |e| io_errno(&e))
}

fn measure(cap: &str) -> StepResult {
    let result: Result<(), i32> = match cap {
        "landlock" => sys::landlock_abi().map(|abi| {
            emit("abi", abi);
            if let Ok(errata) = sys::landlock_errata() {
                emit("errata", errata);
            }
        }),
        "seccomp" => {
            let actions =
                read_trimmed("/proc/sys/kernel/seccomp/actions_avail").unwrap_or_default();
            emit(
                "actions",
                actions.split_whitespace().collect::<Vec<_>>().join("+"),
            );
            sys::seccomp_allow_all()
        }
        "userns" => sys::unshare(libc::CLONE_NEWUSER),
        "uid_map" => enter_userns(0),
        "tmpfs" => {
            enter_mount_ns().and_then(|()| sys::mount(Some("tmpfs"), "/tmp", Some("tmpfs"), 0))
        }
        "ro_bind" => enter_mount_ns()
            .and_then(|()| ro_bind_in_place("/tmp"))
            .and_then(|()| match write_errno("/tmp/procage-kf-ro-check") {
                libc::EROFS => Ok(()),
                0 => Err(-1),
                e => Err(e),
            }),
        "fresh_proc" => enter_userns(libc::CLONE_NEWPID | libc::CLONE_NEWNS)
            .and_then(|()| nested(&["proc-inner"]))
            .and_then(|out| {
                let obs = procage_kernel_facts::Observation::parse(&String::from_utf8_lossy(&out));
                match obs.int("errno") {
                    Some(0) => Ok(()),
                    Some(e) => Err(e as i32),
                    None => Err(-1),
                }
            }),
        "netns" => enter_userns(libc::CLONE_NEWNET).and_then(|()| {
            if interfaces_up()? == 0 {
                Ok(())
            } else {
                Err(-1)
            }
        }),
        "apparmor" => {
            match read_trimmed("/proc/sys/kernel/apparmor_restrict_unprivileged_userns") {
                Some(v) => {
                    emit("value", v);
                    Ok(())
                }
                None => Err(libc::ENOENT),
            }
        }
        _ => unreachable!("checked by choice"),
    };
    match result {
        Ok(()) => emit("ok", 1),
        Err(e) => {
            emit("ok", 0);
            emit("errno", e);
        }
    }
    Ok(())
}

/// Runs this binary with `args` in a child (which joins any PID namespace
/// this process unshared) and returns its stdout.
fn nested(args: &[&str]) -> Result<Vec<u8>, i32> {
    let exe = std::env::current_exe().map_err(|e| io_errno(&e))?;
    let out = Command::new(exe)
        .args(args)
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .output()
        .map_err(|e| io_errno(&e))?;
    Ok(out.stdout)
}

/// PID 1 of a new PID namespace: mounts a fresh /proc.
fn proc_inner() -> StepResult {
    let r = sys::mount(None, "/", None, libc::MS_REC | libc::MS_PRIVATE).and_then(|()| {
        sys::mount(
            Some("proc"),
            "/proc",
            Some("proc"),
            libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
        )
    });
    emit("pid", std::process::id());
    emit_result("errno", r);
    Ok(())
}

/// Interface names in this network namespace's `/proc/self/net/dev`.
fn net_interfaces() -> Vec<String> {
    read_trimmed("/proc/self/net/dev").map_or_else(Vec::new, |s| {
        s.lines()
            .skip(2)
            .filter_map(|l| l.split_once(':').map(|(name, _)| name.trim().to_owned()))
            .collect()
    })
}

/// How many interfaces in this network namespace have `IFF_UP`. A new
/// namespace may also hold fallback tunnel devices (tunl0, gre0, sit0, …)
/// when their modules are loaded; all of them start down.
fn interfaces_up() -> Result<usize, i32> {
    let mut up = 0;
    for name in net_interfaces() {
        if sys::interface_up(&name)? {
            up += 1;
        }
    }
    Ok(up)
}

fn userns() -> StepResult {
    let r = enter_userns(0);
    emit_result("errno", r);
    emit("uid", sys::ids().0);
    Ok(())
}

fn ro_bind(scratch: &str) -> StepResult {
    let dir = format!("{scratch}/d");
    std::fs::create_dir(&dir).map_err(|e| setup(e.to_string()))?;
    emit("before_errno", write_errno(&format!("{dir}/before")));
    enter_mount_ns().map_err(|e| setup(format!("mount ns errno {e}")))?;
    ro_bind_in_place(&dir).map_err(|e| setup(format!("ro bind errno {e}")))?;
    emit("after_errno", write_errno(&format!("{dir}/after")));
    Ok(())
}

fn count_entries(dir: &str) -> usize {
    std::fs::read_dir(dir).map_or(0, Iterator::count)
}

fn tmpfs(scratch: &str) -> StepResult {
    let dir = format!("{scratch}/h");
    std::fs::create_dir(&dir).map_err(|e| setup(e.to_string()))?;
    std::fs::write(format!("{dir}/file"), b"x").map_err(|e| setup(e.to_string()))?;
    emit("before_entries", count_entries(&dir));
    enter_mount_ns().map_err(|e| setup(format!("mount ns errno {e}")))?;
    sys::mount(Some("tmpfs"), &dir, Some("tmpfs"), 0)
        .map_err(|e| setup(format!("tmpfs errno {e}")))?;
    emit("after_entries", count_entries(&dir));
    Ok(())
}

fn restrict_to(scratch: &str, extra: &[&str]) -> Result<(), Fail> {
    let rs = sys::landlock_ruleset(RW).map_err(|e| setup(format!("ruleset errno {e}")))?;
    for path in std::iter::once(scratch).chain(extra.iter().copied()) {
        let access = if path == "/dev/null" {
            sys::FS_WRITE_FILE
        } else {
            RW
        };
        sys::landlock_allow(&rs, path, access).map_err(|e| setup(format!("rule errno {e}")))?;
    }
    sys::landlock_restrict(&rs).map_err(|e| setup(format!("restrict errno {e}")))
}

fn landlock_write(scratch: &str) -> StepResult {
    for d in ["a", "b"] {
        std::fs::create_dir(format!("{scratch}/{d}")).map_err(|e| setup(e.to_string()))?;
    }
    emit(
        "control_errno",
        write_errno(&format!("{scratch}/b/control")),
    );
    restrict_to(&format!("{scratch}/a"), &[])?;
    emit("a_errno", write_errno(&format!("{scratch}/a/f")));
    emit("b_errno", write_errno(&format!("{scratch}/b/f")));
    Ok(())
}

fn landlock_devnull(scratch: &str, rule: bool) -> StepResult {
    restrict_to(scratch, if rule { &["/dev/null"] } else { &[] })?;
    let r = std::fs::OpenOptions::new().write(true).open("/dev/null");
    emit("errno", r.err().map_or(0, |e| io_errno(&e)));
    Ok(())
}

/// Writes are handled and nothing is granted; truncation is handled only
/// when `handled` (as from ABI 3). Each route tries to empty its own file.
fn landlock_truncate(scratch: &str, handled: bool) -> StepResult {
    let file = |n: &str| format!("{scratch}/{n}");
    for n in ["w", "t", "r", "n"] {
        std::fs::write(file(n), "content").map_err(|e| setup(e.to_string()))?;
    }
    let fs = sys::FS_WRITE_FILE | if handled { sys::FS_TRUNCATE } else { 0 };
    let rs = sys::landlock_ruleset(fs).map_err(|e| setup(format!("ruleset errno {e}")))?;
    sys::landlock_restrict(&rs).map_err(|e| setup(format!("restrict errno {e}")))?;
    emit_result("write_errno", sys::open_close(&file("w"), libc::O_WRONLY));
    emit_result("truncate_errno", sys::truncate(&file("t")));
    emit_result(
        "rdonly_trunc_errno",
        sys::open_close(&file("r"), libc::O_RDONLY | libc::O_TRUNC),
    );
    emit_result(
        "noaccess_trunc_errno",
        sys::open_close(&file("n"), 3 | libc::O_TRUNC),
    );
    let emptied = ["t", "r", "n"]
        .iter()
        .filter(|n| std::fs::metadata(file(n)).is_ok_and(|m| m.len() == 0))
        .count();
    emit("emptied", emptied);
    Ok(())
}

fn netns() -> StepResult {
    emit("host_up", interfaces_up().unwrap_or(0));
    let r = enter_userns(libc::CLONE_NEWNET);
    emit_result("errno", r);
    emit("interfaces", net_interfaces().len());
    emit(
        "has_lo",
        u8::from(net_interfaces().iter().any(|n| n == "lo")),
    );
    emit(
        "up",
        interfaces_up().map_or_else(|e| format!("errno-{e}"), |n| n.to_string()),
    );
    Ok(())
}

fn nested_undo(scratch: &str) -> StepResult {
    let (ro, hide, other) = (
        format!("{scratch}/ro"),
        format!("{scratch}/hide"),
        format!("{scratch}/other"),
    );
    for d in [&ro, &hide, &other] {
        std::fs::create_dir(d).map_err(|e| setup(e.to_string()))?;
    }
    enter_mount_ns().map_err(|e| setup(format!("mount ns errno {e}")))?;
    ro_bind_in_place(&ro).map_err(|e| setup(format!("ro bind errno {e}")))?;
    sys::mount(Some("tmpfs"), &hide, Some("tmpfs"), 0)
        .map_err(|e| setup(format!("tmpfs errno {e}")))?;
    // The nested namespace: its mounts are now locked copies of the outer ones.
    let (uid, gid) = sys::ids();
    sys::unshare(libc::CLONE_NEWUSER | libc::CLONE_NEWNS)
        .map_err(|e| setup(format!("nested unshare errno {e}")))?;
    for (path, data) in [
        ("/proc/self/setgroups", "deny".to_owned()),
        ("/proc/self/uid_map", format!("0 {uid} 1")),
        ("/proc/self/gid_map", format!("0 {gid} 1")),
    ] {
        std::fs::write(path, data).map_err(|e| setup(format!("nested map: {e}")))?;
    }
    emit_result(
        "remount_errno",
        sys::mount(None, &ro, None, libc::MS_BIND | libc::MS_REMOUNT),
    );
    emit_result("umount_errno", sys::umount(&hide));
    emit_result(
        "bind_errno",
        sys::mount(Some(scratch), &other, None, libc::MS_BIND),
    );
    Ok(())
}

fn nested_uidmap(scratch: &str) -> StepResult {
    enter_mount_ns().map_err(|e| setup(format!("mount ns errno {e}")))?;
    restrict_to(scratch, &[])?;
    let (uid, _) = sys::ids();
    sys::unshare(libc::CLONE_NEWUSER).map_err(|e| setup(format!("nested unshare errno {e}")))?;
    let r = std::fs::write("/proc/self/uid_map", format!("0 {uid} 1"));
    emit("map_errno", r.err().map_or(0, |e| io_errno(&e)));
    Ok(())
}

fn mount_after_landlock(scratch: &str) -> StepResult {
    let (m1, m2) = (format!("{scratch}/m1"), format!("{scratch}/m2"));
    for d in [&m1, &m2] {
        std::fs::create_dir(d).map_err(|e| setup(e.to_string()))?;
    }
    enter_mount_ns().map_err(|e| setup(format!("mount ns errno {e}")))?;
    emit_result(
        "before_errno",
        sys::mount(Some("tmpfs"), &m1, Some("tmpfs"), 0),
    );
    restrict_to(scratch, &[])?;
    emit_result(
        "after_errno",
        sys::mount(Some("tmpfs"), &m2, Some("tmpfs"), 0),
    );
    Ok(())
}

fn proc_mount() -> StepResult {
    enter_userns(libc::CLONE_NEWPID | libc::CLONE_NEWNS)
        .map_err(|e| setup(format!("userns errno {e}")))?;
    let out = nested(&["proc-inner"]).map_err(|e| setup(format!("spawn errno {e}")))?;
    let obs = procage_kernel_facts::Observation::parse(&String::from_utf8_lossy(&out));
    emit("ok", u8::from(obs.int("errno") == Some(0)));
    forward("inner_", &out);
    Ok(())
}
