//! macOS steps. Each step that cages itself compiles a profile, applies it to
//! this (single-threaded, freshly exec'd) process, performs one action and
//! reports what happened.

use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use procage_kernel_facts::emit;
use procage_kernel_facts::sys::macos::{self as sys, Bytecode, Sandbox};

use super::{Fail, StepResult, choice, forward, io_errno, scratch_arg, setup};

const ALLOW_ALL: &str = "(version 1)(allow default)";
/// The extension class used for per-spawn write grants.
const RW_CLASS: &str = "com.apple.app-sandbox.read-write";
/// The setuid binary KF-M11 execs, with arguments that never prompt.
const SETUID_ARGV: [&str; 3] = ["/usr/bin/sudo", "-n", "-V"];

pub(crate) fn run(step: &str, args: &[String]) -> StepResult {
    match step {
        "osinfo" => osinfo(),
        "symbols" => symbols(),
        "selfcheck" => selfcheck(),
        "compile" => compile_case(choice(args, 0, COMPILE_CASES)?),
        "compile-rules" => compile_rules(args),
        "apply-selfcheck" => apply_selfcheck(),
        "apply-then-spawn" => apply_then_spawn(),
        "read" => read(choice(
            args,
            0,
            &[
                "control",
                "literal-etc",
                "literal-private",
                "control-users",
                "deny-users",
            ],
        )?),
        "tmp-create" => tmp_create(
            choice(args, 0, &["control", "subpath-tmp", "subpath-private"])?,
            scratch_arg(args, 1)?,
        ),
        "nest" => nest(scratch_arg(args, 0)?),
        "compile-inside" => compile_inside(),
        "setuid-exec" => setuid_exec(choice(args, 0, &["control", "caged"])?),
        "no-sandbox-exec" => no_sandbox_exec(choice(args, 0, &["control", "escape"])?),
        "patha-contention" => patha_contention(args),
        "fd-parent" => fd_parent(scratch_arg(args, 0)?),
        "fd-child" => fd_child(args),
        "ext-parent" => ext_parent(
            scratch_arg(args, 0)?,
            choice(args, 1, &["apply-first", "consume-first"])?,
        ),
        "ext-child" => ext_child(
            scratch_arg(args, 0)?,
            choice(args, 1, &["apply-first", "consume-first"])?,
        ),
        "check-oracle" => check_oracle(scratch_arg(args, 0)?),
        "tiocsti" => tiocsti(choice(args, 0, &["control", "caged"])?),
        "tiocsti-child" => tiocsti_child(args),
        other => Err(Fail::Usage(format!("unknown step {other}"))),
    }
}

fn sandbox() -> Result<Sandbox, Fail> {
    Sandbox::load().map_err(|name| {
        emit("missing", name);
        setup(format!("symbol {name} unavailable"))
    })
}

fn compile(sb: &Sandbox, sbpl: &str) -> Result<Bytecode, Fail> {
    sb.compile(sbpl, &[])
        .map_err(|e| setup(format!("compile failed: {:?}", e.text)))
}

fn apply(sb: &Sandbox, sbpl: &str) -> Result<(), Fail> {
    let bc = compile(sb, sbpl)?;
    sb.apply_path_a(&bc).map_err(|e| {
        emit("apply_errno", e);
        setup(format!("apply failed: errno {e}"))
    })
}

fn self_exe() -> Result<String, Fail> {
    let p = std::env::current_exe().map_err(|e| setup(e.to_string()))?;
    p.to_str()
        .map(str::to_owned)
        .ok_or_else(|| setup("non-UTF-8 executable path"))
}

/// Runs this binary with `args` (empty env, stdin as given) and returns its stdout.
fn nested(args: &[&str], stdin: Option<&[u8]>) -> Result<Vec<u8>, Fail> {
    let mut child = Command::new(self_exe()?)
        .args(args)
        .env_clear()
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|e| setup(format!("spawn: {e}")))?;
    if let (Some(data), Some(mut pipe)) = (stdin, child.stdin.take()) {
        let _ = pipe.write_all(data);
    }
    let out = child.wait_with_output().map_err(|e| setup(e.to_string()))?;
    Ok(out.stdout)
}

fn err_kind(text: Option<&str>) -> &'static str {
    match text {
        None => "none",
        Some(t) if t.contains("expected pattern, got boolean") => "unset_param",
        Some(t) if t.contains("host must be * or localhost") => "ip_host",
        Some(t) if t.contains("exceeds maximum") => "data_too_long",
        Some(t) if t.starts_with("unbound variable") => "unbound",
        // The over-long literal is rejected by the reader, not a size check.
        Some(t) if t.starts_with("Error reading string") => "string_read",
        Some(_) => "other",
    }
}

fn osinfo() -> StepResult {
    emit(
        "product",
        sys::sysctl_string("kern.osproductversion").unwrap_or_else(|| "unknown".into()),
    );
    emit(
        "build",
        sys::sysctl_string("kern.osversion").unwrap_or_else(|| "unknown".into()),
    );
    emit("arch", std::env::consts::ARCH);
    Ok(())
}

fn symbols() -> StepResult {
    let missing = sys::missing_symbols();
    emit("checked", sys::SYMBOLS.len());
    emit("missing_count", missing.len());
    for (i, name) in missing.iter().enumerate() {
        emit(&format!("missing_{i}"), name);
    }
    Ok(())
}

fn selfcheck() -> StepResult {
    emit("sandboxed", sandbox()?.check_self());
    Ok(())
}

const COMPILE_CASES: &[&str] = &[
    "small",
    "error",
    "keeps-slot",
    "unset-param",
    "ip-host",
    "hard-deny",
    "params",
    "literal-1016",
    "literal-1024",
    "param-4000",
];

/// Every hard-deny-tier and network form procage plans to emit.
const HARD_DENY_FORMS: &[&str] = &[
    "",
    "(deny system-fcntl (fcntl-command 80 110))",
    "(deny system-fcntl (fcntl-command 80))",
    "(deny mach-lookup (xpc-service-name-prefix \"\"))",
    "(deny file-write-unlink (require-all (vnode-type DIRECTORY) (literal \"/private/tmp/procage-kf-anchor\")))",
    "(deny file-write-setugid)",
    "(deny process-exec (file-mode #o4000))",
    "(deny mach-priv-task-port)",
    "(deny process-info-pidinfo)",
    "(allow signal (target children))",
    "(allow process-info* (target same-sandbox))",
    "(allow network-bind (local ip \"*:*\"))",
    "(allow network-outbound (remote ip \"localhost:3128\"))",
    "(allow network-outbound (remote unix-socket (path-literal \"/private/var/run/mDNSResponder\")))",
    "(import \"system.sb\")",
];

/// Every filter that must accept `(param …)`.
const PARAM_FORMS: &[&str] = &[
    "(allow file-write* (subpath (param \"W0\")))",
    "(deny file-read* (literal (param \"W0\")))",
    "(deny file-read* (prefix (param \"W0\")))",
    "(deny file-read* (regex (param \"W0\")))",
    "(allow network-outbound (remote unix-socket (path-literal (param \"W0\"))))",
    "(allow mach-lookup (global-name (param \"S0\")))",
    "(allow file-read* (subpath (string-append (param \"W0\") \"/x\")))",
];

fn literal_of(len: usize) -> String {
    let mut s = String::with_capacity(len);
    s.push('/');
    s.extend(std::iter::repeat_n('a', len - 1));
    s
}

fn compile_case(case: &str) -> StepResult {
    let sb = sandbox()?;
    let report = |r: Result<Bytecode, sys::CompileError>| match r {
        Ok(bc) => {
            emit("ok", 1);
            emit("size", bc.data.len());
            emit("builtin_null", u8::from(bc.builtin_null));
        }
        Err(e) => {
            emit("ok", 0);
            emit("err_kind", err_kind(e.text.as_deref()));
            // Diagnostic only: the runner never parses stderr.
            eprintln!(
                "compile error: {:?}",
                e.text.as_deref().map(|t| t.lines().next().unwrap_or(""))
            );
            if let Some(t) = &e.text
                && let Some((line, col)) = parse_line_col(t)
            {
                emit("err_line", line);
                emit("err_col", col);
            }
        }
    };
    match case {
        "small" => report(sb.compile(ALLOW_ALL, &[])),
        "error" => report(sb.compile("(version 1)(allow nonsense-op)", &[])),
        "keeps-slot" => match sb.compile_keeps_error_slot(ALLOW_ALL) {
            Some(kept) => emit("slot_kept", u8::from(kept)),
            None => return Err(setup("valid profile did not compile")),
        },
        "unset-param" => report(sb.compile(
            "(version 1)(deny default)(allow file-read* (subpath (param \"UNSET\")))",
            &[],
        )),
        "ip-host" => report(sb.compile(
            "(version 1)(deny default)(allow network-outbound (remote ip \"10.0.0.1:443\"))",
            &[],
        )),
        "hard-deny" => {
            let mut failed = 0;
            for (i, form) in HARD_DENY_FORMS.iter().enumerate() {
                let sbpl = format!("(version 1)(deny default (with message \"pc-run-1\")){form}");
                if sb.compile(&sbpl, &[]).is_err() {
                    failed += 1;
                    emit(&format!("failed_{i}"), 1);
                }
            }
            emit("forms", HARD_DENY_FORMS.len());
            emit("failed", failed);
        }
        "params" => {
            let params = [("W0", "/private/tmp/w"), ("S0", "com.apple.foo")];
            let mut failed = 0;
            for (i, form) in PARAM_FORMS.iter().enumerate() {
                if sb
                    .compile(&format!("(version 1)(deny default){form}"), &params)
                    .is_err()
                {
                    failed += 1;
                    emit(&format!("failed_{i}"), 1);
                }
            }
            emit("forms", PARAM_FORMS.len());
            emit("failed", failed);
        }
        "literal-1016" | "literal-1024" => {
            let len = if case == "literal-1016" { 1016 } else { 1024 };
            report(sb.compile(
                &format!(
                    "(version 1)(deny default)(allow file-read* (literal \"{}\"))",
                    literal_of(len)
                ),
                &[],
            ));
        }
        "param-4000" => {
            let value = literal_of(4000);
            report(sb.compile(
                "(version 1)(deny default)(allow file-read* (literal (param \"L\")))",
                &[("L", &value)],
            ));
        }
        _ => unreachable!("checked by choice"),
    }
    Ok(())
}

fn parse_line_col(text: &str) -> Option<(u32, u32)> {
    let rest = &text[text.find("line ")? + 5..];
    let (line, rest) = rest.split_once(", column ")?;
    let col: String = rest.chars().take_while(char::is_ascii_digit).collect();
    Some((line.trim().parse().ok()?, col.parse().ok()?))
}

/// Builds `n` rules of `shape`.
fn rules(shape: &str, n: usize) -> Option<String> {
    let mut s = String::with_capacity(n * 64 + 64);
    match shape {
        // The shape of the original measurement: deny default, one allow per
        // distinct directory.
        "deny-default-allow" => {
            s.push_str("(version 1)(deny default)");
            for i in 0..n {
                s.push_str(&format!(
                    "(allow file-read* (literal \"/private/tmp/dir{i:06}/file\"))"
                ));
            }
        }
        "allow-default-deny" => {
            s.push_str("(version 1)(allow default)");
            for i in 0..n {
                s.push_str(&format!(
                    "(deny file-read* (literal \"/private/tmp/pc-kf/r{i:07}\"))"
                ));
            }
        }
        "require-any" => {
            s.push_str("(version 1)(deny default)(allow file-read* (require-any");
            for i in 0..n {
                s.push_str(&format!(" (literal \"/private/tmp/dir{i:06}/file\")"));
            }
            s.push_str("))");
        }
        _ => return None,
    }
    Some(s)
}

fn compile_rules(args: &[String]) -> StepResult {
    let shape = choice(
        args,
        0,
        &["deny-default-allow", "allow-default-deny", "require-any"],
    )?;
    let n: usize = args
        .get(1)
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| Fail::Usage("rule count".into()))?;
    let sb = sandbox()?;
    let sbpl = rules(shape, n).expect("shape checked");
    // Flush the step identity first: an abort below loses buffered output.
    emit("rules", n);
    let _ = std::io::stdout().flush();
    let start = Instant::now();
    let result = sb.compile(&sbpl, &[]);
    emit("ms", start.elapsed().as_millis());
    match result {
        Ok(bc) => {
            emit("ok", 1);
            emit("size", bc.data.len());
        }
        Err(e) => {
            emit("ok", 0);
            emit("err_kind", err_kind(e.text.as_deref()));
        }
    }
    Ok(())
}

fn apply_selfcheck() -> StepResult {
    let sb = sandbox()?;
    let bc = compile(&sb, ALLOW_ALL)?;
    emit("before", sb.check_self());
    let rc = sb.apply_path_a(&bc);
    emit("apply_errno", rc.err().unwrap_or(0));
    emit("after", sb.check_self());
    let again = sb.apply_path_a(&bc);
    emit("again_errno", again.err().unwrap_or(0));
    emit("after_again", sb.check_self());
    Ok(())
}

fn apply_then_spawn() -> StepResult {
    let sb = sandbox()?;
    apply(&sb, ALLOW_ALL)?;
    forward("child_", &nested(&["selfcheck"], None)?);
    Ok(())
}

fn read(variant: &str) -> StepResult {
    let (path, rule) = match variant {
        "control" => ("/etc/hosts", None),
        "literal-etc" => (
            "/etc/hosts",
            Some("(deny file-read* (literal \"/etc/hosts\"))"),
        ),
        "literal-private" => (
            "/etc/hosts",
            Some("(deny file-read* (literal \"/private/etc/hosts\"))"),
        ),
        "control-users" => ("/Users/Shared", None),
        "deny-users" => (
            "/Users/Shared",
            Some("(deny file-read* (subpath \"/Users\"))"),
        ),
        _ => unreachable!("checked by choice"),
    };
    if let Some(rule) = rule {
        let sb = sandbox()?;
        apply(&sb, &format!("{ALLOW_ALL}{rule}"))?;
    }
    if std::path::Path::new(path).is_dir() || path == "/Users/Shared" {
        match std::fs::read_dir(path) {
            Ok(entries) => {
                emit("errno", 0);
                emit("entries", entries.count());
            }
            Err(e) => emit("errno", io_errno(&e)),
        }
    } else {
        match std::fs::read(path) {
            Ok(data) => {
                emit("errno", 0);
                emit("bytes", data.len());
            }
            Err(e) => emit("errno", io_errno(&e)),
        }
    }
    Ok(())
}

fn tmp_create(variant: &str, dir: &str) -> StepResult {
    let private = dir;
    let Some(tmp) = dir.strip_prefix("/private") else {
        return Err(Fail::Usage("expected a /private/tmp scratch dir".into()));
    };
    if !tmp.starts_with("/tmp/") {
        return Err(Fail::Usage("expected a /private/tmp scratch dir".into()));
    }
    let allowed = match variant {
        "control" => None,
        "subpath-tmp" => Some(tmp),
        "subpath-private" => Some(private),
        _ => unreachable!("checked by choice"),
    };
    if let Some(allowed) = allowed {
        let sb = sandbox()?;
        apply(
            &sb,
            &format!(
                "{ALLOW_ALL}(deny file-write* (subpath \"{private}\"))(allow file-write* (subpath \"{allowed}\"))"
            ),
        )?;
    }
    // Create through the /tmp spelling, as a user of the path would.
    match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(format!("{tmp}/x"))
    {
        Ok(_) => emit("errno", 0),
        Err(e) => emit("errno", io_errno(&e)),
    }
    Ok(())
}

fn nest(scratch: &str) -> StepResult {
    let a = format!("{scratch}/a");
    let b = format!("{scratch}/b");
    std::fs::write(&a, b"a").map_err(|e| setup(e.to_string()))?;
    std::fs::write(&b, b"b").map_err(|e| setup(e.to_string()))?;
    let sb = sandbox()?;
    let pa = compile(
        &sb,
        &format!("{ALLOW_ALL}(deny file-read* (literal \"{a}\"))"),
    )?;
    let pb = compile(
        &sb,
        &format!("{ALLOW_ALL}(deny file-read* (literal \"{b}\"))"),
    )?;
    emit("first_errno", sb.apply_path_a(&pa).err().unwrap_or(0));
    emit(
        "a_errno",
        std::fs::read(&a).err().map_or(0, |e| io_errno(&e)),
    );
    emit("second_errno", sb.apply_path_a(&pb).err().unwrap_or(0));
    emit(
        "b_errno",
        std::fs::read(&b).err().map_or(0, |e| io_errno(&e)),
    );
    emit("same_errno", sb.apply_path_a(&pa).err().unwrap_or(0));
    Ok(())
}

fn compile_inside() -> StepResult {
    let sb = sandbox()?;
    apply(&sb, ALLOW_ALL)?;
    emit("sandboxed", sb.check_self());
    emit(
        "ok",
        u8::from(
            sb.compile(
                "(version 1)(deny default)(allow file-read* (subpath \"/usr\"))",
                &[],
            )
            .is_ok(),
        ),
    );
    Ok(())
}

fn setuid_exec(variant: &str) -> StepResult {
    if variant == "caged" {
        let sb = sandbox()?;
        apply(&sb, ALLOW_ALL)?;
    }
    let spawned = Command::new(SETUID_ARGV[0])
        .args(&SETUID_ARGV[1..])
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn();
    match spawned {
        Err(e) => {
            emit("exec_errno", io_errno(&e));
        }
        Ok(mut child) => {
            emit("exec_errno", 0);
            let deadline = Instant::now() + Duration::from_secs(10);
            loop {
                match child.try_wait() {
                    Ok(Some(status)) => {
                        emit("exit", status.code().unwrap_or(-1));
                        break;
                    }
                    Ok(None) if Instant::now() < deadline => {
                        std::thread::sleep(Duration::from_millis(10))
                    }
                    _ => {
                        let _ = child.kill();
                        let _ = child.wait();
                        emit("exit", "timeout");
                        break;
                    }
                }
            }
        }
    }
    Ok(())
}

fn no_sandbox_exec(variant: &str) -> StepResult {
    let sb = sandbox()?;
    let extra = if variant == "escape" {
        "(allow process-exec (with no-sandbox))"
    } else {
        ""
    };
    apply(&sb, &format!("{ALLOW_ALL}{extra}"))?;
    emit("sandboxed", sb.check_self());
    forward("child_", &nested(&["selfcheck"], None)?);
    Ok(())
}

fn patha_contention(args: &[String]) -> StepResult {
    let trials: u32 = args
        .first()
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| Fail::Usage("trials".into()))?;
    let apply = choice(args, 1, &["apply", "control"])? == "apply";
    let sb = sandbox()?;
    let bc = compile(
        &sb,
        &format!("{ALLOW_ALL}(deny file-read* (literal \"/private/etc/hosts\"))"),
    )?;
    let prepared = sb.prepare_exec(&bc, &["/bin/cat", "/private/etc/hosts"], apply);
    let stop = Arc::new(AtomicBool::new(false));
    let churners: Vec<_> = (0..4)
        .map(|_| {
            let stop = Arc::clone(&stop);
            std::thread::spawn(move || sys::dyld_churn(&stop))
        })
        .collect();
    let (mut denied, mut ok, mut hangs, mut apply_failed, mut other) = (0, 0, 0, 0, 0);
    for _ in 0..trials {
        match prepared.spawn() {
            Err(_) => other += 1,
            Ok(pid) => {
                match sys::wait_with_timeout(pid, Duration::from_secs(3)).map(sys::exit_code) {
                    None => hangs += 1,
                    Some(Some(0)) => ok += 1,
                    Some(Some(1)) => denied += 1,
                    Some(Some(126)) => apply_failed += 1,
                    Some(_) => other += 1,
                }
            }
        }
    }
    stop.store(true, Ordering::Relaxed);
    for t in churners {
        let _ = t.join();
    }
    emit("trials", trials);
    emit("denied", denied);
    emit("ok", ok);
    emit("hangs", hangs);
    emit("apply_failed", apply_failed);
    emit("other", other);
    Ok(())
}

fn fd_parent(scratch: &str) -> StepResult {
    let path = format!("{scratch}/secret");
    std::fs::write(&path, b"0123456789abcdef").map_err(|e| setup(e.to_string()))?;
    let file = std::fs::File::open(&path).map_err(|e| setup(e.to_string()))?;
    sys::clear_cloexec(file.as_raw_fd()).map_err(|e| setup(format!("fcntl errno {e}")))?;
    let fd = file.as_raw_fd().to_string();
    forward("", &nested(&["fd-child", &fd, scratch], None)?);
    Ok(())
}

fn fd_child(args: &[String]) -> StepResult {
    let fd: i32 = args
        .first()
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| Fail::Usage("fd".into()))?;
    let scratch = scratch_arg(args, 1)?;
    let path = format!("{scratch}/secret");
    let sb = sandbox()?;
    apply(
        &sb,
        &format!("{ALLOW_ALL}(deny file-read* (literal \"{path}\"))"),
    )?;
    match sys::read_fd_len(fd) {
        Ok(n) => {
            emit("fd_errno", 0);
            emit("fd_bytes", n);
        }
        Err(e) => emit("fd_errno", e),
    }
    emit(
        "open_errno",
        std::fs::File::open(&path).err().map_or(0, |e| io_errno(&e)),
    );
    Ok(())
}

/// The compiled-once profile for per-spawn grants: writes in `scratch` are
/// denied unless an extension of [`RW_CLASS`] grants them.
fn ext_profile(scratch: &str) -> String {
    format!(
        "{ALLOW_ALL}(deny file-write* (subpath \"{scratch}\"))(allow file-write* (extension \"{RW_CLASS}\"))"
    )
}

fn ext_parent(scratch: &str, order: &str) -> StepResult {
    let sb = sandbox()?;
    for d in ["a", "b"] {
        std::fs::create_dir(format!("{scratch}/{d}")).map_err(|e| setup(e.to_string()))?;
    }
    let bc = compile(&sb, &ext_profile(scratch))?;
    std::fs::write(format!("{scratch}/profile.bin"), &bc.data).map_err(|e| setup(e.to_string()))?;
    for (run, grant) in [(0, "a"), (1, "b")] {
        let token = sb
            .issue_file_extension(RW_CLASS, &format!("{scratch}/{grant}"))
            .ok_or_else(|| setup("sandbox_extension_issue_file failed"))?;
        // The token is a capability: it goes over stdin only, never argv,
        // env or output.
        let out = nested(&["ext-child", scratch, order], Some(token.as_bytes()))?;
        forward(&format!("run{run}_"), &out);
    }
    Ok(())
}

fn ext_child(scratch: &str, order: &str) -> StepResult {
    let mut token = String::new();
    std::io::stdin()
        .read_to_string(&mut token)
        .map_err(|e| setup(e.to_string()))?;
    let data = std::fs::read(format!("{scratch}/profile.bin")).map_err(|e| setup(e.to_string()))?;
    let sb = sandbox()?;
    let bc = Bytecode {
        data,
        builtin_null: true,
    };
    let consume = |sb: &Sandbox| {
        let handle = sb.consume_extension(token.trim());
        emit("consume_ok", u8::from(handle >= 0));
    };
    if order == "consume-first" {
        consume(&sb);
    }
    sb.apply_path_a(&bc)
        .map_err(|e| setup(format!("apply errno {e}")))?;
    if order == "apply-first" {
        consume(&sb);
    }
    for d in ["a", "b"] {
        let r = std::fs::write(format!("{scratch}/{d}/f"), b"x");
        emit(&format!("{d}_errno"), r.err().map_or(0, |e| io_errno(&e)));
    }
    Ok(())
}

fn check_oracle(scratch: &str) -> StepResult {
    let x = format!("{scratch}/x");
    let y = format!("{scratch}/y");
    for p in [&x, &y] {
        std::fs::write(p, b"z").map_err(|e| setup(e.to_string()))?;
    }
    let sb = sandbox()?;
    apply(
        &sb,
        &format!(
            "{ALLOW_ALL}(deny file-read* (literal \"{x}\"))(deny mach-lookup (global-name \"com.procage.kf.denied\"))"
        ),
    )?;
    emit("read_denied", sb.check_path("file-read-data", &x));
    emit("read_allowed", sb.check_path("file-read-data", &y));
    emit(
        "mach_denied",
        sb.check_global_name("mach-lookup", "com.procage.kf.denied"),
    );
    emit(
        "mach_allowed",
        sb.check_global_name("mach-lookup", "com.procage.kf.other"),
    );
    // The kernel's own answer for the same path, as a cross-check.
    emit(
        "read_errno",
        std::fs::read(&x).err().map_or(0, |e| io_errno(&e)),
    );
    Ok(())
}

fn tiocsti(variant: &str) -> StepResult {
    // A pseudo-terminal this step owns; the inherited terminal is never used
    // (stdin is /dev/null and the child starts a new session first).
    let (master, slave) = sys::open_pty().map_err(|e| setup(format!("pty errno {e}")))?;
    if !slave.starts_with("/dev/ttys")
        || !slave
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'/')
    {
        return Err(setup("unexpected pty name"));
    }
    let out = nested(&["tiocsti-child", &slave, variant], None)?;
    forward("", &out);
    drop(master);
    Ok(())
}

fn tiocsti_child(args: &[String]) -> StepResult {
    let slave = args
        .first()
        .filter(|s| s.starts_with("/dev/ttys"))
        .ok_or_else(|| Fail::Usage("pty".into()))?;
    let variant = choice(args, 1, &["control", "caged"])?;
    sys::setsid().map_err(|e| setup(format!("setsid errno {e}")))?;
    // After setsid there must be no controlling terminal: the maintainer's
    // terminal is out of reach (ENXIO) before the probe's own pty is opened.
    emit(
        "ctty_before_errno",
        std::fs::File::open("/dev/tty")
            .err()
            .map_or(0, |e| io_errno(&e)),
    );
    let tty = sys::open_controlling_tty(slave).map_err(|e| setup(format!("ctty errno {e}")))?;
    if variant == "caged" {
        let sb = sandbox()?;
        apply(&sb, ALLOW_ALL)?;
    }
    match sys::tiocsti(&tty, b'k') {
        Ok(()) => emit("errno", 0),
        Err(e) => emit("errno", e),
    }
    let mut buf = [0u8; 8];
    let n = std::fs::File::from(tty.try_clone().map_err(|e| setup(e.to_string()))?)
        .read(&mut buf)
        .unwrap_or(0);
    emit("injected", u8::from(buf[..n].contains(&b'k')));
    Ok(())
}
