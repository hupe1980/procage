# Research: Exec entry

Sources: std 1.99 (`library/std/src/os/unix/process.rs`,
`sys/process/unix/unix.rs`), procage `6d05458` (`src/{macos,linux}/sys.rs`).

## R1 — std's exec runs pre_exec hooks in-process

`Command::exec` → `do_exec`: dup2 stdio, chdir, `process_group`, `setsid`
(if set on the command), SIGPIPE reset, **pre_exec closures**, environ
swap, `execvp`; returns `io::Error` on failure. A failing closure's
`io::Error` (procage's step code) is returned as-is, so `spawn::decode`
works unchanged. std documents that the process may be in a broken state
when `exec` returns.

## R2 — The step sequences are parent-free

- macOS: session, rlimits, fd marking (`proc_pidinfo` into a buffer made
  beforehand), path A apply, `sandbox_check(self)`, token consume.
- Linux: session, parent-death signal + `getppid` check, T1 `unshare` +
  self-written `setgroups`/`uid_map`/`gid_map` + mounts, capabilities,
  death signal again (T1), rlimits, fd marking, no-new-privs, Landlock,
  seccomp, verify.
- **Decision**: one shared preparation per backend; the session step takes
  a mode `New | Group | Keep`; `exec` uses `Keep`. The Linux death-signal
  check compares against the helper's parent (`getppid` at preparation).

## R3 — Threads

`unshare(CLONE_NEWUSER)` returns `EINVAL` in a multithreaded process
(user_namespaces(7)). Landlock and seccomp without TSYNC restrict the
calling thread, which is the one that calls `execvp`; the new image is
single-threaded. **Decision**: count `/proc/self/task` entries before
preparing; T1 with more than one → `Unsupported::ExecThreads { threads }`;
T2 proceeds. macOS applies per process; no limit.

## R4 — What to refuse up front

| Check | Why before | Error |
|---|---|---|
| nesting, probe | as spawn | as spawn |
| `tmpdir` grant | nothing would remove the directory | `GrantError::TmpdirWithExec` |
| T1 threads | `unshare` fails after the process changed nothing yet, but the error would be an opaque step failure | `Unsupported::ExecThreads` |
| environment decision | spec 026 | `Unsupported::EnvClear` |
| program lookup | `execvp` fails only after confinement | `SpawnError::Io` (NotFound) naming the program and search path |

Program lookup mirrors `execvp`: a name with `/` is checked relative to
the command's directory; otherwise each `PATH` entry of the child's
environment (default `/usr/bin:/bin`) for an executable regular file.

## R5 — Lifetime

No handle. Linux: under `Lifetime::Run` descendants stay in the helper's
process group (the outside code should start the helper in its own group
and kill the group), and the parent-death signal ends the command when its
parent dies. macOS: a group kill reaches descendants that stay in the
group; one that starts its own session is not reached; the run marker is
bound (forking policies need the parameters) but never searched.

## R6 — Tests

libtest runs tests on spawned threads, so a libtest test process is
multithreaded. **Decision**: `tests/exec.rs` with `harness = false`: its
`main` plays the outside code and, when `PROCAGE_EXEC` is set, the helper,
single-threaded like a real helper.
