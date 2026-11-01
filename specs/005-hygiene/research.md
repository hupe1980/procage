# Research: 005-hygiene

macOS 26.6.2 (25G83), 2026-10-30.

## R1. Descriptor sweep

- **Decision**: mark, don't close. In the child, after the rlimits and before
  apply, procage:
  1. lists the open descriptors with `proc_pidinfo(getpid(), PROC_PIDLISTFDS,
     0, buf, len)` into a buffer the parent allocated;
  2. calls `fcntl(fd, F_SETFD, FD_CLOEXEC)` on each fd ≥ 3 that is not named;
  3. calls `fcntl(fd, F_SETFD, 0)` on each named fd (std's `dup2`s for 0–2
     already ran).

  `execve` then closes the marked fds. std's error pipe is already
  close-on-exec, so it keeps working until `execve` succeeds.
- **Buffer**: the parent sizes it from its own descriptor count (one
  `proc_pidinfo` call with a null buffer), times 2, plus 1,024 entries.
  Other threads may open descriptors between sizing and fork. If the child's
  call fills the buffer completely, it falls back to an `fcntl(F_SETFD)`
  sweep from 3 to `getdtablesize()`.
- **Why not a plain sweep**: the soft limit is 1,048,576 here, and
  `getdtablesize()` returns `kern.maxfilesperproc` = 184,320, so a sweep is
  184k system calls per spawn.
- **Syscalls only**: `proc_pidinfo` is a thin wrapper over the `proc_info`
  system call in libsystem_kernel (Apple's libproc source:
  `proc_pidinfo` → `__proc_info`). `fcntl` and `getdtablesize` are system
  calls.
- **Named fds**: they must be open in the parent (`fcntl(F_GETFD)` succeeds),
  otherwise `SpawnError::Fd { fd }`.

## R2. Lifetime

- **Decision**:
  - `Tty::None`: `setsid` (as in 004), so pgid = pid.
  - `Tty::Inherit`: `setpgid(0, 0)`.
  - The handle (`procage::macos::Child`) derefs to `std::process::Child`.

  Its `kill_all()`:
  1. walk descendants from the child pid with `proc_listchildpids`,
     repeating until no new pid appears (at most 8 rounds);
  2. send SIGKILL to each;
  3. `killpg(pid, SIGKILL)`;
  4. `wait()`.

  `Drop` calls `kill_all()` unless `detach()` was called, then removes the
  temp directory.
- **Reaped leader**: if the caller already waited, `killpg` still reaches the
  group's remaining members. The kernel does not hand out a pid that equals a
  live process group id, so the group cannot belong to someone else while it
  exists. The descendant walk has nothing to start from, so a reaped leader's
  setsid descendants are orphaned. Documented.
- **Double fork**: an orphaned descendant is reparented to launchd and cannot
  be found from the child. This is a documented macOS gap.

## R3. Environment filter

- **Decision**: `procage::hygiene::environment(caller_env, policy, explicit)
  -> EnvDecision { set: Vec<(OsString, OsString)>, dropped: Vec<String> }`.
  It is pure and shared with Linux.

  Under passthrough, the dropped patterns are:
  - the prefixes `DYLD_` and `AWS_`;
  - the exact names `LD_PRELOAD`, `LD_LIBRARY_PATH` and `SSH_AUTH_SOCK`;
  - the suffixes `_TOKEN`, `_SECRET`, `_PASSWORD` and `_API_KEY`.

  Explicit command variables always win, and an allowlist is taken as
  written.

## R4. Private temporary directory

- **Decision**: if the policy declares a grant named `tmpdir`, each spawn:
  1. creates a directory under the canonical `std::env::temp_dir()` with mode
     0700 (`DirBuilder` with `mode(0o700)`), named
     `procage-<pid>-<counter>-<nanos>`;
  2. binds the grant to it;
  3. sets `TMPDIR` to it unless the caller set `TMPDIR` explicitly.

  The handle removes the directory on drop. A `tmpdir` binding the caller
  passes explicitly is an error (`GrantError::Reserved`).

## R5. Testing

- The intermediary (uncaged) re-runs the test binary with a crafted
  environment, so the passthrough filter sees real `GITHUB_TOKEN`,
  `SSH_AUTH_SOCK` and `DYLD_INSERT_LIBRARIES` values. Setting variables in
  the test process itself would need `unsafe` `set_var`.
- New child actions:

  | Action | What the child does |
  |---|---|
  | `fd:N` | does `fd N` exist? |
  | `fdcount` | count of fds ≥ 3 |
  | `sleepers` | start a same-group and a setsid `/bin/sleep`, print their pids, wait |
  | `tmpdir` | write `$TMPDIR/f`, print `TMPDIR` |

- New testing helpers (in `sys`, safe wrappers):
  - `clear_cloexec(fd)`;
  - `fd_is_open(fd)`;
  - `alive(pid)`;
  - `spawn_sleeper(setsid) -> pid`.
