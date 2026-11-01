# Research: 034-linux-violations

Measured in Docker (Linux 7.0.14-linuxkit, aarch64, default seccomp profile
= tier T2 conditions), C probe in the scratchpad, 2026-11-01.

## R1 — The notification protocol works unprivileged in the lanes

- `seccomp(SET_MODE_FILTER, NEW_LISTENER)` after `no_new_privs` returned a
  listener; a second filter with a listener in the same chain failed with
  `EBUSY` (16).
- A notified `getppid` blocked until the parent answered `error = -EPERM`;
  the child saw `-1/EPERM` (3.4 ms including the parent's start-up).
- The listener reported `POLLHUP` once the child had exited (before it was
  reaped).
- **Decision**: user notification for every `EPERM` rule when reporting is
  on; completeness from `POLLHUP` (no timing assumption). KF-L15 pins all
  four facts on both tiers.

## R2 — Can a caged process take the listener?

- The child closes its copy (created close-on-exec) after sending it.
- Reopening the parent's listener through `/proc/<ppid>/fd/<n>`: refused,
  `ENXIO` as root, `EACCES` as an ordinary user.
- `pidfd_getfd` on the parent: `EPERM`; procage's process-access class
  refuses it (and `ptrace`) anyway. Waiving that class already lets the
  child control its unsandboxed parent, so the listener adds no hole.
- **Decision**: escape canary R-32 (listener hijack) with `/proc` granted.

## R3 — Answer semantics

- `SECCOMP_USER_NOTIF_FLAG_CONTINUE` would let the call run: never set.
  The answer is built in one function (`-EPERM`, value 0, flags 0) and sent
  before anything is recorded.
- A supervisor that is gone makes the kernel answer `ENOSYS`: still refused.
- A notification withdrawn by a signal makes `NOTIF_SEND` fail with
  `ENOENT`: ignored. The process name is read from `/proc/<pid>/comm` while
  the caller blocks, then checked with `NOTIF_ID_VALID`.

## R4 — Reasons

Rule origins in `lower/linux.rs`: hard-deny classes (process access,
terminal injection, kernel surface, namespaces, socket families), `Network::
None` (socket), no fork (fork, vfork, clone), `Lifetime::Run` (setsid,
setpgid), `Signals::None` (kill family), SysV IPC, the truncation guard below
ABI 3, the raw layer. **Decision**: `SeccompRule::reason: Option<DenyReason>`
(None = not granted); `DenyReason` gains `Lifetime` and `OlderKernel`.

## R5 — Alternatives

- Landlock audit (ABI 7): privileged reader (`CAP_AUDIT_READ`); rejected.
- `SECCOMP_RET_TRAP` (SIGSYS in the child): changes the child's behaviour and
  reports to nobody outside; rejected.
- `SECCOMP_FILTER_FLAG_LOG`: audit log again; rejected.
