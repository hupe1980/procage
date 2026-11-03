# Implementation Plan: A fresh pseudo-terminal for interactive runs

**Branch**: `022-pty` (local planning; commits on `main`) | **Date**: 2026-11-03 | **Spec**: [spec.md](spec.md)

## Measured before planning (macOS 26.6.2)

- `posix_openpt(O_RDWR | O_NOCTTY | O_CLOEXEC)` returns a close-on-exec
  controller; `ioctl(TIOCPTYGNAME)` names the device (`/dev/ttysNNN`).
- On Linux the same call works (glibc passes the flags to `/dev/ptmx`);
  `ioctl(TIOCGPTN)` gives the number of `/dev/pts/N`.

## Design

### The pair (parent)

1. **Open.** Each `sys` module gets `open_terminal() -> (controller,
   device, path)`: `posix_openpt(O_RDWR|O_NOCTTY|O_CLOEXEC)`, `grantpt`,
   `unlockpt`, the name (`TIOCPTYGNAME` on macOS, `TIOCGPTN` on Linux), and
   the device opened `O_RDWR|O_NOCTTY|O_CLOEXEC`. Every descriptor is
   close-on-exec from its first instant, so a concurrent fork elsewhere in
   the caller cannot inherit it. The window size is set to 80 by 24
   (`TIOCSWINSZ` on the controller) before the child starts. The existing
   test helper `testing::open_pty` (which uses `openpty`) moves onto it.
2. **Stdio.** The device is duplicated (close-on-exec) into the command's
   stdin, stdout and stderr; whatever the caller set there is replaced.
   After `Command::spawn` returns, the parent replaces the three with
   `Stdio::null()`, which closes its copies: the controller then reads EOF
   or EIO once every process of the run has gone.
3. **Handle.** A new public `Pty` (in a shared `pty` module, no `unsafe`;
   the ioctls live in the `sys` modules) owns the controller:
   `Read` and `Write` (also on `&Pty`), `AsFd`, `AsRawFd`,
   `From<Pty> for OwnedFd`, `device() -> &Path`, and
   `set_size(rows, cols)`. Its rustdoc says the bytes are the cage's
   untrusted output, escape sequences included, unfiltered (SR-007).
   `Child::take_pty()` and `AsyncChild::take_pty()` hand it over once; the
   child handle keeps it until then, so dropping the handle closes it.

### The child

4. **Session.** `sys::Session` gains `Terminal`: `setsid()` then
   `ioctl(0, TIOCSCTTY, 0)`; failures report the existing session step.
   Two system calls on descriptor 0, which std has already set to the
   device before `pre_exec` runs. No new step code. Full sequence with a
   new terminal: `setsid`, `ioctl(TIOCSCTTY)`, then the platform's existing
   steps unchanged.
5. **Exec.** `Cage::exec` and `Cage::exec_session` refuse `Tty::NewPty`
   with `Unsupported::Setting` before any change (SR-006).

### The grant

6. **macOS.** The lowering emits, for `Tty::NewPty` and independent of the
   base, an allow of `file-read*`, `file-write-data` and `file-ioctl` on
   `(extension "procage.tty")` and on `(literal "/dev/tty")` (which names
   the child's controlling terminal). Each spawn issues a file extension of
   that class for its device, as grants do. Base V1 to V3 fixtures are
   unchanged: the `Tty::Inherit` rules are not reused (they allow every
   `/dev/ttys*`). If the kernel refuses an extension on a device file, the
   spawn binds the device literal as a profile parameter instead (measured
   first; the decision is recorded here).

   *Measured (macOS 26.6.2):* the extension on `/dev/ttysN` works; no
   parameter fallback is needed. *Decision (implementation):* the rule
   also allows `file-read*` on the literal `/dev` (the directory, no
   device): `ttyname` lists it, and without it `tty` says "not a tty" and
   programs that name their terminal fail.
7. **Linux.** The lowering adds `/dev/tty` (read, write, `IOCTL_DEV`) for
   `Tty::NewPty`; each spawn adds a Landlock rule for exactly its device
   (`/dev/pts/N`) with the same rights, next to the bound grants. Below
   Landlock ABI 5 `IOCTL_DEV` is not handled, so ioctls are not limited by
   Landlock there (as for every device today). The `/dev/pts` subpath of
   `Tty::Inherit` is not used.
8. **Injection.** The terminal-injection class stays in force: TIOCSTI
   fails on the child's own terminal too (seccomp on Linux, the ioctl
   filter on macOS) unless the caller waives it by name (SR-002). With
   `Lifetime::Run` Linux keeps denying `setsid` after the child's own;
   `setpgid` stays allowed (it is denied only with `Tty::Inherit`), so a
   shell's job control works inside the session the run kills.

### Records

9. **Tests** (the kernel is the oracle; every lane):
   - `pty.rs`, one file for both systems through `procage::native` (T1
     and T2 on Linux; *decision (implementation)*: the scenarios are the
     same, so one file replaces the two planned): an interactive shell
     (`/bin/sh -i`: a command answered through the controller, `test -t 0`
     in the child, the terminal is the controlling one); a REPL
     (`python3 -i`, present on every lane and in the test container); a
     full-screen program (`vi` where the lane ships it, otherwise `top`,
     which the test container ships; the quickstart records which ran);
     the run ending kills a background job; no base profile still gives a
     usable terminal (on macOS no program starts without a base, so base
     V1, which has no terminal rule, stands in); exec and exec_session
     refuse. The full-screen test sets `TERM` as a harness would (the
     environment allowlist drops it) and grants `/proc` to `top`.
   - Escape suites, R-22: with `Tty::NewPty`, TIOCSTI on the own terminal
     fails, and waived reaches only the controller; another terminal the
     test opened cannot be opened by the child. On macOS TIOCSTI also needs
     `hid-control`; the canary allows it, as R-22's first canary does, so
     the class alone refuses. On Linux since 6.2 the waived control may
     still fail without CAP_SYS_ADMIN (`dev.tty.legacy_tiocsti`). R-22's evidence column
     gains these.
   - Descriptors: two concurrent runs from two threads; each child's open
     descriptors contain neither controller nor the other run's terminal
     (SR-003). The multithreaded spawn test spawns with `Tty::NewPty`
     (SR-004).
10. **Docs.** README known limits drop "no pseudo-terminals"; THREAT_MODEL's
    "does not provide pseudo-terminals" goes, R-22's row names the new
    canaries; site macOS/Linux pages describe the terminal and its grant;
    changelog for 0.5.0.

### Found during implementation

11. **Marker search race (macOS).** The concurrent new-terminal test
    showed a run killed with SIGKILL by another run's end: the marker
    search asked whether a process allows the run's marker, then whether it
    allows the probe, and a process another run had just forked applied its
    sandbox between the two checks (unsandboxed it allows both). The probe
    is now checked first; a process only ever gains a sandbox, so a denied
    probe means the marker check sees the same sandbox. Measured: about one
    test run in three failed before, none in 20 after. *Decision
    (implementation):* fixed here, since the spec's concurrency test
    cannot pass without it; it is not specific to terminals.

## Constitution Check

| Principle | Check | Status |
|---|---|---|
| I | A setting procage cannot honour (exec with a new terminal) is a typed error; the grant is exactly one device | PASS |
| II | `Pty` is a typed handle; the device path is never matched as a string pattern | PASS |
| III | Every claim (shell, REPL, full-screen, other terminals unreachable) has a caged test on every lane | PASS |
| IV | The child adds `ioctl(TIOCSCTTY)` after `setsid`: system calls only, in `sys`; the multithreaded spawn test uses a new terminal | PASS |
| V | Only stdio and declared fds reach the child; the controller is close-on-exec from creation; the caller asked for this terminal | PASS |
| VI | No private interface added | PASS |
| VII | Additive API (`Pty`, `take_pty`); no global state; 0.5.0 | PASS |

**Remaining gaps**: terminal output filtering is the caller's (documented);
below Landlock ABI 5 terminal ioctls on the own device are not limited by
Landlock (TIOCSTI is still denied by seccomp).
