# Research: `Exec::Never`

All measurements 2026-11-12 unless stated. macOS 26.6.2 (arm64), procage
0.7.2 at `9d48fc7`.

## R1. The defect, measured

| Policy | Result |
|---|---|
| `Base::None` + `Exec::Never` + read of `/bin/echo` | spawn fails, `EPERM` (the exec is refused) |
| `Base::None` + `Exec::Granted` + `Exec` rule on `/bin/echo` only | child aborts (status 6): dyld cannot map the system libraries |
| `Base::V3` + `Exec::Never` + `fork`, `/bin/sh -c '/bin/echo …; /usr/bin/env true'` | both run |

The plan text shows why: the base emits `(allow file-read* process-exec*
file-map-executable (subpath "/System") …)` and `Exec::Never` emits nothing
(`lower/macos.rs`, `lower/linux.rs`: only a ledger entry). Linux: the base
adds `rights(Access::Exec, handled)` with `EXECUTE` handled
(`base.rs`, `lower/linux.rs:228`), so the same holds there by
construction.

## R2. How others confine exec

- **Chromium (Linux)**: renderers are forked from a zygote and never
  exec; the seccomp-bpf policy then denies `execve`.
- **Firefox (Linux)**: the content process installs its own filter after
  start-up; anything that must fork and exec is triggered before the
  filter (Mozilla bug 1259508).
- **Kernel**: no "filter from the next exec" mode; requested on the seccomp
  list, answered with "apply the filter after the exec".
- **`AT_EXECVE_CHECK` + `SECBIT_EXEC_RESTRICT_FILE`** (Linux 6.14): an
  interpreter or loader asks the kernel whether a file may be executed.
  Closes the `ld.so <file>` route only with a cooperating loader; glibc's
  is an unmerged external patch. Not usable as the mechanism.
- **macOS**: `/usr/lib/dyld` cannot be executed directly
  (`exec format error`, measured), so Seatbelt's `process-exec` on the
  program alone leaves no loader route.

**Decision**: a library that execs an arbitrary program cannot apply its
filter after the exec. procage counts the exec in the parent instead
(R3). macOS: path allowance only; re-execution is the residual.

## R3. Counting the run's first exec on Linux

procage already has a per-run seccomp notification supervisor (spec 034):
the child installs the filter with a listener and hands it to the parent
over a `SOCK_SEQPACKET` pair before its exec.

Three facts shape the design:

1. **`std::process::Command::spawn` returns only after the exec** (std
   waits on its own close-on-exec error pipe). Today the supervisor starts
   in `Cage::adopt`, after `spawn` returns. A notifying `execve` would
   block the child, and the parent would wait in `spawn` forever. Under
   `Exec::Never` the supervisor must already run when `spawn` is called.
2. **std may issue several `execve` calls**: a bare program name goes
   through `execvp`, one call per `PATH` candidate. "Allow the first
   notification" would let the second candidate fail and a later call
   by the program succeed. Counting calls is wrong; what counts is
   whether the exec has happened.
3. **The handoff socket cannot tell**: the parent holds its copy of the
   child's end inside `spawn` until `spawn` returns, so a hang-up comes
   after the new program may already run.

**Decision: an exec sentinel made in the child.** After installing the
filter, the child creates a pipe (`pipe2(O_CLOEXEC)`), sends the read end
with the listener (`SCM_RIGHTS`, the control buffer sized in the parent
for two descriptors) and closes its read end. The write end exists only
in the child, close-on-exec. The kernel closes it in `begin_new_exec`
(`do_close_on_exec`), before the first instruction of the new program.
The supervisor answers an `execve`/`execveat` notification:

- `CONTINUE` if the sentinel has not hung up (a non-blocking `poll`): the
  call comes from procage's child code (std's `execvp`, any candidate),
  where no code of the caller runs;
- `EPERM` once it has hung up: the program, or any descendant, is
  running.

The pipe's hang-up happens-before any system call of the new program, so
there is no window. The known `CONTINUE` hazard (the target changes the
arguments after the check) does not apply: the supervisor checks no
argument, and before the hang-up only procage's code runs in the child.
Landlock bounds even those calls to the program and its interpreter.

**Alternatives rejected**:
- *Count notifications* (k = candidates before the resolved one): breaks
  when an earlier candidate is the same file (merged `/usr`, hard links),
  leaving credits to the program.
- *procage issues the `execve` itself with the resolved path*: needs the
  final `argv` (including an `arg0` override std does not expose) and the
  environment std builds; a second copy of std's exec.
- *Instruction-pointer or pointer-value filters*: the program can map a
  page at the same address.
- *Supervisor checks the path and `CONTINUE`s the program only*: the
  documented TOCTOU of `CONTINUE`.
- *Require a path with `/` under `Exec::Never`*: still std's single call,
  but does not solve fact 1 and makes bare names fail.

## R4. Where no supervisor can run

- **An outer listener**: `SECCOMP_FILTER_FLAG_NEW_LISTENER` fails with
  `EBUSY` when an enclosing filter already has one (measured in spec 034).
  Today the child then installs the plain filter. Under `Exec::Never` a
  plain filter with the exec rules would refuse even the first exec
  (`ENOSYS` without a listener), and dropping them silently would weaken
  the run. The child fails the spawn with the errno, unless the plan
  carries the accepted approximation; then it installs the plain filter
  without exec rules (Landlock alone).
- **`Cage::exec`**: the calling process becomes the command; there is no
  parent to supervise. Known before anything is applied: a typed gap
  unless accepted.

The probe runs once per cage (a forked child tries `NEW_LISTENER`), not
once per process: a cached answer goes stale when the process installs a
filter later. A spawn that still meets `EBUSY` fails closed.

**Decision**: one construct, `exec-never` on Linux, with the outcome
`Approximated` when no supervisor runs, accepted by name through
`LowerOptions` like the other spawn approximations; an accepted run lists
it in its receipt.

## R5. The program allowance

- **Resolution**: `unix::find_program` (as `execvp`, after the
  environment is final), already used by `Cage::exec`.
- **Scripts**: the first two bytes `#!` → refused (a typed error) under
  `Exec::Never`; allowing the interpreter would allow every script.
- **Linux**: the kernel opens the program and its `PT_INTERP` with
  `open_exec` (`__FMODE_EXEC`, read), so Landlock must grant `EXECUTE` and
  `READ_FILE` on both. The rules are opened by descriptor in the parent
  (inode-bound): a file swapped in at the path afterwards is not covered.
  `PT_INTERP` is read from the ELF program headers, bounded (header ≤ 64
  bytes, ≤ 64 program headers, interpreter path ≤ `PATH_MAX`), fuzzed.
  The interpreter must be absolute and a regular file.
- **macOS**: the allowance rides on the per-spawn grant mechanism
  (extension tokens of a procage class), so the cached profile is not
  recompiled per program. Details in the plan.

## R6. Two settings, one contract each (clarification 2026-11-12)

- `Exec::Never`: no exec after start. Linux exact via R3; macOS: Seatbelt
  cannot count, the program may execute itself again — stated in the
  docs, recorded as decision `decision.macos-reexec` (UX and DX first; an
  opt-in for a small, stated limit would be friction without safety).
- `Exec::Program`: the program only, any number of times. macOS exact
  (no loader route, R2). Linux: the interpreter must stay executable and
  can start any readable ELF, and a supervised path check would be the
  `CONTINUE` race, so the lowering reports `Approximated`; one
  `LowerOptions::allow` accepts it.
- Rejected: a flag on `Never` (two meanings in one variant, nested serde
  and bindings shapes); per-program exactness for static ELF files on
  Linux (spawn-time outcome changes for little gain).

## R7. macOS allowance without recompiling

Grants already issue `sandbox_extension_issue_file` tokens per spawn for
classes `procage.<grant>` and the profile allows `(extension "<class>")`;
the PTY uses the dotted class `procage.pty.device`. A dotted class
`procage.exec.program` cannot collide with a grant name (grant names
have no dot), needs no recompile, and the cached profile serves every
program. A `(param …)` literal would compile once per distinct program
(~7–12 ms the first time).

## R8. Explain, receipts, bindings

- **Explain** shares `emit` with the profile (macOS) and the rights with
  the ruleset (Linux): once the base loses exec, exec questions answer
  denied by construction; the program class maps to no grant. The
  oracle's `runnable()` must not add an `Exec` rule under the two
  settings (it would be `ExecConflict`).
- **Receipts** keep version 1: the exec mode is part of the policy (and
  its digest); accepted approximations already appear in
  `approximations`. A program path in the receipt would break the rule
  that paths appear only with `with_policy_in_receipt`.
- **Bindings** read the policy JSON, so `"program"` needs no new API.
  Accepting an approximation needs a spelling: a generic `allow` list of
  construct names, as `LowerOptions::allow`, rather than one flag per
  construct.
