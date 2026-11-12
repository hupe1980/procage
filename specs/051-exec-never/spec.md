# Feature Specification: `Exec::Never` and `Exec::Program` — the child executes only its program

**Feature Branch**: `051-exec-never` (planning directory; commits land on `main`)

**Created**: 2026-11-12

**Status**: Implemented (2026-11-12)

**Input**: `Exec::Never` means the caged child can execute nothing but the program it was started as. Callers that run untrusted code in a process that needs no other programs (a JIT engine's content process, an evaluator for model-written code, a document or image converter) want a tight base + `Exec::Never`: start one binary, then never execute anything again. Checking such a design against procage 0.7.2 found that `Exec::Never` does not do what it says. Programs that re-execute themselves (Python `multiprocessing`, Node's `child_process.fork`, Go's `/proc/self/exe`) need a second setting: the program only, as often as it likes. Agent harnesses and build tools, which run shells and compilers, keep `Exec::Granted` or `Exec::Any` and are not affected.

## Context

`Exec::Never` is documented as "Nowhere (no `Exec` rule or grant may
exist)", and `explain` reports the construct `exec-never` as exact on every
backend. Measured on 2026-11-12 (macOS 26.6.2, procage 0.7.2):

1. **With any base it is not "nowhere".** Every base (V1–V3) allows
   execution in the system code directories (`process-exec*` on macOS,
   Landlock `EXECUTE` on Linux), and `Exec::Never` removes none of it. A
   caged `/bin/sh` under `Base::V3` + `Exec::Never` + `fork` ran
   `/bin/echo` and `/usr/bin/env`.
2. **Without a base it cannot start anything.** procage executes the
   program after the cage is in place, and under `Exec::Never` no rule or
   grant may allow execution. `Base::None` + `Exec::Never` fails every
   spawn with `EPERM`.

No caged test covers `Exec::Never`; the lowering table's "exact" was taken
from the profile text, not from the kernel. Both defects are a claim
procage makes about enforcement that the kernel contradicts (principles I
and III).

The program is known only at spawn, so the allowance to execute it is per
spawn, like a grant.

## Clarifications

### Session 2026-11-12

- Q: On Linux the program's ELF interpreter must be executable, and a
  process that may execute it can run `ld.so /bin/sh` (any readable ELF);
  re-executing the program is open too. How is `Exec::Never` enforced
  there? → A: Landlock allows execution of the program and its interpreter
  only, and a seccomp notification supervisor allows exactly the exec
  procage's own child code issues before any code of the caller runs.
  Every later `execve` and `execveat` of the run is refused. Where no
  supervisor can run (an outer seccomp listener makes the kernel refuse a
  new one; `Cage::exec`, which leaves no parent), it is a typed gap the
  caller may accept by name; Landlock alone then applies and the receipt
  (where the run has one) lists the approximation.
  Research behind the answer (2026-11-12): browsers never let the
  sandboxed program exec (Chromium forks renderers from a zygote; Firefox
  installs its filter in the content process after start-up); the kernel
  has no "filter from the next exec" mode (requested on the seccomp list,
  answered with "install it after the exec"); `AT_EXECVE_CHECK` and
  `SECBIT_EXEC_RESTRICT_FILE` (Linux 6.14) close the loader route only
  with a cooperating loader, and glibc has none; the notification
  supervisor's known race (`CONTINUE` with arguments the target can
  change) does not apply, since nothing but procage runs in the child
  before its first exec. On macOS `/usr/lib/dyld` cannot be executed
  directly (`exec format error`, measured on 26.6.2), so there is no
  loader route.
- Q: procage serves harnesses, dev tools and language runtimes, and many
  programs re-execute themselves. Does `Exec::Never` mean "no exec after
  start" or "the program only, any number of times"? → A: No exec after
  start.
- Q: Should both cases be supported? → A: Yes: a new `Exec::Program`
  ("the program only, as often as it likes") next to `Exec::Never` ("no
  exec after start").
- Q (scope rule, recorded by the user: UX and DX first, no
  overengineering): How are the platform limits presented? → A: As the
  documented contract of each setting, without opt-ins where the limit is
  small and stated: on macOS the profile cannot count executions, so
  under `Exec::Never` the program may execute itself again (the
  `Exec::Never` docs say so, as `Lifetime::Tree` documents its macOS
  behaviour). Acceptance by name stays only where the setting would
  otherwise allow other programs: `Exec::Never` without a supervisor on
  Linux, and `Exec::Program` on Linux, whose ELF interpreter can start any
  readable ELF file. The gap's message names the one call that accepts
  it. No new receipt field: the exec mode is in the policy, accepted
  approximations are already listed.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Nothing else can be executed (Priority: P1)

A caller who chooses `Exec::Never` or `Exec::Program` gets a child that
cannot start any other program, whatever base the policy has.

**Why this priority**: it is the defect. The setting promises a boundary
the kernel does not draw.

**Independent Test**: spawn a shell under each setting with each base on
macOS, T1 and T2, and have it try to execute system programs.

**Acceptance Scenarios**:

1. **Given** `Base::V1`, `V2` or `V3` with `Exec::Never` or `Exec::Program`
   and `fork`, **When** the caged shell executes `/bin/echo`,
   `/usr/bin/env` or `/bin/sh`, **Then** each execution is refused, on
   macOS, T1 and T2.
2. **Given** the same policy with `Exec::Granted` (positive control),
   **When** the shell executes `/bin/echo`, **Then** it runs, so the refusal
   above comes from the setting and not from the host.
3. **Given** either setting, **When** a descendant forked by the child
   executes a system program, **Then** it is refused too.
4. **Given** `Exec::Never` on T1 or T2 and a dynamically linked program,
   **When** it executes its ELF interpreter directly (`ld.so /bin/echo`)
   or executes itself again, **Then** both are refused.

---

### User Story 2 - The program itself starts (Priority: P1)

A caller can start a program under either setting, with or without a
base, through every spawn entry point.

**Why this priority**: without it `Exec::Never` is unusable under
`Base::None`, which is exactly the configuration a tight cage wants.

**Independent Test**: spawn a program under `Base::None` with read access
to what it needs, and under each base; it runs and exits with its own
status.

**Acceptance Scenarios**:

1. **Given** `Base::None` + `Exec::Never` on Linux and read access to a
   program and what it loads, **When** it is spawned, **Then** it runs. On
   macOS (where every program maps the system's code, which only a base
   allows when no `Exec` rule may exist) the cage is refused with a gap
   that names `Base::V1`; with `Base::V1` the program runs.
2. **Given** a base + either setting, **When** a program from the system
   code directories is spawned by bare name, **Then** it is found as
   `execvp` finds it and runs.
3. **Given** `Exec::Never`, **When** `Cage::exec` replaces the calling
   process with a program, **Then** on macOS it runs and cannot execute
   another program; on Linux it is a typed gap unless accepted by name.
4. **Given** either setting and a program that is a script (`#!`),
   **When** it is spawned, **Then** the spawn is refused before forking
   with an error that names the cause.

---

### User Story 3 - A program that re-executes itself works (Priority: P2)

A caller who runs a program that starts copies of itself (Python
`multiprocessing` with spawn or forkserver, Node's `child_process.fork`,
`/proc/self/exe`) chooses `Exec::Program` and gets exactly that.

**Why this priority**: the second common case; without it such callers
fall back to `Exec::Granted` with a base, which allows every system
program.

**Independent Test**: a caged program executes itself again under
`Exec::Program` and fails to execute `/bin/echo`.

**Acceptance Scenarios**:

1. **Given** `Exec::Program` on macOS, **When** the program executes
   itself, **Then** it runs; `/bin/echo` is refused.
2. **Given** `Exec::Program` on Linux without accepting the approximation,
   **When** the cage is created, **Then** it fails with a gap whose message
   names how to accept it; accepted, the program executes itself and
   `/bin/echo` is refused.

---

### User Story 4 - What procage reports is what the kernel does (Priority: P2)

`explain`, the lowering table, the receipt and the bindings describe both
settings, and `explain` agrees with the kernel.

**Why this priority**: the defect came from a report that was never checked
against the kernel.

**Independent Test**: `explain` the execution of a system program under
each setting; compare with a caged attempt.

**Acceptance Scenarios**:

1. **Given** either setting, **When** `explain` asks whether a system
   program may be executed, **Then** it answers denied, and the caged
   attempt is refused.
2. **Given** the Python and Node.js bindings, **When** a policy with exec
   `"never"` or `"program"` is spawned there, **Then** it behaves as in
   Rust, and an approximation can be accepted there.

### Edge Cases

- **Re-executing the same program under `Exec::Never`**: refused on Linux
  (one exec per run). On macOS the profile cannot count executions, so the
  program may execute itself again; the `Exec::Never` docs state it.
- **The program lives in a writable tree**: on Linux under `Exec::Never` a
  changed program cannot be executed again. Elsewhere the child could
  change it and execute it again, which runs no more than the child already
  can (same confinement); documented.
- **`ld.so` invoked directly** on Linux: refused under `Exec::Never` (every
  exec after the first); possible under `Exec::Program`, which is why that
  setting is an approximation on Linux.
- **No supervisor possible** on Linux under `Exec::Never` (an outer
  listener, `Cage::exec`): a typed gap; accepted by name, Landlock alone
  applies (as `Exec::Program`), listed in the receipt.
- **With violation reporting on**: a refused exec is reported like any
  other refused call.
- **The program is reached through a symlink or a relative path**: the
  allowance names the file the resolution reaches, as `execvp` would.
- **The program is not found or not executable**: refused before forking,
  as `Cage::exec` already does.
- **Linux, dynamically linked program**: the kernel also checks the
  program's ELF interpreter (`PT_INTERP`), which Landlock must allow too;
  under `Exec::Never` the supervisor keeps it from being executed on its
  own afterwards.
- **The program is replaced between the check and the execution**: on
  Linux the allowance stays with the file that was checked.
- **macOS without a base**: every macOS program (Go binaries included)
  maps the system's libraries, which needs map rights only a base (or an
  `Exec` rule, forbidden here) gives; measured 2026-11-12: dyld aborts
  (status 6). The lowering refuses the combination (gap `exec-never` /
  `exec-program`, unsupported) with a message that names `Base::V1`.
- **macOS `/bin/sh`** is a launcher that executes another shell, so under
  either setting it cannot be the program; name the shell itself
  (`/bin/bash`, `/bin/zsh`).
- **`Exec::Granted` and `Exec::Any`** keep their meaning.
- **A frozen preset**: none uses `Exec::Never`; none gains `Exec::Program`.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: Under `Exec::Never` and `Exec::Program` no process of the run
  MUST be able to execute any file other than its program, on macOS, T1
  and T2, whatever the base.
- **FR-002**: Under `Exec::Never` on Linux no process of the run MUST be
  able to execute anything after the run's first exec, the interpreter and
  the program itself included. On macOS the program may execute itself
  again, as documented.
- **FR-003**: On Linux, `Exec::Never` without a supervisor (an outer
  seccomp listener, `Cage::exec`) and `Exec::Program` MUST be typed gaps
  unless the caller accepts them by name; the gap's message MUST name the
  call that accepts it, and an accepted approximation MUST be listed in the
  receipt where the run has one (`Cage::exec` has no handle and no receipt).
- **FR-004**: Under both settings the base rules MUST keep their read and
  map rights and lose their execute rights.
- **FR-005**: Every spawn entry point (`spawn`, `spawn_with_fds`, the async
  variants, `Cage::exec` and its variants) MUST allow the execution of the
  program, resolved as `execvp` resolves it, for that spawn only, unless
  the setting is a gap there (FR-003).
- **FR-006**: On Linux the allowance MUST stay with the file that was
  resolved, not a file put at the same path later.
- **FR-007**: A program that starts with `#!` MUST be refused under both
  settings before forking, with a typed error.
- **FR-008**: Both settings MUST refuse policies with an `Exec` rule or
  grant (`PolicyError::ExecConflict`).
- **FR-009**: `explain` MUST answer for execution under both settings as
  the kernel decides, checked by a caged test.
- **FR-010**: The `Exec` docs, the lowering table, the threat model, the
  bindings (policy JSON `"program"`, a way to accept an approximation by
  name) and the changelog (Security) MUST describe both settings, their
  platform contracts, and the migration for callers who relied on
  executing system programs under a base + `Exec::Never`.
- **FR-011**: `Exec::Granted` and `Exec::Any` MUST behave as before (their
  existing tests unchanged).

### Key Entities

- **Program allowance**: the one file a run may execute under either
  setting — the resolved program (plus, on Linux, the ELF interpreter the
  kernel loads for it), bound per spawn. Under `Exec::Never` on Linux it is
  used once: the run's first exec.

<!-- threatspec:begin -->
### Security Requirements *(managed by ThreatSpec — edit threat-model.yaml)*

- **SR-001** (P1): Under Exec::Never and Exec::Program no process of the run MUST be able to execute any file other than its program (and, on Linux, that program ELF interpreter), whatever the base, on macOS, T1 and T2.
  - Mitigates: `threat.base-exec-under-never` via `mitigation.never-strips-base-exec`
  - Given Base V1, V2 or V3 with Exec::Never or Exec::Program and fork, on macOS, T1 and T2, when the caged shell and a descendant it forks execute /bin/echo, /usr/bin/env and /bin/sh, then every execution is refused, while the same probes under Exec::Granted run
  - Given Base::None with Exec::Never and read access to what the program loads, when the program is spawned, then it runs and exits with its own status
  - Given Exec::Never on T1 and T2 and a dynamically linked program, when it executes its ELF interpreter directly (ld.so /bin/echo) or executes itself again, then both are refused
- **SR-002** (P1): The program allowance MUST hold for its own spawn only and MUST NOT let another run of the same cage execute that program.
  - Mitigates: `threat.allowance-crosses-runs`, `threat.program-path-replaced` via `mitigation.allowance-per-spawn`
  - Given one cage under Exec::Never and two spawns of different programs A and B, when the run of A tries to execute B, then it is refused
  - Given Exec::Program on Linux and a program in a writable tree, when the program replaces its own file by rename and executes the path again, then the exec is refused (the rule holds the original inode)
- **SR-003** (P1): Under Exec::Never and Exec::Program a program that starts with '#!' MUST be refused before forking with a typed error.
  - Mitigates: `threat.script-interpreter` via `mitigation.refuse-scripts`
  - Given Exec::Never and an executable shell script as the program, when it is spawned or passed to Cage::exec, then the call fails before forking with an error naming the script
- **SR-004** (P1): explain MUST answer for execution under Exec::Never and Exec::Program as the kernel decides.
  - Mitigates: `threat.report-disagrees` via `mitigation.kernel-checked-reports`
  - Given Exec::Never with a base, when explain asks whether /bin/echo may be executed and a caged shell tries it, then both say denied
- **SR-005** (P1): The lowering table and the Exec docs MUST state each setting per platform (exact, approximated, and the macOS re-execution under Exec::Never), and an accepted approximation MUST be listed in the receipt.
  - Mitigates: `threat.report-disagrees` via `mitigation.kernel-checked-reports`
  - Given the lowering table, when the table test compares it with the lowering on every target, then exec-never and exec-program match their outcomes
  - Given an accepted exec-program approximation on Linux, when the run receipt is read, then its approximations list exec-program
- **SR-006** (P2): Reading the program header MUST be bounded and MUST NOT panic on any input; an interpreter that is not an absolute path to an existing regular file MUST fail the spawn.
  - Mitigates: `threat.hostile-program-header` via `mitigation.bounded-header-parse`
  - Given arbitrary bytes as the program file, when the header reader runs (fuzz target), then it returns a value or a typed error, never panics, and reads no more than its bound
  - Given an ELF whose interpreter is relative, missing or a directory, when it is spawned under Exec::Never, then the spawn fails before forking with a typed error
- **SR-007** (P1): On Linux under Exec::Never exactly one exec MUST succeed per run, the one procage issues to start the program; every later execve and execveat of any process of the run MUST be refused.
  - Mitigates: `threat.first-exec-claimed`, `threat.interpreter-route`, `threat.program-path-replaced` via `mitigation.one-exec-supervisor`
  - Given Exec::Never on T1 and T2, when the program, after it started, executes itself, its interpreter and /bin/echo, and a forked descendant does the same, then every call fails with EPERM and the program had started
  - Given Exec::Never with violation reporting on, when the program executes /bin/echo, then the refusal is reported as a violation
- **SR-008** (P1): On Linux, Exec::Never where the one-exec supervisor cannot be installed and Exec::Program MUST fail as typed gaps unless the caller accepted the approximation by name; the gap message MUST name the accepting call.
  - Mitigates: `threat.program-loader-route`, `threat.supervisor-unavailable` via `mitigation.no-supervisor-is-a-gap`
  - Given Exec::Never and Cage::exec on Linux, when it is called without accepting the approximation, then it fails before the cage is applied with the gap named
  - Given an outer seccomp listener (simulated) and Exec::Never, when a run is spawned, then it fails with the gap; with the approximation accepted it runs and its receipt names it
  - Given Exec::Program on Linux, when the cage is created without accepting exec-program, then it fails with a gap whose message names the call that accepts it
- **SR-009** (P1): A spawn under Exec::Never on Linux MUST NOT block on its own exec, and the exec sentinel MUST NOT reach the program or any descendant.
  - Mitigates: `threat.sentinel-leak`, `threat.supervisor-late` via `mitigation.supervisor-before-spawn`
  - Given Exec::Never on T1 and T2 with and without violation reporting, from a parent with 8 threads spawning concurrently, when 100 programs are spawned, then every spawn returns and every program runs
  - Given Exec::Never, when the program lists its open descriptors, then only stdio and declared descriptors are open, and an exec it tries is refused
<!-- threatspec:end -->

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: Under either setting, 0 of the probed system programs can be
  executed from a caged shell, with each base, on macOS, T1 and T2; with
  `Exec::Granted` all of them can. Under `Exec::Never` on T1 and T2, 0
  execs succeed after the first, the ELF interpreter and the program
  itself included.
- **SC-002**: A program starts under `Base::None` + `Exec::Never` on Linux
  and under `Base::V1` + `Exec::Never` on macOS; before this change 0
  programs could start under `Base::None` + `Exec::Never`.
- **SC-003**: A cached-cage spawn under `Exec::Never` costs no more than
  0.5 ms over the same spawn under `Exec::Granted` (median, 300 spawns).
- **SC-004**: `explain` and the kernel agree on every exec probe of the
  new tests.
- **SC-005**: Choosing a setting takes one line of policy; accepting a
  Linux approximation takes one line, which the gap's message spells out.

## Assumptions

- The change tightens behaviour: a caller who executed system programs
  under a base + `Exec::Never` relied on the defect. It ships in a minor
  version with a Security changelog entry and a migration note
  (`Exec::Program` for self-re-executing programs, `Exec::Granted` with
  `Exec` rules for other programs).
- `Exec::Program` is a new variant of the `Exec` enum (serde `"program"`);
  callers matching on `Exec` exhaustively update one match (noted in the
  migration).
- On Linux the run's first exec is recognised by procage's seccomp
  notification supervisor (Linux 5.5+ for `CONTINUE`; procage already
  needs 5.13). Both settings limit the exec call, not code: a process that
  can read and map a file can run its code without exec on both systems.
- Scripts are refused rather than allowing their interpreter: allowing an
  interpreter would let the child run any script it can read.
- The per-spawn allowance reuses the grant path each backend already has.
