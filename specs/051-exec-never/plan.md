# Implementation Plan: `Exec::Never` and `Exec::Program`

**Branch**: `051-exec-never` (local planning; commits on `main`) | **Date**: 2026-11-12 | **Spec**: [spec.md](spec.md)

## Summary

Both settings strip exec from the base and allow the spawned program by a
per-spawn allowance that reuses each backend's grant path. On Linux,
`Exec::Never` adds a one-exec rule enforced by the existing seccomp
notification supervisor, which now starts before the spawn and tells the
run's own exec from any later one by a close-on-exec sentinel the child
makes ([research R3](research.md#r3-counting-the-runs-first-exec-on-linux)).
`Exec::Program` on Linux is an approximation accepted by name (the ELF
interpreter can start any readable ELF). Every new mechanism is an existing
one extended: grant slots, the supervisor, backend-raised gaps, receipt
approximations. No new receipt field, no new crate.

| Setting | macOS | Linux T1/T2 |
|---|---|---|
| `Exec::Never` | exact; documented: the program may execute itself again | exact (supervised); approximated where no supervisor can run (outer listener, `Cage::exec`) |
| `Exec::Program` | exact | approximated (interpreter route), accepted by name |

## Technical Context

**Language/Version**: Rust 1.99 (edition 2024)
**Primary Dependencies**: `libc` 0.2.191 (`SECCOMP_USER_NOTIF_FLAG_CONTINUE`, `pipe2`); no new dependency
**Storage**: N/A
**Testing**: `cargo test` (macOS lanes), Docker T1/T2 lanes (`just linux`, `just linux-t1`), oracle, lowering table, fuzz (`cargo fuzz`, new target `elf`)
**Target Platform**: macOS 26 (arm64), Linux ≥ 5.13 (Landlock ABI 1+)
**Project Type**: library (+ Python and Node.js bindings)
**Performance Goals**: SC-003 — `Exec::Never` spawn ≤ +0.5 ms median over `Exec::Granted`
**Constraints**: constitution IV (child code: syscalls only, prepared in the parent)
**Scale/Scope**: two crates, two bindings, docs; ~one new module (`elf`)

## Design

### Policy crate (`procage-policy`)

1. **`Exec::Program`** (`policy.rs`), serde `"program"`; `validate`
   refuses an `Exec` rule or grant with `Program` as with `Never`
   (`ExecConflict`, message names the setting).
2. **`Construct::ExecProgram`** (`"exec-program"`).
3. **Base without exec** (`lower/macos.rs`, `lower/linux.rs`): under
   `Never`/`Program` the base-tagged rules lose `process-exec*` (macOS) or
   `EXECUTE` (Linux); read and map stay. Done in the lowering, so the
   public `base::*` functions keep their signatures.
4. **Program slot**:
   - macOS: one rule `(allow file-read* process-exec* file-map-executable
     (extension "procage.exec.program"))` (`ops(Access::Exec)`), class
     constant `PROGRAM_EXTENSION_CLASS` next to `PTY_EXTENSION_CLASS`; a
     dotted class cannot collide with a grant name.
   - Linux: a rule with the new `RuleTarget::Program` (rights
     `READ_FILE | EXECUTE`), resolved per spawn by the backend's rule loop
     like `RuleTarget::Grant` (to the program and its interpreter).
5. **Seccomp**: `Syscall::{Execve, Execveat}`, `Action::Supervise`
   (always `SECCOMP_RET_USER_NOTIF`, whatever the reporting flag),
   `DenyReason::Exec` (`code "exec"`). Under `Never` the plan has both
   calls as `Supervise`. `Condition::matches` unchanged.
6. **Ledger**: `exec-never` exact on every target (the backend raises the
   no-supervisor gap, item 10); `exec-program` exact on macOS,
   `Approximated` on Linux with note "the program's ELF interpreter can
   start any readable ELF file".
7. **ELF interpreter reader** (`elf.rs`, `#[doc(hidden)] pub`, no
   `unsafe`, `no_std`): `interpreter(header: &[u8]) -> Result<Option<&[u8]>,
   ElfError>` over a buffer the caller read (bounded: ELF64/ELF32 header,
   ≤ 64 program headers, `PT_INTERP` ≤ 4096 bytes, NUL-terminated);
   fuzz target `elf`.

### procage, both backends

8. **Program allowance** (`unix.rs`): under `Never`/`Program` every spawn
   entry point calls `find_program` (today only the exec paths) after the
   environment is final, then `program_allowance(path)`: canonicalise,
   read at most 64 KiB once; first bytes `#!` → `SpawnError::Script`
   (new variant, names the path); on Linux the `PT_INTERP` path, which
   must be absolute and a regular file (`SpawnError::Interpreter`).
9. **macOS** (`macos/spawn.rs`, `macos/mod.rs`): issue a token for the
   resolved program with `PROGRAM_EXTENSION_CLASS` (after
   `canon::exact_allow`, R-37), consumed with the grant tokens; no
   recompile (cached profile unchanged).

### procage, Linux

10. **Gaps** (`linux/mod.rs`, `linux/probe.rs`):
    - one probe per cage under `Exec::Never` (not cached; decided in
      implementation): can a child install a filter with `NEW_LISTENER`?
      `EBUSY` → no supervisor. A per-process cache would go stale when the
      process installs a filter later (an embedding sandbox, the
      outer-listener test); the probe is one fork per cage, not per spawn.
    - `Cage::with_options` under `Never` without a supervisor: gap
      `exec-never` (`Approximated`, note "no seccomp listener: an
      enclosing filter has one") unless allowed; allowed → the cage drops
      the exec rules (Landlock only) and lists the approximation in its
      facts.
    - `Cage::exec*` under `Never`: the same gap at call time (`Cage.allowed`,
      as `proc_gap`), before anything is applied.
    - `CapabilityGap`'s message for both constructs names
      `LowerOptions::allow(Construct::…)` and the bindings' spelling.
11. **Ruleset** (`linux/spawn.rs`): the program and its interpreter as
    file rules (`READ_FILE | EXECUTE`), opened `O_PATH` in the parent, so
    they stay with the inode that was checked.
12. **Supervisor before the spawn** (`linux/mod.rs`, `violations.rs` →
    renamed in place to `supervisor.rs`):
    - a run has a listener when reporting is on or the plan supervises
      exec. `launch` starts the supervisor thread **before**
      `command.spawn()`; it waits for the handover (poll on the parent
      end) until the child sends it or the parent marks the spawn done
      (an `AtomicBool`, then one last non-blocking receive).
    - handover: listener + sentinel read end (control buffer for two
      descriptors, allocated in the parent).
    - answers: a `Supervise` notification → `CONTINUE` while the sentinel
      has not hung up (`poll`, timeout 0), else `EPERM`; every other →
      `EPERM` (as today). Recorded only when reporting is on;
      `DeniedBy::Exec`.
    - `Child` keeps `Reporting` as today; without reporting the record's
      coverage stays `Off`.
13. **Child sequence** (`linux/sys.rs`, after Landlock, step `SECCOMP`):
    with a listener: install with `NEW_LISTENER`; on success
    `pipe2(O_CLOEXEC)` (only when the plan supervises exec), `sendmsg`
    both, `close` the listener and the read end; the write end stays
    until exec. On failure: reporting-only plans keep today's fallback
    (plain filter, errno sent); a plan that supervises exec fails the
    step with the errno (fail closed; the probe makes this rare).

### Explain, receipts, bindings, docs

14. **Explain**: nothing to add: the base loses exec in `emit`, which
    explain shares; the program class maps to no grant, so exec of any
    path answers denied. The oracle covers both settings: `runnable()`
    adds no `Exec` rule under `Never`/`Program` (the program allowance
    starts the test binary).
15. **Receipts**: no new field. Accepted approximations appear through the
    existing `approximations` (lowering degradations, cage facts).
16. **Bindings**: policy JSON `"program"` (serde); `CageOptions`
    gains `allow: [construct names]` (Python `allow=[...]`, Node
    `allow: string[]`), mapped to `LowerOptions::allow`; an unknown name
    raises `PolicyError`, as an unknown `relax` name does; a gap's `accept`
    lists `allow: ["exec-program"]` / `["exec-never"]`.
17. **Docs**: `Exec` rustdoc (contract per platform), `lowering.md`
    (`exec-never`, new `exec-program`), `site/content/docs/policies.md`,
    `exec.md`, `explain.md`, the bindings READMEs, `THREAT_MODEL.md`
    (new row R-38 "Execution beyond the program", canaries `r38_*`),
    `CHANGELOG.md` (Security + Added + migration), and a decision-log
    entry.

## Child call sequence (principle IV)

Unchanged up to Landlock. Then, for a plan with a listener:

```text
seccomp(SET_MODE_FILTER, NEW_LISTENER, notifying)  -> listener | errno
  ok:   [supervised exec] pipe2(O_CLOEXEC) -> (r, w)
        sendmsg(socket, [1], SCM_RIGHTS [listener, r?])   // buffer from parent
        close(listener); close(r)
  err:  [supervised exec] return step error (errno)
        [reporting only] seccomp(SET_MODE_FILTER, 0, plain); sendmsg([0, errno])
prctl(GET_SECCOMP), prctl(GET_NO_NEW_PRIVS)               // verify, unchanged
-> std execvp: each execve notifies; the supervisor answers CONTINUE (w open)
-> kernel closes w in begin_new_exec; any later execve: EPERM
```

All syscalls; no allocation (the control buffer and filters come from the
parent). The multithreaded spawn test runs with `Exec::Never`.

## Constitution Check

| Principle | Check | Status |
|---|---|---|
| I. Fail closed | Base exec removed; no supervisor → typed gap, never a silent fallback; supervised-exec child fails the step on `EBUSY`; a gone supervisor → kernel `ENOSYS` (exec refused). `CONTINUE` is new: answered only while the sentinel is open, when only procage's code runs in the child; no argument is checked, so the documented `CONTINUE` race does not apply (research R3) | PASS (034's "never `CONTINUE`" amended, recorded) |
| II. Types | `Exec::Program`, `Construct::ExecProgram`, `Action::Supervise`, `DenyReason::Exec`, `SpawnError::{Script, Interpreter}`; no strings for decisions | PASS |
| III. Kernel oracle | caged canaries per setting on macOS, T1, T2 (`r38_*`); oracle covers both; lowering table test; probe fact checked by a test with an outer listener | PASS |
| IV. fork/exec, unsafe | new child calls `pipe2`, `sendmsg` (2 fds), `close`; prepared in the parent; `unsafe` only in `linux::sys`; multithreaded spawn test with `Never`; `elf` is safe code | PASS |
| V. Hygiene | sentinel write end close-on-exec, read end never kept by the child; no fd reaches the program | PASS |
| VI. Private interfaces | macOS: one more extension class on the existing token path; Linux: documented kernel ABI | PASS |
| VII. Library | global state: one more probe result (allowed); one supervisor thread per supervised run (as for reporting); `Exec` gains a variant → minor version, migration note | PASS |

## Project Structure

### Documentation (this feature)

```text
specs/051-exec-never/
├── spec.md, research.md, plan.md, data-model.md, quickstart.md
├── contracts/api.md
├── threat-model.yaml, threat-model.md, security/
└── tasks.md            (next: /speckit-tasks)
```

### Source Code

```text
crates/procage-policy/src/{policy.rs, linux.rs, sbpl.rs, elf.rs (new), lib.rs, lowering.md}
crates/procage-policy/src/lower/{mod.rs, macos.rs, linux.rs}
crates/procage-policy/src/explain/   (no change expected; tests)
crates/procage-policy/tests/{gaps.rs, lowering_table.rs, common/mod.rs, base.rs}
crates/procage-policy/fuzz/fuzz_targets/{lower.rs, elf.rs (new)}
crates/procage/src/{unix.rs, lib.rs, receipt.rs (none expected)}
crates/procage/src/macos/{mod.rs, spawn.rs}
crates/procage/src/linux/{mod.rs, probe.rs, spawn.rs, sys.rs, seccomp.rs, violations.rs→supervisor.rs, child.rs}
crates/procage/tests/{escape_macos.rs, escape_linux.rs, spawn_macos.rs, spawn_linux.rs, exec.rs, oracle.rs, threat_model.rs}
crates/procage/THREAT_MODEL.md, README.md, CHANGELOG.md
bindings/python/{src/lib.rs, python/procage/_native.pyi, README.md, tests/}
bindings/nodejs/{src/lib.rs, index.d.ts, README.md, test/}
site/content/docs/{policies.md, exec.md, explain.md, python.md, nodejs.md}
specs/README.md
```

## Complexity Tracking

| Item | Why | Simpler alternative rejected |
|---|---|---|
| Supervisor starts before the spawn | std's `spawn` returns only after the exec, which the supervisor must answer | after the spawn (today): deadlock |
| Sentinel pipe made in the child | the only signal that orders "procage's exec" before any code of the program | counting notifications (PATH search, credits leak); handoff-socket hang-up (parent holds a copy during `spawn`) |
| `Exec::Program` as an approximation on Linux | the interpreter route cannot be closed without a racy path check | supervised path check (`CONTINUE` race) |
