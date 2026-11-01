# Implementation Plan: Spawn a caged child on macOS

**Branch**: `004-spawn-macos` | **Date**: 2026-10-30 | **Spec**: [spec.md](spec.md)

**Input**: Feature specification from `specs/004-spawn-macos/spec.md`

## Summary

Add `procage::macos` to the root crate, which now depends on
`procage-policy`.

- **Preparing a cage**: `Cage::new(&Policy)`
  1. resolves every path to its real, firmlink-visible spelling, recording
     each rewrite;
  2. lowers the policy for macOS;
  3. refuses profiles over the in-process compile limit and `Tty::NewPty`;
  4. compiles the profile through dlsym-resolved libsandbox symbols, with an
     exact-key in-memory cache.
- **Spawning**: `Cage::spawn(&mut Command, &Grants)`
  1. refuses an already-sandboxed parent;
  2. runs a once-per-process probe of path A;
  3. resolves the grants and issues `procage.<name>` tokens;
  4. builds the environment from the policy;
  5. installs a `pre_exec` closure that runs, syscalls only: `setsid`,
     `setrlimit`, the path A `__mac_syscall`, `sandbox_check(self)`, and
     `sandbox_extension_consume`.

  A failed step reaches the parent as an encoded number through std's own
  error channel.
- **Tests**: integration tests spawn real caged children, including a
  100-child run under dyld contention and self-re-exec checks inside the
  child.
- **Other changes**:
  - the version becomes 0.0.2, and the policy crate becomes publishable;
  - `package-docs` packages both crates;
  - the docs and the threat model's release status are updated.

## Technical Context

**Language/Version**: Rust 2024, MSRV 1.99

**Primary Dependencies**:
- `procage-policy` (path dependency, version 0.0.1);
- `libc` 0.2 for macOS, already in the lockfile through the kernel facts.

**Storage**: in-memory compile cache only

**Testing**:
- `tests/spawn_macos.rs` (macOS, real caged children);
- `tests/unsafe_confined.rs`;
- the existing gates.

**Target Platform**: macOS 26.6.2 measured. The CI macOS lanes run the same tests.

**Project Type**: library

**Performance Goals**:
- a caged spawn adds at most 5 ms of median latency (recorded);
- a cache hit costs 0 compiles.

**Constraints**:
- syscalls only between fork and exec;
- no enforcement claim without a test;
- the tests fail inside a sandbox.

**Scale/Scope**: 5 source files, 2 test files, recipe and manifest changes, doc updates.

## The child's call sequence (constitution IV)

Prepared in the parent:
- `Arc<[u8]>` bytecode;
- `Vec<CString>` tokens;
- `[(c_int, rlimit); ≤5]`;
- copied fn pointers `mac_syscall`, `check` and `consume`;
- `tty_inherit: bool`.

In the child, after std's own stdio, `cwd` and signal setup:

| # | Call | Condition | Failure → step |
|---|---|---|---|
| 1 | `setsid()` | not `Tty::Inherit` | Session |
| 2 | `setrlimit(res, &lim)` | for each prepared limit (CORE always) | Rlimit |
| 3 | `__mac_syscall("Sandbox", 0, &ApplyArgs{data, size, NULL, 0})` | always | Apply |
| 4 | `getpid()`, then `sandbox_check(pid, NULL, 0) == 1` | always | Verify |
| 5 | `sandbox_extension_consume(token) >= 0` | for each token | Consume |
| — | return `Ok(())`; std calls `execve` | | |

A failure returns `Err(io::Error::from_raw_os_error(0x5043_0000 | step << 12 | errno))`.
std writes it to its CLOEXEC pipe and `_exit`s the child. There is no
allocation, lock or dlsym in this sequence.

## Constitution Check

| Principle | How this plan complies | Evidence | Gap |
|---|---|---|---|
| I. Fail closed | Each of these is a typed error, and no target runs after a failed step:<ul><li>a missing symbol;</li><li>a nested sandbox;</li><li>a failed probe;</li><li>a profile over the limit;</li><li>an unsupported setting;</li><li>a grant problem;</li><li>any in-child step failure.</li></ul>Paths are resolved, so no rule silently does nothing | `spawn_macos` tests | Path B is absent: a failed probe makes spawning unsupported (by design) |
| II. Types over strings | Lowering is unchanged from 003. Resolved globs escape their resolved prefix | `spawn_macos`, 003 suites | — |
| III. Kernel is the oracle | Every doc claim maps to a caged-child test. The tests fail when sandboxed. Measurements carry their date and build. Threat-model statuses are unchanged | `spawn_macos`; review | Newer macOS lanes after a push |
| IV. Syscalls only; unsafe in sys | The call sequence is listed above; `unsafe` is only in `macos::sys`, each block with a `SAFETY` comment | `contention` test, `unsafe_confined` | — |
| V. Hygiene by default | Environment, rlimits (CORE 0) and the new session are applied; `NewPty` is refused | `spawn_macos` | fds and lifetime are in 005, and the docs say so |
| VI. Private interfaces, honestly | dlsym table, `Unsupported` naming the symbol and OS build, and a first-use probe | `spawn_macos::probe…`, `missing_symbol…` | — |
| VII. Library, not a harness | Global state is limited to the symbol table, the probe result and the compile cache. No runtime. Options are overridable | review | — |

**Gate result**: PASS (pre-research and post-design).

## Project Structure

```text
Cargo.toml                    # version 0.0.2; dep procage-policy; macOS libc; lints with unsafe_code = deny
crates/procage-policy/Cargo.toml   # version 0.0.1; publishable
src/lib.rs                    # docs (development status), `pub use procage_policy as policy`, `pub mod macos`
src/macos/{mod,sys,canon,probe,spawn}.rs
tests/spawn_macos.rs          # caged-child tests (macOS)
tests/unsafe_confined.rs      # unsafe only in macos::sys, SAFETY comments
THREAT_MODEL.md, README.md    # release status for 0.0.2 (development); gaps stated
justfile                      # package-docs packs both crates
.github/workflows/ci.yml      # macOS lanes run spawn_macos
```

## Complexity Tracking

| Item | Why | Simpler alternative rejected |
|---|---|---|
| Step encoded in std's errno channel | Syscalls only; no extra pipe | Own status pipe: an inherited-fd race and more child code |
| Self re-exec for in-child checks | Observes the session, rlimits, env and nesting from inside the cage | A separate helper binary would ship in the package |
