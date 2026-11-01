# Implementation Plan: Spawning a caged child on Linux

**Branch**: committed on `main` | **Date**: 2026-10-30 | **Spec**: [spec.md](spec.md)

## Summary

A Linux spawn backend, `procage::linux`, mirroring `procage::macos`:

- a per-process **probe** picks T1 or T2 (or `Unsupported`) and reports the
  Landlock ABI;
- a **`Cage`** lowers the policy for that tier and ABI and builds the
  seccomp filter once;
- **`spawn`** builds the Landlock ruleset (rule fds opened in the parent,
  grants included), the T1 mount list (policy mounts plus the data-class
  masks found at spawn), the id maps, limits and environment, then forks a
  child that applies them with syscalls only;
- the lowering becomes coverage-aware for the data classes and states the
  gaps this backend leaves.

Evidence: `tests/spawn_linux.rs`, run by `just linux` in a T2 container
(Docker defaults) and a T1 container (seccomp unconfined); BPF unit tests
with a small classic-BPF interpreter; lowering fixtures.

## Technical Context

**Language**: Rust 2024, MSRV 1.99. **Dependencies**: none new (`libc` only,
now also on Linux). `procage-policy` stays `no_std`.
**Targets**: aarch64 and x86_64 Linux (glibc and musl); checked by clippy on
both from macOS, run on aarch64 in Docker (kernel 7.0.14-linuxkit, Landlock
ABI 8).
**Performance**: spawn of `true` under 50 ms median (SC-003, recorded).

## Constitution Check

| Principle | Compliance | Gap |
|---|---|---|
| I. Fail closed | Tier probe, gaps at preparation, `Unsupported` without Landlock, refused covering grants on T2, walk bound fails the spawn | — |
| II. Types | Plan is typed data; syscalls by name mapped per architecture; mounts and rules as typed enums | — |
| III. Kernel is the oracle | Every scenario is a caged test in both containers; the tier comes from the probe, never `uname` | x86_64 kernel runs only after a push |
| IV. Syscalls only between fork and exec | All allocation in the parent; `src/linux/sys.rs` is the only unsafe module; full call sequence below; multithreaded spawn test | — |
| V. Hygiene | Same as macOS plus `PR_SET_PDEATHSIG` | — |
| VI. Private interfaces | Landlock and seccomp are public kernel ABIs; the probe tests user namespaces in a throwaway child | — |
| VII. Library | No binary, no setuid helper | — |

**Gate**: PASS.

### Child call sequence (between fork and exec)

1. `setsid()` (or `setpgid(0, 0)` with `Tty::Inherit`)
2. `prctl(PR_SET_PDEATHSIG, SIGKILL)`; `getppid()` equals the parent's pid
3. T1: `unshare(CLONE_NEWUSER|NEWNS|NEWIPC|NEWUTS[|NEWNET])`; `open`+`write`+`close` on `/proc/self/setgroups` (`deny`), `uid_map`, `gid_map`; `mount(NULL, "/", NULL, MS_REC|MS_PRIVATE)`; per mount: `mount` bind / tmpfs and `mount` remount; per capability: `prctl(PR_CAPBSET_DROP)`; `prctl(PR_CAP_AMBIENT, CLEAR_ALL)`; `capset` to zero
4. `setrlimit` per limit
5. `close_range(lo, hi, CLOSE_RANGE_CLOEXEC)` around kept fds (fallback: `fcntl(F_SETFD)` up to the open-files limit)
6. `prctl(PR_SET_NO_NEW_PRIVS, 1)`
7. `landlock_restrict_self(ruleset, 0)`
8. `seccomp(SECCOMP_SET_MODE_FILTER, 0, prog)`
9. verify: `prctl(PR_GET_SECCOMP) == 2`, `prctl(PR_GET_NO_NEW_PRIVS) == 1`
10. `execve` (std)

Each failure returns `0x5043_0000 | step << 12 | errno` through std's pipe.

## Project Structure

```text
crates/procage-policy/src/
  presets.rs        # + Linux lists (SECRETS_HOME_LINUX, PERSISTENCE_*_LINUX, LINUX_HOMES), linux_class_paths()
  linux.rs          # + Mount::Pin, ClassPaths, LinuxPlan.classes; Namespaces.pid stays false
  lower/linux.rs    # coverage-aware data classes; gaps for relays, unix<9, hide T2, glob, signals<6
  lowering.md       # Linux cells updated (fixture)
crates/procage-policy/tests/{lowering_table.rs, gaps.rs, presets.rs}
src/lib.rs          # pub mod linux (cfg linux); shared spawn helpers
src/unix.rs         # NEW: environment, private_tmpdir, limits, TmpdirGuard (shared by both backends)
src/macos/{mod.rs, spawn.rs}   # use crate::unix
src/linux/
  mod.rs            # Cage, CageOptions, Grants, GrantError, SpawnError, Step, Unsupported, Child, probe, testing
  probe.rs          # Probe { tier, landlock_abi, errata, userns }
  seccomp.rs        # BPF builder + syscall table + interpreter tests
  classes.rs        # homes, walk, data-class mount list
  spawn.rs          # ruleset build, mount list, id maps, decode
  child.rs          # Child (tree kill via /proc children)
  sys.rs            # ALL unsafe: landlock, seccomp, ChildPlan::run, probe child, kill, /proc
tests/spawn_linux.rs   # NEW: caged tests (cfg linux)
tests/unsafe_confined.rs  # both sys modules
justfile            # lint also for Linux targets; `linux`, `linux-t1` lanes; ci-all
THREAT_MODEL.md, README.md
```
