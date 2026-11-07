# Implementation Plan: Windows backend

**Spec**: [spec.md](spec.md) · **Research**: [research.md](research.md) ·
**Data model**: [data-model.md](data-model.md) · **Contract**:
[contracts/windows-api.md](contracts/windows-api.md) · **Quickstart**:
[quickstart.md](quickstart.md)

## Summary

A `procage::windows` backend (and `native` on Windows) that lowers the
portable policy to a Windows plan. The plan is encoded as the OS's process
security environment specification and attached to a suspended
`CreateProcessW` together with a kill-on-close job, an explicit handle list
and an environment block. The child is verified from the parent and then
resumed. Nothing of procage runs in the child, and no ACL on the user's
files is changed. Every construct the OS cannot be shown to enforce on the
lane is a typed gap.

## Technical Context

- **Language**: Rust, edition 2024, MSRV 1.99 (unchanged).
- **New targets**: `aarch64-pc-windows-msvc` (lane), `x86_64-pc-windows-msvc`
  (builds in CI; claimed only with an x64 Windows 11 lane).
- **New dependencies** (all `cfg(windows)`): `windows-sys` (Win32
  bindings), `flatbuffers` (builder). See research R10.
- **OS interface**: `processmodel.dll` security-environment exports,
  resolved at runtime (R1, R3). The schema is vendored as
  `crates/procage/src/windows/psec.fbs` with its SHA-256 and MIT notice (R2).
- **Testing**: the KF-W facts (`procage-kernel-facts`), `spawn_windows.rs`,
  `escape_windows.rs`, the shared `native.rs`, `receipts.rs` and `tokio.rs`,
  all on the Windows lane. Lowering and encoding tests also run on every
  other lane: the encoder is pure Rust, and is compiled for tests on all
  OSes behind `cfg(any(windows, test))`.
- **Performance target**: SC-004, under 5 ms median overhead over a plain
  `CreateProcessW`, published by `benches/spawn.rs`.
- **Constraints**: no administrator rights, no elevation prompt, no ACL
  writes (SR-005), no fallback (SR-001).

## Layout

```text
crates/procage-policy/src/
├── lower/windows.rs     # NEW: Target::Windows lowering → WindowsPlan, gaps, base
├── lower/mod.rs         # Target::Windows { features }, constructs (exec-where-readable)
├── path.rs              # AbsPath ↔ Windows spelling helpers (pure: /C:/… form)
├── presets.rs           # SECRETS_WINDOWS, PERSISTENCE_WINDOWS, *_PIPES_WINDOWS (frozen)
├── base.rs              # windows-base-1 as data (measured, KF-W8)
└── lowering.md          # Windows column in the lowering table
crates/procage/src/
├── lib.rs               # cfg(windows) mod windows; pub use windows as native
└── windows/
    ├── mod.rs           # Cage, CageOptions, Grants, Child, SpawnError, Unsupported (same shapes as linux/macos)
    ├── probe.rs         # build, API set, exports, version, support flags (OnceLock)
    ├── psec.rs          # encoder: WindowsPlan + grants → PSEC bytes (pure; also built for tests)
    ├── psec.fbs         # vendored schema (MIT, provenance, SHA-256)
    ├── spawn.rs         # job, attribute list, CreateProcessW, verify, resume
    ├── cmdline.rs       # argv → command line (inverse of CommandLineToArgvW)
    ├── paths.rs         # Path ↔ AbsPath; final-path resolution, case-sensitivity refusal
    ├── child.rs         # Child: wait, try_wait, kill_all, receipt, handles
    └── sys.rs           # the only unsafe: FFI, attribute lists, tokens, jobs
crates/procage-kernel-facts/src/sys/windows.rs   # KF-W1…KF-W19
crates/procage/tests/{spawn_windows.rs, escape_windows.rs}
crates/procage/THREAT_MODEL.md               # Windows column
.github/workflows/ci.yml                     # windows job (windows-11-arm)
```

## Lowering (procage-policy, `lower/windows.rs`)

| Construct | Windows plan | Condition / gap |
|---|---|---|
| `Read` literal/subpath | `fs_read_only` | path spelled `/X:/…`; else gap |
| `Write` | `fs_read_write` | |
| `Exec` rules, `Exec::Granted` | exact if KF-W1 refuses exec on read-only | else the approximation `exec-where-readable` (accepted by name) |
| `Exec::Any` | no restriction beyond reads | |
| `Exec::Never` | `CHILD_PROCESS_POLICY` restricted | KF-W3; else gap |
| `Protect` | `fs_read_only` inside `fs_read_write` | KF-W4; else gap |
| `Hide` | `fs_deny` | `FS_DENY` support + KF-W5; else gap |
| `Glob` | none | gap |
| per-spawn grants | appended to the spawn's lists | |
| `Base::V1..V3` | `windows-base-1` (the OS base, recorded) | |
| `Base::None` | none | gap |
| `Network::*` | research R5 | per feature |
| `ipc.unix_sockets`, `posix_shm`, `sysv` | none | gap (shm/sysv do not exist: gap only when set) |
| `Signals::SameUser` | none | gap; `SelfAndChildren`/`None` hold (the container cannot open outside processes, KF-W12) |
| `Lifetime::Run`, `Tree` | job | |
| rlimits `nproc`, `cpu_seconds` | job `ACTIVE_PROCESS`, `JOB_TIME` | |
| rlimits `nofile`, `fsize_bytes`, `core_bytes` | none | gap |
| `Tty::None` / `Inherit` | new hidden console / shared console + `TerminalInjection` waiver | |
| `Tty::NewPty` | none | gap (this record) |
| hard-deny classes | research R8 and KF-W9…W12 | per class: enforced or gap |
| `seatbelt` / `linux` layers | ignored when lowering for Windows, as each backend ignores the other's layer | |

`Target::Windows` carries a `WindowsFeatures` value (schema minor, the
support flags, and the build-gated loopback and ingress features).
Lowering is pure, and is tested on every lane with feature sets taken
from the KF-W results recorded in a fixture.

## Spawn sequence (procage, `windows/spawn.rs`)

Research R6, steps 1–8. The call sequence the constitution (IV, 2.4.0)
requires, in the parent and in this order:

1. `CreateProcessSecurityEnvironment`
2. `CreateJobObjectW`
3. `SetInformationJobObject` (extended limits, UI restrictions)
4. `InitializeProcThreadAttributeList`
5. `UpdateProcThreadAttribute` (security environment, handle list, job
   list or none, child-process policy, mitigation policy)
6. `CreateProcessW(CREATE_SUSPENDED …)`
7. If there is no job list: `AssignProcessToJobObject`
8. Verify: `OpenProcessToken`, then `GetTokenInformation` (`TokenIsAppContainer`,
   `TokenAppContainerSid`) and `IsProcessInJob`
9. `ResumeThread`, or on failure `TerminateProcess` and the error
10. `DeleteProcThreadAttributeList`, close the thread handle

The multithreaded spawn test (constitution IV) runs 64 concurrent spawns
while other threads create inheritable handles. None of those handles may
appear in any child (SR-007).

## Errors

`windows::Unsupported` has these variants:

- `NoSecurityEnvironment`: the API set or an export is missing.
- `UntestedVersion { major, minor }`.
- `MissingFeature(name)`.
- `AlreadySandboxed`: the caller's token is an AppContainer.
- `UnsupportedOs { build }`: the build is below the minimum, or the OS is
  Windows Server or Windows 10. Probed, never inferred from the build
  alone, but reported with it.

`SpawnError::Apply { step, hresult }` names the step of the sequence above.
The Windows `Step` enum mirrors the Linux and macOS ones.

## Decisions (planning)

- **P-1**: Windows paths are written `/X:/…` inside `AbsPath` (R7). No new
  path type.
- **P-2**: one security environment per spawn (SR-012). The plan and the
  encoded base are cached per policy shape; per-spawn grants are appended
  to a copy. No environment is reused across runs.
- **P-3**: `Target` gains a variant. The enum is exhaustive, so this is a
  breaking change of `procage-policy`. Release 0.8.0 marks `Target` and
  `Plan` `#[non_exhaustive]` at the same time, so later targets are not breaking,
  and ships a migration note (FR-011).
- **P-4**: `spawn_with_handles(&[BorrowedHandle])` replaces
  `spawn_with_fds` on Windows. `exec`/`exec_session` exist on
  `windows::Cage` and return `SpawnError::Unsupported`, so code written
  against `native` compiles on all three OSes.
- **P-5**: no violations on Windows in this record. `with_violations`
  returns a gap, and the OS denial trace is a later record.
- **P-6**: Windows builds and unit tests run in CI before the lane is
  green. The lane decides the claims; no Windows claim reaches the README
  before it is green.

## Constitution Check (2.4.0)

| Principle | Check | Status |
|---|---|---|
| I | No fallback; every construct is enforced, a named approximation, or a gap; untested schema is `Unsupported`; the child is verified before resume | PASS |
| II | Paths keep the `AbsPath` invariant (`/X:/` spelling); globs never inferred; hard-deny tier lowered last per class; waivers by name | PASS |
| III | Every enforcement claim waits for a KF-W fact or a canary on the Windows lane; the lane fails on a host without the feature | PASS (lane pending; claims gated by P-6) |
| IV | `unsafe` only in `windows::sys`; no code in the child; full call sequence listed; multithreaded spawn test | PASS |
| V | Handle list, explicit environment, no inherited console, job kill-on-close, rlimits where Windows has them, gaps where not; path resolution never follows a reparse point inside a writable tree (research R7, SR-016) | PASS |
| VI | Exports resolved from System32 at runtime, probed, `Unsupported` when absent; the dependency is stated in rustdoc and README | PASS |
| VII | Global state: the probe result only (already allowed); the plan cache is the existing compile cache; no async runtime required; `procage-policy` stays `no_std`, pure and dependency-free | PASS |

No violations, so the Complexity Tracking table is empty.

## Re-check after design

The data model and contract add no global state and no `unsafe` outside
`sys`. The breaking change is recorded (P-3). The constitution check is
unchanged: PASS.
