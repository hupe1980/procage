# Research: 001-kernel-facts

Date: 2026-10-29. Reference machine: macOS 26.6.2 (25G83), Apple M4 Pro, not
sandboxed (`sandbox_check(getpid(), NULL, 0) == 0`). Rust 1.99.1 (1.99.0
toolchain installed), Docker Desktop kernel 7.0.14-linuxkit aarch64, image
`rust:1.99`. libc 0.2.191 has the Landlock syscall numbers but no Landlock
structs.

## R1. Rule-count limits: re-measured before planning (feeds KF-M17, KF-M24, KF-M27, KF-M28)

Probe: scratchpad `lim.c` / `lim2.c`. Each compiles N rules via `dlsym`'d
`sandbox_compile_string` in its own process.

| Shape | N | Result | Time |
|---|---|---|---|
| `(allow default)` + `(deny file-read* (literal "/private/tmp/pc-kf/rNNNNNNN"))` | 5,000 | OK, 32,230 B | 3.3 s |
| same | 10,000 | OK, 63,995 B | 13.1 s |
| same | 20,000 | **error** `data object length 127088 exceeds maximum (65535)`, no abort | 52.7 s |
| same, one `require-any` | 10,000 | **NULL, error slot left NULL** | 0.01 s |
| `(deny default)` + `(allow file-read* (literal "/private/tmp/dirNNNNNN/file"))` (the shape measured in earlier research) | 5,000 | OK, 57,249 B | 3.3 s |
| same | 10,000 | error `data object length 113548 exceeds maximum (65535)` | 14.4 s |
| same | 20,000 | **SIGABRT** `diff <= INSTR_JUMP_NE_MAX_LENGTH`, serialize.c:240 | ~50 s |
| same, one `require-any` | 5,000 / 10,000 / 20,000 | OK / NULL no error / NULL no error | ≤ 3.4 s |

- **Decision**: there are two limits, not one. (1) A **64 KiB bytecode cap**
  that fails cleanly with a parseable message. (2) A **jump-offset assertion**
  that aborts the process. It is reached only for some shapes, and only past the
  point where the cap would already reject the profile. The compile-abort question is answered by
  bisecting the `deny default` shape between 10,000 (clean error) and 20,000
  (abort), and the `allow default` shape between 20,000 and 40,000. KF-M17
  keeps the 20,000 `deny default` case. KF-M27 asserts the clean cap error.
  KF-M28 asserts the silent `require-any` failure, which matters for spec 003:
  a NULL profile with a NULL error is a possible outcome, and the facade must map
  it to a typed error.
- **Rationale**: the earlier "20k rules SIGABRT" finding is true but incomplete; the
  design's soft limit should be expressed in emitted bytecode size, not only rule
  count. That is recorded as a finding for spec 004, not decided here.
- **Alternatives**: assert only rule counts (rejected: it hides the 64 KiB cap);
  skip the abort case (rejected: FR-005 and KF-M17 need it).
- **Cost**: the abort case needs about 50 s and each bisection step 15–50 s. So
  the bisection is opt-in (SR-007), and the default suite asserts only the
  recorded bracket edges.

## R2. Where the fact suite lives and how it may use unsafe

- **Decision**: an unpublished workspace member at `tests/kernel_facts/` (crate
  `procage-kernel-facts`, `publish = false`). It holds:
  - a library: report, protocol, timeouts and the `sys` FFI;
  - one probe binary `kf-probe` that performs a single step per invocation;
  - one integration test `kernel_facts` with `harness = false`. This is the
    runner and owns the catalog and assertions.

  Unsafe code is allowed only in `src/sys/` (`#![allow(unsafe_code)]` on that
  module, `unsafe_code = "deny"` crate-wide, clippy
  `undocumented_unsafe_blocks = "deny"`).
- **Rationale**: the design names `tests/kernel_facts`. The constitution keeps
  unsafe out of published code, and this crate is never published. A harness of
  its own gives the three states FR-004/FR-011 need (pass, fail, not applicable),
  which libtest cannot express. Running each step in a freshly exec'd binary
  means no fact code runs between fork and exec in a multithreaded runner
  (SR-008).
- **Alternatives**: `#[test]` functions in the `procage` crate (rejected: unsafe
  outside `procage::*::sys`, no N/A state, fork in the libtest runner); C probes
  as in the research (rejected: a second toolchain in CI, and later specs reuse
  the Rust `sys` code).

## R3. How a child is caged without code between fork and exec

- **Decision**: **self-caging steps**. A step process (fresh and
  single-threaded) compiles a profile, applies it to itself, performs the
  action, and prints the observation. Where a fact is about inheritance or
  per-spawn grants (M06, M19, M20), the step spawns another step through
  `std::process::Command`, with no `pre_exec`.

  The only fork-then-apply code is KF-M18, whose subject is exactly that. Its
  child sequence uses syscalls only:
  `dup2(devnull, 1)` → `dup2(devnull, 2)` →
  `__mac_syscall("Sandbox", 0, &{data, size, NULL, 0})` → `execve("/bin/cat",
  ["/bin/cat", "/private/etc/hosts"], [])` → `_exit(127)`. Everything (bytecode,
  CStrings, argv/envp arrays, the `/dev/null` fd) is prepared before `fork`.
- **Rationale**: constitution IV. Self-apply in an exec'd process is how path B
  works anyway, and it keeps every other fact free of async-signal-safety
  concerns.
- **Alternatives**: `pre_exec` closures everywhere (rejected: unsafe and fork
  windows in many places for no benefit).

## R4. Linux probing without extra crates

- **Decision**: `libc` only. Landlock is called by raw `syscall(SYS_landlock_*)`
  with `#[repr(C)]` structs defined in `sys/linux.rs`; the ABI comes from
  `landlock_create_ruleset(NULL, 0, VERSION)` and the errata from the `ERRATA`
  flag. seccomp: actions from `/proc/sys/kernel/seccomp/actions_avail`, plus a
  real `seccomp(SET_MODE_FILTER)` of an allow-all program in a throwaway child.
  userns: `unshare(CLONE_NEWUSER)`, then `setgroups=deny` and the uid/gid maps
  through `std::fs`. Mounts use `mount(2)` after `unshare(CLONE_NEWNS)`. netns:
  `unshare(CLONE_NEWNET)`, then `/proc/self/net/dev` (lists only `lo`) and
  `SIOCGIFFLAGS` on `lo` (not `IFF_UP`).
- **Rationale**: the earlier Linux experiments used the same calls. `landlock` and `seccompiler`
  are spec 008's choice to make. Fewer dependencies keep the cargo-deny surface
  small.
- **Alternatives**: the `landlock` 0.4.7 crate (deferred to spec 008).

## R5. Tier derivation and lane expectations

- **Decision**: each capability is measured in its own throwaway child
  (`kf-probe measure <cap>`). Exit 0 with `ok=1` means present; anything else
  (error, signal, timeout) means absent. The rules:
  - **T1** = userns ∧ uid_map ∧ tmpfs ∧ ro-bind EROFS ∧ Landlock ≥ 1 ∧ seccomp filter;
  - **T2** = Landlock ≥ 4 ∧ seccomp filter;
  - **T3** = otherwise.

  `fresh_proc` and the AppArmor sysctl are reported but not used in the tier.
  CI lanes and the container recipes set `PROCAGE_KF_EXPECT_TIER`, and the
  runner fails if the measured tier differs.
- **Rationale**: SR-016, R-27. An expected tier per lane turns a silent
  downgrade into a red lane.

## R6. Toolchain gates

- **MSRV**: `cargo +1.99.0 check --workspace --all-targets` (installed locally;
  CI installs it).
- **no_std**: `cargo build -p procage-policy --target thumbv7em-none-eabihf`
  (installed locally). A bare-metal target proves that no `std` comes in through
  dependencies.
- **Deny**: `cargo deny check` with licences {MIT, Apache-2.0, Unicode-3.0},
  crates.io as the only source, `wildcards = "deny"`, advisories with yanked
  denied. libc is MIT OR Apache-2.0.
- **semver**: `cargo semver-checks -p procage` against crates.io 0.0.1
  (constitution VII).
- **Planning-path gate**: `git ls-files`-independent; it greps the files that
  `cargo package --list` and the workspace members would publish, plus
  `.github/`, for the private notes directory, `specs/`, `.specify/` (SR-015).

## R7. CI actions (SR-010)

- **Decision**: no third-party Rust setup action. Runners have rustup, so the
  workflow runs `rustup toolchain install`. The only actions are
  `actions/checkout`, pinned by full SHA with `persist-credentials: false`, and
  `taiki-e/install-action`, pinned by full SHA, for `cargo-deny`, `just` and
  `cargo-semver-checks`. `permissions: contents: read`. No `secrets.*`.
- SHAs are resolved with `git ls-remote` at implementation time and written
  with a version comment.

## R8. Local Linux runs (SR-013)

- **Decision**: `docker run --rm --user 65534:65534 -e HOME=/tmp -e
  CARGO_HOME=/tmp/cargo -e CARGO_TARGET_DIR=/tmp/target -v "$PWD":/src:ro -w
  /src rust:1.99 cargo test --locked -p procage-kernel-facts --test
  kernel_facts`. That is the T2 recipe; the T1 recipe adds `--security-opt
  seccomp=unconfined` and `--security-opt apparmor=unconfined`. No
  `--privileged`, no `--network host`, read-only source. Expected tiers: T2
  and T1.
- **Note**: the T1 container has masked /proc, so KF-L13 expects
  `fresh_proc = false` there.

## R9. Reports and dates without dependencies

- **Decision**: the runner prints a header (OS name, version, build or kernel
  release, arch, UTC date from `SystemTime` via days-to-civil, sandboxed flag,
  tier). It writes the same text to
  `target/kernel-facts/report-<os>-<arch>.txt`. On macOS the step `osinfo` reads
  `kern.osproductversion` and `kern.osversion` via `sysctlbyname` (in `sys`).
  Linux reads `/proc/sys/kernel/osrelease`. Observations are key=value pairs:
  numbers, errno, byte counts. Never contents or env values (SR-014).

## R10. Extension-ordering and TIOCSTI methods

- **Extension ordering**: a probe consumes the extension token **before** apply, then applies
  and writes to the granted path, and records allowed or denied. For the
  "syscalls only" part, disassemble `sandbox_extension_consume` and
  `sandbox_check` from the shared cache (`otool -tV` against an extracted
  `libsystem_sandbox`, or `lldb -o "disassemble -n …"` in a probe process) and
  list the branch targets. The finding is recorded as *inferred*.
- **TIOCSTI**: `posix_openpt` → `grantpt`/`unlockpt` → fork a child step that calls
  `setsid()` and opens the slave (it becomes the controlling tty), then
  `ioctl(slave, TIOCSTI, "k")`. Afterwards the parent reads the master. The
  probe runs unsandboxed and under `(deny default)` with the pty allowed, and
  records the rc/errno and whether `k` arrived. It never touches the inherited
  terminal: stdin is `/dev/null` and the child calls `setsid` first (SR-003).

## R11. Findings recorded during implementation (2026-10-29, macOS 26.6.2 25G83)

- **Path A layout**: path A `{data, size, NULL, 0}` enforced 200/200 under 4-thread
  dyld contention, 0 hangs, 0 apply failures (KF-M18, KF-M23).
- **Extension ordering (measured)**: a token consumed **before** apply returns a
  valid handle but grants nothing after apply. Consume after apply (KF-M25;
  KF-M20 is the working order).
- **Extension calls, syscalls only (inferred, `proven=false`)**: lldb disassembly.
  - `sandbox_extension_consume` calls `strcmp`, `strlen` and `__sandbox_ms`.
  - `sandbox_check` calls `sandbox_operation_fixup`, which calls `strcmp`, or
    `sandbox_warn` for a deprecated operation name.
  - `sandbox_operation_fixup` then calls `sandbox_check_common`, which calls
    `strcmp`, `__error`, `__mac_syscall` and `sandbox_warn`.

  No allocation or locks on the normal path.
- **TIOCSTI (measured)**: TIOCSTI injects into the caller's own controlling tty,
  unsandboxed and under `(allow default)` (KF-M26).
- **KF-M16 detail**: the 1024-byte literal is rejected by the reader with
  "Error reading string", not by a size check.
- **KF-L07 detail**: on linuxkit 7.0.14 a new netns holds fallback tunnel
  devices (tunl0, gre0, sit0, …) besides `lo`; all are down. The fact asserts
  "no interface up", not "only lo".
- **Gate bug found by quickstart #9**: `cargo deny check` in a workspace with
  a root package checks only the root's graph. The gate uses `cargo deny
  --workspace check`.
