# Research: 004-spawn-macos

Measured on macOS 26.6.2 (25G83), Apple M4 Pro, 2026-10-30, outside any
sandbox. Experiments compiled and applied profiles in throwaway children, or
through `sandbox-exec` for discovery only. Nothing here relies on
`sandbox-exec` at run time.

## R1. Module layout and lints

- **Decision**: the root crate gets `src/macos/` (`cfg(target_os = "macos")`)
  with these files:

  | File | Holds |
  |---|---|
  | `mod.rs` | `Cage`, `CageOptions`, `Grants`, errors, the compile cache |
  | `sys.rs` | the only `unsafe` code: the dlsym table, compile, apply, check, extensions, setsid/setrlimit wrappers |
  | `canon.rs` | path resolution |
  | `probe.rs` | the apply-method probe |
  | `spawn.rs` | environment, tokens, the `pre_exec` sequence, step decoding |

  The root crate keeps the workspace lints, except that `unsafe_code` becomes
  `deny` instead of `forbid`. `sys.rs` opts in with `#![allow(unsafe_code)]`,
  as the kernel-facts crate does. A text test, `tests/unsafe_confined.rs`,
  checks two things:
  - no `unsafe` appears outside `src/macos/sys.rs`;
  - every `unsafe` there has a `// SAFETY:` comment on the lines above.
- **Rationale**: constitution IV, SR-003. `forbid` cannot be lifted per module.
- **Alternative**: a separate `procage-sys` crate was rejected, because it is
  more publish surface for one module.

## R2. Symbol table

- **Decision**: `Libsandbox` is resolved once into a `OnceLock<Result<Libsandbox, Unsupported>>`.
  - It `dlopen`s `/usr/lib/libsandbox.1.dylib`, which is never closed, then
    resolves with `dlsym(RTLD_DEFAULT, …)`.
  - The symbols: `sandbox_compile_string`, `sandbox_free_profile`,
    `sandbox_create_params`, `sandbox_set_param`, `sandbox_free_params`,
    `__mac_syscall`, `sandbox_check`, `sandbox_extension_issue_file`,
    `sandbox_extension_consume`.
  - The signatures are the ones the kernel-facts suite uses (KF-M01…M05,
    M18, M20, M23 pass on 26.6.2).
  - The OS build comes from `sysctl kern.osversion`.

  The table is resolved by `Cage::new` and by `spawn`, both before any fork.
  It is global state the constitution allows (VII).

## R3. Path resolution

- **Decision**: `resolve(&AbsPath) -> Result<AbsPath, io::Error>` works like
  this.
  1. Find the longest existing leading part, popping components while
     `std::fs::canonicalize` returns `NotFound`.
  2. Canonicalise that part, then append the popped remainder byte-exact.
  3. Firmlinks: if the result starts with `/System/Volumes/Data/`, and the
     same path without that prefix exists with the same device and inode,
     use the shorter, visible form.
  4. Any error other than `NotFound` (for example permission) is
     `SpawnError::Path { path, error }`.

  Globs:
  - split the source at the first component that holds an unescaped `*` or
    `?`;
  - resolve the leading components as a path;
  - write them back with `\ * ? [ ] { }` escaped, then append the rest
    unchanged.

  A rewrite `{ from, to }` is recorded whenever the text changes.

  Paths resolved: file-rule targets, unix-socket paths, and the raw Seatbelt
  layer's literal, subpath, glob and unix-socket filters. Linux-layer paths
  are left alone; they are ignored on macOS anyway.
- **Measured**:
  - `/tmp` resolves to `/private/tmp`, and `/etc/hosts` to
    `/private/etc/hosts`;
  - a rule written with the symlinked spelling is ignored by the kernel
    (KF-M07, KF-M08);
  - a `/Users` deny holds through the firmlink (KF-M21).
- **Symlink lookups (found during implementation)**: the child still opens
  `/tmp/x` in the caller's spelling, and that lookup needs
  `file-read-metadata` on the symlink `/tmp`. Resolution therefore adds a raw
  rule allowing metadata reads of every symlink a policy path passes
  through, and of `/etc`, `/tmp` and `/var`, so that grants bound later also
  resolve. Measured: metadata on the link is enough, and `..` traversal stays
  denied.
- **Known limit**: paths are resolved when the cage is prepared, so a
  symlink swapped later is not followed. Grants are resolved per spawn.

## R4. Compile and cache

- **Decision**:
  - A process-wide cache: `Mutex<HashMap<(String, Vec<(String, String)>), Arc<[u8]>>>`.
    The key is the exact profile text and parameters, so there is no hash
    and no collision.
  - It lives in memory only and is never written to disk.
  - `Cage::compiled()` reports whether this preparation compiled or hit the
    cache (SC-003).
  - If `plan.rule_count > options.compile_limit` (default 2,000), the result
    is `SpawnError::LimitExceeded`, returned before libsandbox is called.
  - Compile failures give `SpawnError::Compile { message }`. Empty error text
    becomes `"<no error text>"`, as the 10k-`require-any` case shows (KF-M28).
- **Why 2,000**: lowering already caps at 2,000 rules by default. Aborts begin
  at 15,625 rules or more, and the 64 KiB bytecode cap is reached at about 10k
  rules (KF-M24, KF-M27). Choosing a limit by bytecode size waits for the helper feature.

## R5. Apply-method probe

- **Decision**: `probe()` runs once per process (`OnceLock`).
  1. It compiles `(version 1)(deny default)`.
  2. It spawns `/usr/bin/true` with a `pre_exec` that applies via path A,
     requires `sandbox_check(getpid(), NULL, 0) == 1`, and requires
     `open("/private/etc/hosts", O_RDONLY)` to fail with EPERM.
  3. The child then returns the encoded marker `PROBE_OK` as its `pre_exec`
     error, so it never execs.
  4. `Ok(ApplyMethod::PathA)` only when `spawn()` returns that exact marker.

  Anything else is `Unsupported::ApplyMethod { os_build, detail }`, and the
  cached failure makes every later spawn fail.
- **Rationale**: FR-009; path A is the chosen apply method. The probe shows both apply and enforcement on
  this build.

## R6. The in-child sequence and step reporting

- **Decision**: `std::process::Command` plus `CommandExt::pre_exec`. std then
  forks and runs the closure in the child, after stdio, `cwd` and signal
  setup and before `execve`.

  The closure owns, prepared in the parent:
  - `Arc<[u8]>` bytecode;
  - `Vec<CString>` tokens;
  - a fixed `[(resource, rlimit)]` list;
  - copied function pointers.

  It calls only:

  | # | Call | When |
  |---|---|---|
  | 1 | `setsid()` | unless `Tty::Inherit` |
  | 2 | `setrlimit()` | for each limit the policy sets; CORE is always set, default 0 |
  | 3 | `__mac_syscall("Sandbox", 0, &{data, size, NULL, 0})` | always |
  | 4 | `getpid()`, then `sandbox_check(pid, NULL, 0)`, which must return 1 | always |
  | 5 | `sandbox_extension_consume(token)` for each token, each result ≥ 0 | when the spawn binds grants |

  On failure the closure returns `io::Error::from_raw_os_error(code)` with
  `code = 0x5043_0000 | step << 12 | (errno & 0xfff)`. std writes that
  number through its CLOEXEC pipe and exits the child, so the target never
  runs. The parent decodes it into `SpawnError::Apply { step, errno }`.
  - **Why not procage's own status pipe** (10 §6.1): std already delivers an
    `i32` from the child. Encoding the step in it avoids an extra pipe and its
    inheritance races. The marker range `0x5043_xxxx` (`PC`) does not
    collide with real errno values, which are below 200.
  - **Syscalls-only status**: `__mac_syscall` and `getpid` are syscalls.
    `sandbox_check` and `sandbox_extension_consume` were inferred to be
    syscall-only on 26.6.2 (the KF-M25 finding: `strcmp`, `strlen`, `__sandbox_ms`, no
    malloc or locks on the normal path). The multithreaded test (SR-004) is
    the evidence.

## R7. Environment

- **Decision**: before spawning:
  1. read the variables the caller set explicitly (`Command::get_envs`);
  2. call `env_clear()`;
  3. add the allowlisted names present in `std::env::vars_os()`, or, for
     passthrough, every variable except the denied names;
  4. re-apply the caller's explicit settings (including explicit removals).

  With the default policy (an empty allowlist), the child gets only the
  explicit variables. Always-dropped patterns (`DYLD_*`, secrets) belong to
  feature 005.

## R8. Grants

- **Decision**: `Grants::new().bind(name, path)`. At spawn, each binding:
  - must name a grant the policy declares (otherwise
    `GrantError::Undeclared`);
  - is resolved like a policy path, and must exist (otherwise
    `GrantError::Missing`);
  - is issued as a token: `sandbox_extension_issue_file("procage.<name>",
    path, 0)` → token, copied into a `CString` and freed. A null result is
    `GrantError::Issue`.
- **Measured** (26.6.2): a token of class `procage.scratch` lets the child
  write in directory A and not in B. A rule naming `procage.other` is not
  satisfied by a `procage.scratch` token. So custom classes work and stay
  separate. Consuming before apply grants nothing (KF-M25), so tokens are
  consumed after apply.

## R9. What a program needs to start (test base)

Measured with `/bin/cat` under `(deny default)`:

| Rules | Outcome |
|---|---|
| process-exec on the binary; read + map-executable on `/usr/lib` and `/System`; read of literal `/` | runs |
| without the literal `/` | dyld aborts (SIGABRT, 134) |
| with only metadata of `/` | dyld aborts |

Further results:

- `sysctl-read` is not needed.
- Writing to an inherited `/dev/null` stdout was refused (`cat: stdout:
  Operation not permitted`); writing to a pipe works. The tests therefore
  use pipes for stdio.

The tests use their own minimal base:
- Exec on `/usr/lib`, `/System`, `/bin`, `/usr/bin`;
- Read on the literal `/`.

The curated base profile is feature 006.

## R10. Tests that need code inside the child

- **Decision**: `tests/spawn_macos.rs` re-runs its own test binary as the
  caged child. It passes `--exact child_entry --nocapture --test-threads=1`
  with `PROCAGE_CHILD=<action>`.

  `child_entry` is a no-op unless the variable is set. Otherwise it performs
  the action and prints a result line:

  | Action | What the child does |
  |---|---|
  | `session` | `getsid(0) == getpid()` |
  | `rlimit` | `getrlimit` NOFILE and CORE |
  | `env` | sorted variable names |
  | `nested` | try a procage spawn from inside the cage |

  The policy grants Exec on the test binary.

## R11. Packaging and version

- **Decision**:
  - `procage` depends on `procage-policy = { path = "crates/procage-policy", version = "0.0.1" }`.
  - `procage-policy` becomes `version = "0.0.1"`, publishable, and released
    together with `procage`.
  - The root package version becomes 0.0.2, because cargo-semver-checks needs
    a bump for new public items. This is not a release.
  - `just package-docs` packages both crates, unpacks both into a temporary
    directory, and builds the `procage` docs with
    `--config 'patch.crates-io.procage-policy.path="…"'`.
- **Measured**: `cargo package -p procage` alone fails with "no matching package
  named `procage-policy`". Packaging both works when `procage-policy` is
  publishable.
- **User action**: reserve `procage-policy` on crates.io.

## R12. Out of this feature (recorded)

- Path B and the helper: a later feature, 021-helper.
- Closing fds, process groups, kill-on-drop, `NewPty`: 005.
