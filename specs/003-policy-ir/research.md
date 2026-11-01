# Research: 003-policy-ir

Measurements below were taken on macOS 26.6.2 (25G83), Apple M4 Pro, on
2026-10-30. Each profile was compiled with `sandbox_compile_string` from
`/usr/lib/libsandbox.1.dylib`, via ctypes from the session scratchpad. Nothing
was applied to a process. **Compiling shows only that a profile is well-formed;
it says nothing about enforcement.**

## R1. Crate layout

- **Decision**: one crate, `procage-policy` (`no_std` + `alloc`, no `unsafe`),
  with these modules:

  | Module | Holds |
  |---|---|
  | `path` | `AbsPath`, `PathError` |
  | `glob` | `Glob`, `GlobError`, the SBPL regex compiler |
  | `policy` | the intent layer |
  | `seatbelt` | the raw layer: `Operation`, `Filter`, `Rule`, `OperationName` |
  | `linux` | the raw layer and the `LinuxPlan` types |
  | `sbpl` | the escaper (`quote`), the profile writer and the limits guard |
  | `lower` | `lower()`, `Target`, `CapabilityGap`, `Construct`, `Plan`, and the lowering table as rustdoc |
  | `format` | the serde representation, behind feature `serde` |

  Tests live in `crates/procage-policy/tests/`. The fuzz targets live in
  `crates/procage-policy/fuzz/`, a cargo-fuzz package that is its own
  workspace, excluded from the root workspace.
- **Rationale**: matches the workspace layout set in spec 001. The escaper is the one audited
  function, in one small module.
- **Alternatives**:
  - Split crates for each backend layer: rejected, because it adds publish
    surface with no benefit.
  - A typestate builder now: deferred (spec assumption; the builder is still planned).

## R2. Paths (`AbsPath`)

- **Decision**: `AbsPath(Vec<u8>)`. It accepts bytes that:
  - start with `/`;
  - contain no NUL, no empty component (`//`), no `.` or `..` component;
  - have no trailing `/`, except the root `/` itself.

  `~` cannot pass, because the first byte must be `/`. Errors are a
  `PathError` enum:
  - `Empty`
  - `Relative`
  - `Nul { at }`
  - `EmptyComponent { at }`
  - `DotComponent { at }`
  - `DotDotComponent { at }`
  - `TrailingSlash`

  Methods: `as_bytes`, `components`, `parent`, `starts_with_path`
  (component-wise), `join(component)` (it validates the component).
- **Rationale**: FR-001. Lexical only; canonicalisation is
  `procage`'s job.
- **Alternatives**:
  - Normalising `//` and a trailing `/` silently: rejected, because the caller
    would not see what changed.
  - `String` paths: rejected, because they are lossy.

## R3. Globs and SBPL regex

- **Decision**: `Glob` is parsed from text. It must be absolute (first byte
  `/`), UTF-8, with no NUL or control characters. Tokens:

  | Token | Meaning | SBPL regex |
  |---|---|---|
  | `**` | a whole component, at the start of a component and followed by `/` or the end | `**/` → `(.*/)?`; a trailing `/**` → `(/.*)?` |
  | `*` | within a component | `[^/]*` |
  | `?` | within a component | `[^/]` |
  | `\x` | the literal `x`, for any `x` | escaped `x` |

  Anything else is literal. `[`, `]`, `{`, `}` are refused unescaped
  (`GlobError::UnsupportedSyntax`). A `**` that does not form a whole
  component is refused as `GlobError::MisplacedDoubleStar`.

  Literal characters are regex-escaped: every one of `\ . ^ $ | ? * + ( ) [ ] { }`
  gets a backslash. The pattern is wrapped in `^…$`, and the regex text then
  goes through the one string escaper (R4), so a regex `\.` is emitted as
  `"\\."`.
- **Measured** (26.6.2):
  - `(regex "^/tmp/a\\.b$")`, `(regex "^/tmp/[^/]*\\.rs$")`,
    `(regex "^/tmp/(.*/)?x$")` and a pattern escaping every metacharacter all
    compile;
  - the `#"…"` syntax also compiles, but is not used, so that one quoting
    function covers everything.
- **Rationale**: FR-002 to FR-004, R-03. Glob characters are never inferred:
  a `Subpath` with `*` in its name stays a `subpath`.
- **Alternatives**:
  - Raw `#"…"` regex literals: rejected, because they need a second escaping
    scheme.
  - Character classes: rejected for now. They are refused, not guessed.

## R4. The escaper and the inline limit

- **Decision**: `sbpl::quote(&[u8]) -> Result<String, EscapeError>` emits
  `"…"`. It escapes `\` as `\\` and `"` as `\"`. It refuses:
  - invalid UTF-8 (`NotUtf8 { at }`);
  - NUL and other control characters U+0000–U+001F and U+007F
    (`ControlCharacter { at, byte }`).

  Every other byte is copied unchanged, including non-ASCII UTF-8.

  If the quoted form is longer than `INLINE_LIMIT = 1016` bytes, the writer
  uses `(param "P<n>")`. The plan carries `("P<n>", value)`, where the value is
  the validated, unescaped string. Parameter names are generated (`P0`, `P1`,
  …), never taken from input.
- **Measured** (26.6.2):

  | Literal content | Result |
  |---|---|
  | 1023 characters | compiles |
  | 1024 characters | "Error reading string" |
  | 600 escaped backslashes (1,201 source bytes, 601 decoded) | compiles |
  | `\n`, `\x41;` | compile (the reader decodes them) |
  | parameters of 3,000+ bytes | compile |
  | an unset parameter | fails ("expected pattern, got boolean") |

  The cap therefore applies to the decoded length. Measuring the quoted form
  against 1016 is conservative: the quoted form is never shorter than the
  decoded one.
- **Why control characters are refused even though the reader decodes them**:
  emitting them raw relies on the reader's tolerance of raw newlines. Emitting
  them escaped relies on escape forms with no published grammar. Refusing them
  is fail-closed (constitution I) and costs nothing real: APFS rejects names
  that are not valid UTF-8, and control characters in paths are adversarial in
  practice.
- **Decoder for tests**: a test-only reader turns `"…"` back into bytes, using
  only `\\` and `\"`. Every accepted output must decode to exactly the input
  (SR-001).

## R5. Seatbelt lowering

- **Decision**: the profile is written in fixed blocks.
  1. `(version 1)` and `(deny default)`, or `(deny default (with message "<tag>"))`.
  2. **Allow block**: intent allows, grants and raw allows, each rendered and
     sorted bytewise.
  3. **Deny-within-allow block**: protect and hide, then raw denies, sorted.
  4. **Hard-deny block**: the classes in enum order, minus waivers, emitted
     last.

  Inside one block every rule has the same effect, so sorting cannot change
  meaning (last-match-wins only matters between different effects). This
  gives byte-identical output for any input order (FR-017). Duplicates are
  removed after rendering.

  Access mapping:

  | Intent | SBPL |
  |---|---|
  | Read | `(allow file-read* F)` |
  | Write | `(allow file-read* file-write* F)` |
  | Exec | `(allow file-read* process-exec* file-map-executable F)` |
  | Protect | `(deny file-write* F)`, plus rename anchors (R8) |
  | Hide | `(deny file-read* file-write* process-exec* file-map-executable F)` |
  | Subpath / Literal / Glob | `F` = `(subpath "…")` / `(literal "…")` / `(regex "…")` |
  | Grant `name` | `(allow <ops of access> (extension "procage.<name>"))`; the plan lists the class `procage.<name>` |

  Network:

  | Intent | SBPL |
  |---|---|
  | None | nothing |
  | Loopback(any) | `(allow network-outbound (remote ip "localhost:*"))` and `(allow network-bind network-inbound (local ip "localhost:*"))` |
  | Loopback(ports) | the same, one entry per port |
  | UnixSockets(paths) | `(allow network-outbound (remote unix-socket (path-literal "…")))` |
  | Proxy{http,socks} | outbound `localhost:<port>` for each port given |
  | All | `(allow network*)` |

  Any network other than None also adds `(allow system-socket)`.

  Process and IPC:

  | Intent | SBPL |
  |---|---|
  | `exec: Any` | `(allow process-exec* file-map-executable)` |
  | `fork` | `(allow process-fork)` |
  | `signals: SelfAndChildren` | `(allow signal (target self))` and `(allow signal (target children))` |
  | `posix_shm` | `(allow ipc-posix-shm*)` |
  | `sysv` | `(allow ipc-sysv*)` |

- **Measured**: every form in the tables compiles on 26.6.2, including
  `extension`, `path-literal`, `(target children)`, `localhost:*` and
  `localhost:<port>`.
- **Rationale**: the design (10 §2, §4.5, §5). A raw allow lands in the allow
  block, so it can never override a protect or hide rule, or the hard-deny
  tier (fail closed, SR-007).
- **Open for the spawn features**: whether an `exec: Granted` policy also needs
  an allow for the target binary's own exec, and the base profile (dyld,
  `/dev`). These belong to spawn 004 and base profile 006, which add rules
  through the same IR.

## R6. Closed operation list

- **Decision**: `seatbelt::Operation` is an enum of the 112 names below. Each
  compiled as `(allow <name>)` under `(deny default)` on 26.6.2.

  ```text
  file* file-read* file-read-data file-read-metadata file-read-xattr
  file-write* file-write-create file-write-data file-write-unlink
  file-write-mode file-write-owner file-write-flags file-write-times
  file-write-xattr file-write-acl file-write-setugid file-write-finderinfo
  file-ioctl file-link file-lock file-map-executable file-mknod file-mount
  file-unmount file-clone file-search file-test-existence file-issue-extension
  file-chroot file-revoke fs-rename
  network* network-outbound network-inbound network-bind system-socket socket-ioctl
  mach* mach-lookup mach-register mach-bootstrap mach-cross-domain-lookup
  mach-priv-host-port mach-priv-task-port mach-task-name mach-task-inspect
  mach-task-read mach-issue-extension
  process* process-exec* process-exec process-exec-interpreter process-fork
  process-info* process-info-listpids process-info-pidinfo process-info-pidfdinfo
  process-info-rusage process-info-codesignature process-info-setcontrol
  process-codesigning* signal
  iokit* iokit-open iokit-open-user-client iokit-open-service
  iokit-get-properties iokit-set-properties
  ipc* ipc-posix* ipc-posix-shm* ipc-posix-shm-read-data ipc-posix-shm-read-metadata
  ipc-posix-shm-write-create ipc-posix-shm-write-data ipc-posix-shm-write-unlink
  ipc-posix-sem* ipc-sysv* ipc-sysv-msg ipc-sysv-sem ipc-sysv-shm
  sysctl* sysctl-read sysctl-write nvram* user-preference* user-preference-read
  user-preference-write managed-preference-read appleevent-send lsopen
  darwin-notification-post distributed-notification-post pseudo-tty hid-control
  device-camera device-microphone dynamic-code-generation load-unsigned-code
  system* system-fsctl system-fcntl system-info system-privilege system-mac-syscall
  system-sched system-set-time system-audit system-reboot system-kext*
  job-creation qtn-user
  ```

  The following are excluded:
  - `default`, because the IR has no allow-by-default;
  - `mach-message-send` and `xpc-message-send`, which are not operations
    ("operation not applicable in this context", confirming the earlier macOS research).

  `Operation::Other(OperationName)` exists only with feature
  `unstable-operations`. `OperationName` accepts `[a-z0-9*-]{1,64}`, so a
  parenthesis, space or quote can never reach the profile (SR-004).
- **Filters** in the raw layer:
  - `Literal(AbsPath)`, `Subpath(AbsPath)`, `Regex(Glob)`;
  - `Extension(GrantName)`;
  - `GlobalName(Name)`, `GlobalNamePrefix(Name)` (mach), where `Name` is
    `[A-Za-z0-9._-]{1,128}`;
  - `TargetSelf`, `TargetChildren`, `TargetOthers`;
  - `RemoteIp(LoopbackAddr)`, `LocalIp(LoopbackAddr)`;
  - `UnixSocket(AbsPath)`.

  Rule: `Rule { effect: Allow|Deny, ops: Vec<Operation> (≥1), filters: Vec<Filter> }`.
  There is no modifier field at all: the only modifier procage emits is the run
  tag on `deny default`, which comes from `LowerOptions`. `(with no-sandbox)`
  has no representation (FR-011, SR-004).
- **Alternative**: re-mining the full 183-name list from the shared cache was
  rejected, because that list was not kept. The 112 cover the design. Adding a
  name is an additive change that must pass the compile test.

## R7. Linux lowering

- **Decision**: `LinuxPlan` has these fields:

  | Field | Contents |
  |---|---|
  | `tier`, `landlock_abi` | the target the plan is for |
  | `namespaces` | T1 only: user, mount, net, pid, ipc, uts |
  | `mounts` | T1 only: `ReadOnlyBind(path)` for protect, `Mask(path)` for hide, `PrivateDevShm` for POSIX shm |
  | `landlock` | `handled_fs`, `handled_net`, `scopes`, path rules (path, grant slot, or glob-to-expand) with `AccessFs`, net port rules |
  | `seccomp` | deny rules by name: `{ syscall, condition }` |
  | `network` | `Isolated` (T1 netns), `ProxyBridge { ports }` (T1), `LoopbackRelay` (T1, degraded), `Host` |
  | `no_new_privs` | always true |
  | `mask_unix_sockets` | ABI < 9 approximation only |

  `hygiene`, `degradations` and `waivers` are common to both plans.

  Landlock rights use their own bit constants (no extra dependency), and the
  set handled for an ABI is computed:

  | ABI | Adds |
  |---|---|
  | 1 | the FS base |
  | 2 | REFER |
  | 3 | TRUNCATE |
  | 4 | NET TCP |
  | 5 | IOCTL_DEV |
  | 6 | scopes |
  | 9 | RESOLVE_UNIX |
  | 10 | NET UDP |

  Access mapping:
  - Read = READ_FILE | READ_DIR;
  - Write = Read | WRITE_FILE | REMOVE_FILE | REMOVE_DIR | MAKE_REG | MAKE_DIR
    | MAKE_SOCK | MAKE_FIFO | MAKE_SYM | TRUNCATE (when handled);
  - Exec = Read | EXECUTE.

  REFER is never granted (rename anchors). EXECUTE is unhandled only for
  `exec: Any`.

  Minimum ABI is 1 for T1 and 4 for T2. A lower ABI is
  `TargetError::LandlockTooOld { tier, abi, min }`. An ABI above the newest
  known (12) is treated as 12; no later feature is assumed.

  Network:
  - **None**: seccomp denies `socket` for every family (`socketpair` stays
    allowed), plus netns on T1, plus Landlock net handled with no port rules
    (ABI ≥ 4). Exact on both tiers. This is stricter than the earlier Linux research,
    which relied on Landlock to stop pathname AF_UNIX connects, and Landlock
    cannot do that before ABI 9.
  - **UnixSockets**:
    - ABI ≥ 9: RESOLVE_UNIX rules on the listed paths, with seccomp allowing
      `socket(AF_UNIX)` only;
    - ABI < 9: T1 is approximated (`mask_unix_sockets`: the spawn backend
      masks discovered sockets, a snapshot); T2 is unsupported.
  - **Loopback**: T1 approximated (`LoopbackRelay`); T2 unsupported (Landlock
    filters ports, not addresses).
  - **Proxy**: T1 exact (`ProxyBridge`); T2 unsupported.
  - **All**: `Host`, with no socket denies.

  File targets:

  | Target | T1 | T2 |
  |---|---|---|
  | Subpath | exact | exact |
  | Literal | approximated (inode-bound, lost on rename-replace) | approximated |
  | Glob | approximated, "expanded at spawn" (FR-014a) | approximated |
  | Protect | exact (read-only bind) | unsupported |
  | Hide | exact (mask; "not found" instead of EPERM, a table note) | approximated (sibling snapshot) |

  Process and IPC:

  | Intent | T1 | T2 |
  |---|---|---|
  | `fork: false` | seccomp denies `fork`, `vfork`, `clone` without `CLONE_THREAD`; `clone3` returns ENOSYS | same |
  | `signals: SelfAndChildren` | exact (pid ns) | ABI ≥ 6: scope SIGNAL; else unsupported |
  | `signals: None` | seccomp denies `kill`, `tkill`, `tgkill`, `rt_sigqueueinfo`, `rt_tgsigqueueinfo`, `pidfd_send_signal` | same |
  | `posix_shm: true` | exact (private `/dev/shm` mount) | approximated (host `/dev/shm` is shared) |
  | `posix_shm: false` | exact (no rule) | exact (no rule) |
  | `sysv: true` | exact (ipc ns) | approximated (host IPC) |
  | `sysv: false` | seccomp denies the `shm*`, `sem*` and `msg*` families | same |

- **Rationale**: the tier model; fail closed where the
  research's T2 claims rested on rights Landlock lacks.
- **Alternatives**:
  - Generating BPF here: rejected. It is architecture-specific and belongs to
    spec 008.
  - The `landlock` crate: rejected. It needs std and applies rules, and this
    crate applies nothing.

## R8. Hard-deny classes in this feature

| Class | macOS (measured to compile) | Linux |
|---|---|---|
| `FcntlModify` | `(deny system-fcntl (fcntl-command 80 110))` | n/a |
| `Privilege` | `(deny file-write-setugid)`, `(deny process-exec* (file-mode #o4000))`, `(deny process-exec* (file-mode #o2000))` | `no_new_privs` |
| `ServiceHandoff` | `(deny mach-lookup (global-name "com.apple.coreservices.launchservicesd") (global-name-prefix "com.apple.lsd.") (global-name "com.apple.coreservices.appleevents") (global-name "com.apple.pasteboard.1"))`, `(deny mach-lookup (xpc-service-name-prefix ""))`, `(deny lsopen)`, `(deny appleevent-send)` | n/a |
| `ProcessAccess` | `(deny mach-priv-task-port mach-task-name mach-task-inspect mach-task-read)`, `(deny process-info* (require-not (target same-sandbox)))`, `(deny signal (target others))` | seccomp: `ptrace`, `process_vm_readv`, `process_vm_writev`, `pidfd_getfd`, `kcmp` |
| `RenameAnchors` | `(deny file-write-unlink (literal R))` for each writable root R; `(deny file-write-unlink (path-ancestors P))` for each protected or hidden P | REFER never granted; T1 protect/hide targets are mountpoints |
| `TerminalInjection` | `(deny file-ioctl (ioctl-command #x80017472))` (TIOCSTI) | seccomp `ioctl` with arg1 TIOCSTI or TIOCLINUX |
| `KernelSurface` | n/a | seccomp: `io_uring_setup`, `io_uring_enter`, `io_uring_register`, `bpf`, `perf_event_open`, `userfaultfd`, `keyctl`, `add_key`, `request_key` |
| `Namespaces` | n/a | seccomp: `unshare`, `setns`, `clone`/`clone3` with `CLONE_NEW*`, `mount`, `umount2`, `pivot_root`, `open_tree`, `move_mount`, `fsopen`, `fsmount` |
| `SocketFamilies` | n/a | seccomp `socket` with family AF_VSOCK or AF_NETLINK |

- The enum is `#[non_exhaustive]`, so 007 appends the data-driven classes.
- "Measured to compile" is not enforcement. The TIOCSTI deny in particular is
  unverified on macOS (KF-M26 shows the attack works unsandboxed). The escape
  suite (009) decides whether it holds, and spec 005's `Tty::None` is the
  primary defence.
- Hard-deny classes never produce gaps. A class marked n/a for a target emits
  nothing there, and the lowering table says so.

## R9. Limits guard

- **Decision**: the profile is held as `Vec<sbpl::Rule>` until it is written.
  The rule count is the number of top-level rules after `(deny default)`.
  - If the count is at most `max_rules` (default 2,000), there is no rewrite.
  - Otherwise `merge_adjacent` combines neighbouring rules that have the same
    effect and the same operation list, appending their filters into one
    `(require-any …)` of at most 64 filters. An unfiltered rule absorbs its
    neighbours: OR with "everything" is still everything.
  - If the profile is still over the limit, lowering fails with
    `LimitExceeded { limit, rules }`.

  Neighbouring rules of the same effect are OR'd under last-match-wins, so the
  rewrite matches exactly the same requests. It never creates a common prefix
  or parent subtree.
- **Check**: a test-only reference evaluator applies last-match-wins and
  default deny, with literal, subtree, extension and `require-any` matching and
  wildcard operations. Over generated rule lists and at least 10,000 requests,
  it compares `merge_adjacent(rules)` with `rules` (SR-008).
- **Why 64**: the rule-limit measurements of spec 001 (KF-M28) show that a 10,000-literal `require-any`
  fails with no error text. Small groups avoid that cliff. Choosing the
  bytecode-size limit belongs to spec 004.

## R10. Data format

- **Decision**: optional feature `serde`. It uses `serde` with
  `default-features = false, features = ["derive", "alloc"]`.
  - Every struct has `#[serde(deny_unknown_fields)]`.
  - Validated newtypes (`AbsPath`, `Glob`, `GrantName`, `Tag`, `Name`,
    `OperationName`) deserialise through `try_from`, so the constructor checks
    apply.
  - `AbsPath` is written as a string when it is valid UTF-8, otherwise as a
    sequence of byte values (untagged on read).
  - `Policy` is written as `{ "version": 1, … }` through a representation
    struct. Any other version is refused.

  Tests use `serde_json` as a dev-dependency.
- **Rationale**: FR-021, SR-010; an unknown field might be a restriction from a
  newer writer.
- **Alternatives**:
  - A bespoke format: rejected.
  - Lenient unknown fields: rejected, because they drop restrictions silently.

## R11. Generated-input tests and fuzzing

- **Decision**: generated-input tests use a small deterministic xorshift
  generator in `tests/common/mod.rs`, with a fixed seed and 10,000 cases per
  property. There is no `proptest`: it would add a dependency tree under
  `cargo deny`'s single-version rule, for little gain over cargo-fuzz.

  The fuzz package `crates/procage-policy/fuzz` (libfuzzer-sys, nightly) has
  four targets:

  | Target | Property |
  |---|---|
  | `quote` | an accepted value decodes back to the input |
  | `glob` | parse; every literal character is escaped in the regex |
  | `format` | read JSON; an accepted document round-trips |
  | `lower` | an arbitrary-built policy, every target: no panic |

  Recipe: `just fuzz <target> <seconds>`, plus `just fuzz-all` at 60 s each.
  CI gets a nightly job. The fuzz package is in the root workspace's
  `exclude`.
- **Installed**: cargo-fuzz 0.13.2 and the nightly toolchain.

## R12. Libsandbox compile test (well-formedness)

- **Decision**: a new integration test, `tests/kernel_facts/tests/policy_compiles.rs`
  in `procage-kernel-facts`, which gains a dev-dependency on `procage-policy`.
  On macOS it compiles:
  - every reference policy's profile, with its parameters;
  - `(allow <op>)` for every `Operation` variant.

  On other OSes the test file compiles to nothing, because there is no
  libsandbox. It reuses the kernel-facts `Sandbox` binding, so no new unsafe
  code is needed. Its doc comment states that compiling is not evidence of
  enforcement (SR-011).
- **Rationale**: FR-024, SR-004. The constitution names differential compile
  as principle II's check.
- **Alternative**: a dev-dependency from `procage-policy` on the FFI crate was
  rejected, because it would pull `unsafe` and libc into the portable crate's
  test graph.
