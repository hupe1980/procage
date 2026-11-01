# Data model: 003-policy-ir

All types live in `procage-policy` and are `no_std` + `alloc`. "Validated"
means the constructor and serde `try_from` both run the same check.

## Values

| Type | Representation | Rule | Error |
|---|---|---|---|
| `AbsPath` | `Vec<u8>` | starts with `/`; no NUL; no empty, `.` or `..` component; no trailing `/` except `/` | `PathError::{Empty, Relative, Nul{at}, EmptyComponent{at}, DotComponent{at}, DotDotComponent{at}, TrailingSlash}` |
| `Glob` | source `String` | absolute; UTF-8; no control characters; tokens `*`, `**` (whole component), `?`, `\x`; `[ ] { }` refused unescaped | `GlobError::{Relative, ControlCharacter{at}, UnsupportedSyntax{at, ch}, MisplacedDoubleStar{at}, TrailingEscape, Empty}` |
| `GrantName` | `String` | `[a-z0-9_-]{1,32}` | `NameError` |
| `Tag` | `String` | `[A-Za-z0-9._-]{1,64}` | `NameError` |
| `Name` (mach names) | `String` | `[A-Za-z0-9._-]{1,128}` | `NameError` |
| `OperationName` (unstable) | `String` | `[a-z0-9*-]{1,64}` | `NameError` |
| `Port` | `u16` | 1–65535 | `NameError::Port` |

## Intent layer: `Policy` (`#[non_exhaustive]`, `Default` = deny everything)

| Field | Type | Default |
|---|---|---|
| `fs` | `Vec<FsRule { access: Access, target: FsTarget }>` | empty |
| `net` | `Network` | `None` |
| `process` | `Process { exec: Exec, fork: bool, signals: Signals }` | `{ Granted, false, None }` |
| `ipc` | `Ipc { posix_shm: bool, sysv: bool }` | `{ false, false }` |
| `env` | `EnvPolicy::{Allowlist(Vec<String>), Passthrough { deny: Vec<String> }}` | `Allowlist([])` |
| `limits` | `Rlimits { nproc, cpu_seconds, fsize_bytes, nofile: Option<u64>, core_bytes: u64 = 0 }` | all `None`, `core = 0` |
| `tty` | `Tty::{None, Inherit, NewPty}` | `None` |
| `waive` | `BTreeSet<HardDenyClass>` | empty |
| `grants` | `Vec<Grant { name: GrantName, access: Access }>` | empty |
| `seatbelt` | `Option<seatbelt::Layer { rules: Vec<seatbelt::Rule> }>` | `None` |
| `linux` | `Option<linux::Layer { syscalls_deny: Vec<Syscall>, landlock_extra: Vec<(AbsPath, Access)> }>` | `None` |

- `Access::{Read, Write, Exec, Protect, Hide}`. `Write` implies read, and
  `Exec` implies read. A grant's access must be `Read`, `Write` or `Exec`
  (`PolicyError::GrantAccess`).
- `FsTarget::{Literal(AbsPath), Subpath(AbsPath), Glob(Glob)}`.
- `Network::{None, Loopback(Ports), UnixSockets(Vec<AbsPath>), Proxy { http: Option<Port>, socks: Option<Port> }, All}`,
  where `Ports::{Any, List(BTreeSet<Port>)}`. A `Proxy` with neither port set
  is refused (`PolicyError::EmptyProxy`).
- `Exec::{Granted, Any, Never}`:
  - `Granted`: execution only where an `Exec` rule or grant allows it;
  - `Never`, combined with any `Exec` rule or grant, is
    `PolicyError::ExecConflict`.

  This replaces the design's `Paths[..]` variant, because file rules already
  name the paths.
- `Signals::{SelfAndChildren, None}`.
- `HardDenyClass` (`#[non_exhaustive]`, `Ord`): `FcntlModify`, `Privilege`,
  `ServiceHandoff`, `ProcessAccess`, `RenameAnchors`, `TerminalInjection`,
  `KernelSurface`, `Namespaces`, `SocketFamilies`.
- `Policy::validate() -> Result<(), Vec<PolicyError>>` runs the cross-field
  rules. `lower` calls it first.

## Seatbelt layer (`seatbelt`)

- `Rule { effect: Effect::{Allow, Deny}, ops: Vec<Operation>, filters: Vec<Filter> }`.
  `ops` must be non-empty (`PolicyError::EmptyOperations`). An empty `filters`
  means unfiltered.
- `Operation`: the 112 names of research R6, plus `Other(OperationName)` under
  feature `unstable-operations`. `Operation::ALL` lists the stable ones, and
  `as_str()` gives each name.
- `Filter::{Literal(AbsPath), Subpath(AbsPath), Regex(Glob), Extension(GrantName), GlobalName(Name), GlobalNamePrefix(Name), TargetSelf, TargetChildren, TargetOthers, RemoteLoopback(Ports), LocalLoopback(Ports), UnixSocket(AbsPath)}`.
- There is no modifier field. No value can produce `(with …)` (SR-004).

## Linux layer (`linux`)

- `Syscall`: an enum of the syscall names the plans use, plus
  `Other(SyscallName [a-z0-9_]{1,32})`.
- `Layer` entries are checked against the target: `landlock_extra` rights must
  be handled by the ABI. The entries are added to the plan; they never remove
  anything.

## Lowering

- `Target::{MacOs, Linux { tier: Tier::{T1, T2}, landlock_abi: u8 }}`.
- `LowerOptions { allow_degrade: BTreeSet<Construct>, max_rules: usize = 2000, tag: Option<Tag> }`.
- `Construct` (kebab-case names, the row names of the lowering table):
  - file: `fs-read-subpath`, `fs-write-subpath`, `fs-exec-subpath`,
    `fs-literal`, `fs-glob`, `fs-protect`, `fs-hide`, `grant`;
  - network: `net-none`, `net-loopback`, `net-unix-sockets`, `net-proxy`,
    `net-all`;
  - process: `exec-any`, `exec-never`, `fork-denied`,
    `signals-self-and-children`, `signals-none`;
  - IPC: `posix-shm`, `sysv-ipc`;
  - backend layers: `seatbelt-layer`, `linux-layer`;
  - hygiene: `hygiene`;
  - hard-deny: `hd-fcntl-modify`, `hd-privilege`, `hd-service-handoff`,
    `hd-process-access`, `hd-rename-anchors`, `hd-terminal-injection`,
    `hd-kernel-surface`, `hd-namespaces`, `hd-socket-families`.
- `Outcome::{Exact, Approximated, Unsupported, NotApplicable}`.
  - `Approximated` is accepted only when the construct is in `allow_degrade`;
    the plan then records a `Degradation { construct, target, note }`.
  - `Unsupported` is always a gap.
  - `NotApplicable` emits nothing.
- `CapabilityGap { construct, target, kind: GapKind::{Approximation, Unsupported, Unrepresentable(EscapeError)}, subject: Option<String> }`.
  The subject holds the offending path or name, for messages.
- `LowerError`:
  - `Invalid(Vec<PolicyError>)`
  - `Target(TargetError::LandlockTooOld { tier, abi, min })`
  - `Gaps(Vec<CapabilityGap>)`, which is complete and sorted
  - `LimitExceeded { limit, rules }`
- `Plan::{Seatbelt(SeatbeltPlan), Linux(LinuxPlan)}`.
- `SeatbeltPlan`:
  - `profile: String`, `params: Vec<(String, String)>`;
  - `grants: Vec<GrantSlot { name, class, access }>`;
  - `rule_count`, `merged: bool`;
  - `degradations`, `waivers: Vec<HardDenyClass>`, `hygiene: Hygiene`.
- `LinuxPlan`: as described in research R7, plus `degradations`, `waivers`,
  `hygiene`.
- `Hygiene { env, limits, tty }` is copied unchanged from the policy.

## Invariants (tested)

1. `lower` is deterministic, and independent of the order of `fs`, `grants`,
   `UnixSockets`, `seatbelt.rules` and `linux` entries (FR-017).
2. Every SBPL rule is in the allow block, the deny-within-allow block or the
   hard-deny block, in that order. The hard-deny block is last and holds
   exactly the classes not waived (SR-007).
3. Every quoted string in a profile decodes to a value from the policy, the
   fixed hard-deny constants, or a generated parameter name (SR-001).
4. `merge_adjacent` preserves every decision of the reference evaluator
   (SR-008).
5. Serialising then reading gives an equal value (FR-021).
