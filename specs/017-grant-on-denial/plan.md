# Implementation Plan: Grant on denial

**Branch**: `017-grant-on-denial` (local planning; commits on `main`) | **Date**: 2026-11-03 | **Spec**: [spec.md](spec.md)

## Design

### Types (`procage-policy`, new module `suggest`)

```rust
pub struct Suggestion { change: Change, weakens: bool }
#[non_exhaustive]
pub enum Change {
    Allow(FsRule),          // a literal rule: Read, Write or Exec
    UnixSocket(AbsPath),    // added to ipc.unix_sockets
    LeaveOut(FsRule),       // the protect or hide rule that denied it
    Relax(Relaxation),      // Waive(class) or SignalsSameUser
}
impl Suggestion {
    pub fn change(&self) -> &Change;
    pub fn weakens(&self) -> bool;
    pub fn apply(&self, policy: &Policy) -> Policy;  // a new policy
}
impl Display for Suggestion  // "allow writing /p", "waive the trust-handoff class (weakens)"
```

`apply` clones the policy and changes exactly one thing: pushes the rule,
pushes the socket path, removes the one equal rule, inserts the waiver, or
sets `Signals::SameUser`. Nothing touches a running child (no handle is
taken). Constructors are `pub(crate)` except through `procage::suggest`,
plus `Suggestion::new` for tests of `apply` (the type's fields stay
private so a mark cannot be dropped).

### Derivation (`procage::suggest(&Policy, &Violation) -> Option<Suggestion>`)

| `denied_by` | operation | suggestion |
|---|---|---|
| `NotGranted` | `file-read*` | `Allow(Read literal target)` |
| `NotGranted` | `file-write*` | `Allow(Write literal target)` |
| `NotGranted` | `process-exec*`, `file-map-executable` | `Allow(Exec literal target)` |
| `NotGranted` | `network-outbound` with an absolute target | `UnixSocket(target)` |
| `NotGranted` | `signal` | `Relax(SignalsSameUser)`, weakening |
| `HardDeny(Secrets)` | any | none |
| `HardDeny(class)` | any | `Relax(Waive(class))`, weakening |
| `Protect` / `Hide` | any | `LeaveOut(rule)`: the policy's protect or hide rule whose target covers the path (literal equal, subpath prefix, glob match), weakening; none if no rule covers it |
| `Layer`, `Lifetime`, `OlderKernel`, `Allowlist`, `Unknown` | any | none |

Anything else (no target, a relative target, other operations): none. A
grant never lands under a hidden or secret path: there the deny rule wins,
so the denial is reported as `Hide` (leave-out, weakening) or as the
`secrets` class (none), never as not granted.

On Linux, Landlock denials are not reported, so Linux suggestions come
from seccomp denials only (hard-deny classes). Lossy macOS records miss
suggestions with their denials.

### Records

- `Suggestion` derives `Debug, Clone, PartialEq, Eq, Hash` (so a harness
  can deduplicate) and, with the `serde` feature, serialises.
- Rustdoc: the child chooses what it is denied, so suggestions are
  attacker-influenced; show the path and access verbatim, and treat a
  weakening one as such (SR-003, threat.provoked-prompt).
- Site: `docs/violations.md` gains a "From a denial to a grant" section;
  CHANGELOG.

## Tests (the kernel is the oracle)

`tests/suggest_macos.rs`, with violation reporting, one case per row:
deny, take the suggestion, check it, apply, respawn, the operation now
succeeds, and `explain::diff(old, new)` shows only the change:

- read and write outside the policy (and a sibling stays denied), exec of
  a copied program, a Unix socket connect;
- a protected path (leave out, weakening); a hidden file (leave out,
  weakening);
- `trust-handoff` (`.git/hooks`): waiver, weakening, the new run's receipt
  lists it;
- `secrets` (`.env`): none.

`tests/suggest_linux.rs` (T1 and T2), from seccomp records: a hard-deny
syscall (`ptrace` of the class that denies it) gives its waiver and the
respawn succeeds; a `Lifetime::Run` `setsid` gives none.

Unit tests in `procage-policy` for `apply` (each change alters exactly one
field) and in `procage` for the derivation table without a kernel.

## Decisions (implementation)

- **One enum.** `Suggestion` is itself the enum (`Allow`, `UnixSocket`,
  `LeaveOut`, `Waive`, `SignalsSameUser`); `weakens()` is computed from the
  variant, so the mark cannot be dropped or forged, and serde comes with
  the policy types (`Relaxation` has none). The `Change` type above was
  not needed.
- **Resolved paths.** The kernel reports resolved paths (`/private/var/…`);
  a protect or hide rule may be written unresolved, so `suggest` matches
  each rule as written and resolved (`procage_policy::suggest::covers`).
- **What the diff shows.** Adding a rule under base V2 or V3 also adds the
  base's metadata reads on the way to its path, and leaving out a protect
  rule drops its `rename-anchors` deny on the ancestors: both belong to the
  rule. The kernel test accepts exactly those beside the rule.
- **FR-004 in the receipt.** A receipt lists waivers by class and names
  the policy by its digest; it does not list file rules. So an applied
  waiver shows in the receipt itself, and an applied grant as a new digest
  whose rule `explain::diff` of the two policies shows. No receipt field
  was added for rules.
- **Tests.** The Linux case lives in `spawn_linux.rs`, which has the child
  entry and the reporting helpers (no `suggest_linux.rs`). The exec case
  runs a script: macOS refuses to launch a copied system program outside
  its location (launch constraints), caged or not. The secret case lists
  `~/Library/Keychains` (every account has it; nothing is read): a missing
  file under `~/.ssh` fails with ENOENT before the sandbox decides.

## Constitution Check

| Principle | Check | Status |
|---|---|---|
| I | No suggestion widens beyond the denied path and access; weakening ones are marked; secrets never | PASS |
| II | Suggestions are typed (`Change`), never strings; literal rules only | PASS |
| III | Each row is shown by a denial and a respawn on the kernel | PASS |
| IV | No child code | PASS |
| V | Nothing changes a running child | PASS |
| VI | No private interface added | PASS |
| VII | No global state; no approval storage; additive API (0.5.0) | PASS |

**Remaining gaps**: Linux file and network denials are not reported, so
there are no Linux file suggestions; lossy macOS records lose suggestions.
