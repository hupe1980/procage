+++
title = "Fitting a policy to the host"
description = "Cage::fit: when a host cannot enforce part of a policy, relax only what you name, get each relaxation back with what would lift it, and tell your user."
weight = 70

[extra]
group = "Guides"
nav = "Fitting a policy"
+++

A host that cannot enforce part of a policy **refuses the cage** and lists every part as a capability gap: procage never weakens a policy on its own. A harness that would rather run with a known, stated limit (for example on a Linux host without user namespaces) calls `Cage::fit` with the relaxations it accepts. procage applies exactly those to the gaps the host reports and returns the cage with the list of what was relaxed, each with what would lift it.

```rust
use procage::native::{Cage, CageOptions};
use procage::policy::{HardDenyClass, Policy, Relax};

let relax = Relax::new()
    .leave_out_protect() // e.g. `.git` inside a writable workspace
    .waive(HardDenyClass::TrustHandoff)
    .signals_same_user(); // Linux older than 6.12
let (cage, relaxed) = Cage::fit(&policy, &CageOptions::default(), &relax)?;
for r in &relaxed {
    eprintln!("sandbox: {r}");
}
```

On Linux tier T2 with Landlock ABI 8, a policy that protects `/w/.git` inside a writable `/w` prints:

```text
sandbox: fs-protect /w/.git on Linux T2 (Landlock ABI 8): the protect rule is left out; tier T1 (user namespaces) would enforce it
```

## The relaxations

Each relaxation has exactly one effect. Nothing else can be relaxed.

| `Relax` method | Answers the gap | Effect |
|---|---|---|
| `leave_out_protect()` | `fs-protect` | The protect rule the gap names is left out |
| `leave_out_hide()` | `fs-hide` | The hide rule the gap names is left out |
| `waive(class)` | the class's `hd-*` construct | The hard-deny class is waived |
| `no_unix_sockets()` | `ipc-unix-sockets` | No Unix socket is reachable (stricter) |
| `no_loopback()` | `net-loopback` | No network at all (stricter) |
| `signals_same_user()` | `signals-self-and-children` | Signals reach every process of the user |

`Relax::accept(Relaxation::…)` does the same with the enum.

## What you get back

Each `Relaxed` holds:

- `gap`: the `CapabilityGap` the host reported (construct, target, subject path);
- `relaxation`: the change made;
- `lift`: what would make the construct enforceable: tier T1 (user namespaces), a newer Landlock ABI, or either. On macOS, where gaps are rare, the lift is unknown.

Its `Display` is one line for your user. Show it: a relaxation is a weaker sandbox. Relaxations are also recorded in each [receipt](@/docs/receipts.md).

Any gap without an accepted relaxation still fails, with **every** remaining gap, and the policy is not changed. Gaps found only at spawn (for example a grant bound around a hidden path on T2) are not relaxed by fitting.

## Fitting versus approximations

These are separate consents:

- **Relaxations** (`Cage::fit`) give up a construct entirely, or make it stricter.
- **Approximations** (`LowerOptions::allow_degrade`, `LowerOptions::allow`, or `accept_spawn_snapshot()` for the ones taken at spawn) keep a construct in a weaker form, such as masking the class paths that exist at spawn on tier T1. They are listed in the plan's degradations.

Pass approximations through `CageOptions::default().with_lower(…)`; `Cage::fit` honours them.
