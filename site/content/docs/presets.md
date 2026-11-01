+++
title = "Presets"
description = "procage's frozen presets (minimal, agent_readonly, agent_workspace, build): what each grants, the base profile and environment they use, and how they behave on Linux tiers."
weight = 30

[extra]
group = "Policies"
+++

A preset is a function that returns an ordinary `Policy`, so you can inspect and extend it like any other. Presets are **frozen**: a version never loosens. Use version 3.

```rust
use procage::policy::{presets, AbsPath, Network};

let workspace = AbsPath::new("/path/to/project")?;
let mut policy = presets::agent_workspace::v3(&workspace);
policy.net = Network::All; // your own addition; the preset tag stays for receipts
```

## The presets

| Preset | Adds |
|---|---|
| `minimal::v1`, `v2`, `v3` | nothing |
| `agent_readonly::v1`, `v2`, `v3` | read of the workspace, the `tmpdir` grant, fork, signals to self and children |
| `agent_workspace::v1`, `v2`, `v3` | as `agent_readonly`, plus write and exec on the workspace |
| `build::v1` | as `agent_workspace`, plus loopback network (any port) |
| `build::v2`, `build::v3` | as `build::v1`, plus Unix sockets in the workspace |

Every preset also has:

- the base profile of the same version: `Base::V2` and `Base::V3` run developer tools such as `git`, `clang` and Homebrew's, and V3 keeps harmless probes out of violation records;
- the full [hard-deny tier](@/docs/hard-deny.md), nothing waived;
- an environment allowlist of `HOME`, `LANG`, `LC_ALL`, `PATH`, `TERM`, `TMPDIR` and `USER`;
- a `PresetTag` with its name and version;
- the default `Lifetime::Run`: the processes a forking preset's child starts end with the run. On Linux `setsid` and `setpgid` fail inside them; on macOS their profiles carry the run marker.

## On Linux

- `build` is a capability gap on both tiers: Linux cages have no loopback networking. [`Cage::fit`](@/docs/fitting.md) with `Relax::no_loopback()` runs it with no network at all.
- The write rules of `agent_workspace` and `build` reach trust-handoff names such as `.git/hooks` and `.bashrc`. Tier T1 makes the existing ones read-only at spawn, an approximation accepted with `LowerOptions::accept_spawn_snapshot()`. Tier T2 cannot protect a path inside a writable tree, so the policy is refused unless the class is waived.
- `signals: SelfAndChildren` needs Landlock ABI 6 (Linux 6.12). On older kernels it is a gap; `Relax::signals_same_user()` is the named way out.
