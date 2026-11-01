+++
title = "Presets"
description = "procage's frozen presets (minimal, agent_readonly, agent_workspace, build): what each grants, the base profile and environment they use, and how they behave on Linux tiers."
weight = 30

[extra]
group = "Policies"
+++

A preset is a function that returns an ordinary `Policy`, so you can inspect and extend it like any other. Presets are **frozen**: a version never loosens. Start with version 2.

```rust
use procage::policy::{presets, AbsPath, Network};

let workspace = AbsPath::new("/path/to/project")?;
let mut policy = presets::agent_workspace::v2(&workspace);
policy.net = Network::All; // your own addition; the preset tag stays for receipts
```

## The presets

| Preset | Adds |
|---|---|
| `minimal::v1`, `minimal::v2` | nothing |
| `agent_readonly::v1`, `agent_readonly::v2` | read of the workspace, the `tmpdir` grant, fork, signals to self and children |
| `agent_workspace::v1`, `agent_workspace::v2` | as `agent_readonly`, plus write and exec on the workspace |
| `build::v1` | as `agent_workspace`, plus loopback network (any port) |
| `build::v2` | as `build::v1`, plus Unix sockets in the workspace |

Every preset also has:

- a base profile: `Base::V1` for version 1, `Base::V2` for version 2, which runs developer tools such as `git`, `clang` and Homebrew's;
- the full [hard-deny tier](@/docs/hard-deny.md), nothing waived;
- an environment allowlist of `HOME`, `LANG`, `LC_ALL`, `PATH`, `TERM`, `TMPDIR` and `USER`;
- a `PresetTag` with its name and version;
- the default `Lifetime::Run`: the processes a forking preset's child starts end with the run. On Linux `setsid` and `setpgid` fail inside them; on macOS their profiles end with the run-marker block. This was added to the frozen version 1 presets as a tightening.

## On Linux

- `build` is a capability gap on both tiers until loopback networking is relayed into the network namespace. [`Cage::fit`](@/docs/fitting.md) with `Relax::no_loopback()` runs it with no network at all.
- The write rules of `agent_workspace` and `build` reach trust-handoff names such as `.git/hooks` and `.bashrc`. Tier T1 makes the existing ones read-only at spawn, an approximation accepted with `LowerOptions::accept_spawn_snapshot()`. Tier T2 cannot protect a path inside a writable tree, so the policy is refused unless the class is waived.
- `signals: SelfAndChildren` needs Landlock ABI 6 (Linux 6.12). On older kernels it is a gap; `Relax::signals_same_user()` is the named way out.

The tests observe the presets behaving as documented on macOS, where the macOS backend's test suite runs all four.
