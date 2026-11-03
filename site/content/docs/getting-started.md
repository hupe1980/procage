+++
title = "Getting started"
description = "Add procage to a Rust project, cage a first command on macOS or Linux, bind a per-spawn grant and read the errors that tell you why a cage was refused."
weight = 10

[extra]
group = "Start"
+++

## Before you start

- procage is **pre-1.0**: the API may change between minor versions. The [threat model](@/docs/threat-model.md) says where it stops.
- **macOS** (tested on macOS 26 and 27, Apple silicon) or **Linux** with Landlock ABI 1 or later (Linux 5.13). On other targets only the policy types and the hygiene helpers build.
- **Rust 1.99** or newer (edition 2024).
- The caller must **not already be sandboxed**. On macOS a second Seatbelt profile fails or is ignored, so procage refuses with `SpawnError::AlreadySandboxed`. Inside an AI agent's sandbox, run from a plain terminal.

## Add the dependency

```sh
cargo add procage
```

The policy crate comes with it as `procage::policy`. To only build or check policies, depend on `procage-policy` alone: `no_std` with `alloc`, no `unsafe`.

## A first cage

```rust
use procage::native::{Cage, Grants}; // procage::macos or procage::linux
use procage::policy::{AbsPath, Access, Base, FsRule, FsTarget, Policy};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut policy = Policy::default(); // denies everything
    policy.base = Base::V3; // what ordinary programs and developer tools need to start
    policy.fs.push(FsRule::new(
        Access::Read,
        FsTarget::Subpath(AbsPath::new("/tmp/project")?),
    ));

    let cage = Cage::new(&policy)?; // lowered (and on macOS compiled) once
    let status = cage
        .spawn(std::process::Command::new("/bin/ls").arg("/tmp/project"), &Grants::new())?
        .wait()?;
    println!("ls exited with {status}");
    Ok(())
}
```

- `Policy::default()` grants nothing: no files, no network, no process creation, an empty environment, no terminal.
- `Base::V3` is a frozen, opt-in set of rules that lets ordinary programs and developer tools start. It grants nothing in your home directory. See [base profiles](@/docs/policies.md#base-profiles).
- `Cage::new` resolves paths (on macOS `/tmp` becomes `/private/tmp`) and lowers the policy. A `Cage` is reusable for any number of spawns, from any thread.
- `spawn` takes a `std::process::Command`, so arguments, working directory, standard streams and explicit variables work as usual. The returned `Child` dereferences to `std::process::Child`.

## Use a preset

Presets cover common shapes and carry the full hard-deny tier:

```rust
use procage::policy::{presets, AbsPath};

let workspace = AbsPath::new("/path/to/project")?;
let policy = presets::agent_workspace::v3(&workspace); // read, write and exec in the workspace
```

See [Presets](@/docs/presets.md).

## Bind a path per spawn

A policy can declare a named **grant** whose path is chosen at each spawn; the binding gives nothing to other spawns of the same cage:

```rust
use procage::native::{Cage, Grants};
use procage::policy::{Access, Base, Grant, GrantName, Policy};

let mut policy = Policy::default();
policy.base = Base::V1;
policy.grants.push(Grant { name: GrantName::new("data")?, access: Access::Read });

let cage = Cage::new(&policy)?;
let child = cage.spawn(
    std::process::Command::new("/bin/cat").arg("/srv/job-42/input.txt"),
    &Grants::new().bind("data", "/srv/job-42"),
)?;
```

The bound path must exist. The name `tmpdir` is reserved for a [private per-run `TMPDIR`](@/docs/lifetime-and-hygiene.md#a-private-temporary-directory).

## When the cage is refused

Every failure is a `SpawnError` with a readable `Display`, and no child runs. The common ones:

| Error | Meaning |
|---|---|
| `Lower(LowerError::Gaps(..))` | The policy uses constructs this host cannot enforce. Each `CapabilityGap` names the construct, the target and the path it concerns. See [Fitting a policy](@/docs/fitting.md). |
| `Path { .. }` | A policy path does not exist or cannot be resolved. |
| `Grant(..)` | A binding names an undeclared grant, a missing path or the reserved `tmpdir`, or (Linux T2) binds around a hidden or class path. |
| `HardLinks(..)` | A protected, hidden or credential file has a second name outside the protected set. See [Audits](@/docs/audits.md). |
| `AlreadySandboxed` (macOS) | The caller is itself in a Seatbelt sandbox. |
| `Unsupported(..)` | The host lacks something: a libsandbox symbol on macOS, Landlock or the requested tier on Linux, or a setting this version cannot apply (such as `Tty::NewPty`). |
| `Apply { step, errno }` | A step in the child failed before the target ran; `step` names it. |

## Portable code

`procage::native` is `procage::macos` on macOS and `procage::linux` on Linux. Code that uses only the shared subset builds on both without `cfg`: `Cage::new`, `Cage::with_options` and `Cage::fit` with `CageOptions::default().with_lower(…)`, `Cage::spawn`, `Cage::spawn_with_fds`, `Grants::new().bind(…)`, and the `Child` methods `kill_all`, `detach`, `dropped_env`, `tmpdir` and `receipt`. Errors are each backend's own `SpawnError`.

## Next

- [Policies](@/docs/policies.md), the [macOS](@/docs/macos.md) and [Linux](@/docs/linux.md) backends, and the [threat model](@/docs/threat-model.md).
- The rustdoc on [docs.rs](https://docs.rs/procage), with a macOS and a Linux view, is the reference for every type.
