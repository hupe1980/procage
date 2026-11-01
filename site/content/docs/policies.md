+++
title = "Policies"
description = "The procage policy: a portable, deny-by-default intent layer for files, network, processes, IPC, environment, limits and terminal, and how it is lowered to Seatbelt and Linux plans."
weight = 20

[extra]
group = "Policies"
+++

A `Policy` (from the `procage-policy` crate, re-exported as `procage::policy`) says what a child may do. It is written once and lowered for each backend. Its default effect is **deny**: `Policy::default()` grants no files, no network, no process creation, no signals, an empty environment and no terminal.

`Policy` is `#[non_exhaustive]`: start from `Policy::default()` (or a [preset](@/docs/presets.md)) and set fields.

## The fields

| Field | Type | Default | What it controls |
|---|---|---|---|
| `fs` | `Vec<FsRule>` | empty | File access, by path or glob |
| `net` | `Network` | `None` | Network access |
| `process` | `Process` | no exec outside rules, no fork, no signals, `Lifetime::Run` | Programs, process creation, signals, lifetime |
| `ipc` | `Ipc` | nothing | POSIX shared memory, System V IPC, Unix sockets |
| `env` | `EnvPolicy` | empty allowlist | The child's environment |
| `limits` | `Rlimits` | core dumps off | Resource limits |
| `tty` | `Tty` | `None` | The controlling terminal |
| `base` | `Base` | `None` | A curated base profile |
| `grants` | `Vec<Grant>` | empty | Paths bound per spawn |
| `waive` | `BTreeSet<HardDenyClass>` | empty | [Hard-deny classes](@/docs/hard-deny.md) removed by name |
| `preset` | `Option<PresetTag>` | `None` | The preset it was built from (informational) |
| `seatbelt`, `linux` | backend layers | `None` | Raw rules for one backend |

## File rules

A rule is an `Access` on an `FsTarget`:

```rust
use procage::policy::{AbsPath, Access, FsRule, FsTarget, Glob, Policy};

let mut policy = Policy::default();
policy.fs.push(FsRule::new(Access::Write, FsTarget::Subpath(AbsPath::new("/work")?)));
policy.fs.push(FsRule::new(Access::Protect, FsTarget::Subpath(AbsPath::new("/work/.git")?)));
policy.fs.push(FsRule::new(Access::Hide, FsTarget::Literal(AbsPath::new("/work/.env")?)));
policy.fs.push(FsRule::new(Access::Read, FsTarget::Glob(Glob::new("/data/**/*.csv")?)));
```

| Access | Meaning |
|---|---|
| `Read` | Read files and list directories |
| `Write` | Create, change and remove; includes read |
| `Exec` | Execute programs; includes read |
| `Protect` | Readable but not writable, even inside a writable tree |
| `Hide` | Neither readable nor writable, even inside a readable tree |

| Target | Meaning |
|---|---|
| `Subpath(AbsPath)` | The path and everything under it |
| `Literal(AbsPath)` | Exactly this path |
| `Glob(Glob)` | Paths matching an absolute glob (exact on macOS only; a gap on Linux) |

Rules can be listed in any order; the order never changes the result. `AbsPath` is an absolute path held as bytes; procage resolves it to the spelling the kernel matches before applying it, so a rule written through `/tmp` or a symbolic link still holds (escape class R-02).

## Network

| `Network` | macOS | Linux |
|---|---|---|
| `None` (default) | exact | exact: `socket` is refused for every family (`socketpair` still works); tier T1 also gets an empty network namespace |
| `Loopback(Ports)` | exact | gap: needs a relay into the network namespace, not implemented |
| `Proxy { http, socks }` | exact: outbound only to those loopback ports | gap |
| `All` | exact | exact |

## Processes

`Process` has four parts:

- `exec`: `Exec::Granted` (default; only where an `Exec` rule or grant allows), `Exec::Any` (anywhere the child can read) or `Exec::Never`.
- `fork`: whether the child may create processes (default `false`).
- `signals`: `Signals::None` (default), `SelfAndChildren`, or `SameUser`, which lets signals reach every process the OS allows (on Linux, every process of the same user). `SameUser` exists for Linux hosts below Landlock ABI 6 that cannot keep signals within the run; procage never picks it on its own.
- `lifetime`: `Lifetime::Run` (default) or `Lifetime::Tree`. See [Lifetime and hygiene](@/docs/lifetime-and-hygiene.md#lifetime).

## IPC

`Ipc` has `posix_shm` and `sysv` switches and `unix_sockets`, a list of paths at or under which the child may create, bind, listen on and connect to Unix-domain sockets, whatever `net` says. Binding also needs write access to the directory. Keep these paths short: socket addresses are limited to 104 bytes on macOS and 108 on Linux. On Linux below Landlock ABI 9 this is approximated on tier T1 and refused on tier T2 (see [Linux](@/docs/linux.md#unix-sockets)).

## Environment, limits, terminal

- `EnvPolicy::Allowlist(names)` (default, empty) passes only the named variables of the caller. `EnvPolicy::Passthrough { deny }` passes everything except `deny` and a built-in denylist of secret-looking names. Variables set explicitly on the `Command` always win. Details in [hygiene](@/docs/lifetime-and-hygiene.md#environment).
- `Rlimits` sets `nproc`, `cpu_seconds`, `fsize_bytes`, `nofile` and `core_bytes` (0 by default: no core dumps).
- `Tty::None` (default) gives no controlling terminal; the child leads its own session. `Tty::Inherit` shares the caller's terminal, with keystroke injection denied. `Tty::NewPty` is not implemented yet and is refused.

## Base profiles

Most programs cannot even start under a pure deny-everything policy: the dynamic loader, locale data and the system's user database are all files. A **base profile** is a curated, frozen set of rules that lets ordinary programs start, and nothing the user cares about. A policy has none unless it opts in:

- `Base::V1`: system code and libraries, `/etc` files, locale and time-zone data, standard devices, the sysctls the Rust runtime and `uname` read, and a few system services (user names, notifications, certificate trust). Nothing under `/Users`, the temporary directories or `/Volumes`; no network; no writes beyond standard devices.
- `Base::V2`: V1 plus what developer tools need. On macOS, measured with Apple's tool shims, Xcode, the Command Line Tools and Homebrew: the developer directories, `xcode-select`'s link, the Xcode license state, Homebrew's code directories (not its `etc` or `var`) and OpenSSL configuration. On Linux V2 is the same as V1.

- `Base::V3` (recommended): V2, with the probes every program makes refused **quietly**: the logging services (`logd`, `diagnosticd`), `dirhelper`, group membership lookups, the dyld DTrace helper's ioctl and `/dev/tty`. None is needed, so V3 allows exactly what V2 allows; it only keeps these probes out of [violation records](@/docs/violations.md), which then show what matters. On Linux V3 is the same as V2.

Each version is frozen: a loosening needs a new version. The macOS content was measured on macOS 26.6.2; with `Base::V1`, Xcode shims such as `/usr/bin/git` do not run, so use V3 (or V2) for developer tools.

## Grants

A `Grant { name, access }` declares a named slot for a path chosen per spawn with `Grants::bind`. On macOS it becomes a sandbox extension, on Linux a Landlock rule for the bound path. The name `tmpdir` is reserved for a private per-run temporary directory. See [Getting started](@/docs/getting-started.md#bind-a-path-per-spawn).

## Backend layers

`policy.seatbelt` (a `seatbelt::Layer`) and `policy.linux` (a `linux::Layer`) add typed raw rules for one backend. A layer for the other backend is an approximation: it is ignored only when you allow it by name.

## Lowering

`lower(&policy, target, &options)` turns a policy into a `SeatbeltPlan` or a `LinuxPlan`, or returns the **complete** list of `CapabilityGap`s. Each construct is:

- **exact**: expressed as written;
- **approximated**: the plan can only come close. Lowering returns a gap unless you name the construct in `LowerOptions::allow_degrade`; when allowed, the plan lists it among its degradations;
- **unsupported**: always a gap; no option turns it into a weaker rule;
- **n/a**: meaningless on the target (for example a macOS-only hard-deny class on Linux).

The cage does this for you, but the policy crate can be used alone, for example to check a policy against every target in a test:

```rust
use procage_policy::{
    AbsPath, Access, FsRule, FsTarget, LowerOptions, Plan, Policy, Target, Tier, lower,
};

let mut policy = Policy::default();
policy.fs.push(FsRule::new(Access::Write, FsTarget::Subpath(AbsPath::new("/work")?)));
policy.fs.push(FsRule::new(Access::Protect, FsTarget::Subpath(AbsPath::new("/work/.git")?)));

let options = LowerOptions::default();
let Plan::Seatbelt(plan) = lower(&policy, Target::MacOs, &options)? else { unreachable!() };
assert!(plan.profile.contains("(deny file-write* (subpath \"/work/.git\"))"));

// Landlock alone cannot protect a subtree inside a writable one.
let t2 = Target::Linux { tier: Tier::T2, landlock_abi: 6 };
assert!(lower(&policy, t2, &options).is_err());
```

`LowerOptions::accept_spawn_snapshot()` accepts, together, every approximation that depends on the file system as procage reads it at spawn (masks of the data-driven hard-deny paths on tier T1, piecewise hiding on tier T2, masked Unix sockets on T1). It is what reading the whole file system except secrets needs on Linux.

The full lowering table, one row per construct with the macOS, Linux T1 and Linux T2 outcome, is in the rustdoc of `procage_policy::lower`.

A Seatbelt profile is written in fixed blocks: `(deny default)`, every allow, every deny inside an allow (protect, hide, raw denies), and the hard-deny tier last. Within a block rules are sorted.

## A data format

With the `serde` feature, `procage-policy` reads and writes a versioned document (`"version": 1`; any other version is refused). Every map refuses unknown fields, because an unknown field may be a restriction written by a newer writer, and every value is read through its constructor.
