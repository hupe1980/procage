# procage

🛡️ **Process sandboxing for Rust.** procage runs a child process in an OS
sandbox on macOS (Seatbelt, without the deprecated `sandbox-exec`) and on
Linux (Landlock, seccomp and namespaces). No helper binaries, no root.

It is built for programs that run commands on someone else's behalf: coding
agents, MCP servers, build orchestrators. The code inside the child runs with
your user id, whether it is an LLM following injected instructions or a
project's build script.

```sh
cargo add procage
```

```rust
use procage::native::{Cage, Grants};
use procage::policy::{AbsPath, presets};

let workspace = AbsPath::new("/Users/me/project")?;
let cage = Cage::new(&presets::agent_readonly::v3(&workspace))?;
let status = cage
    .spawn(&mut std::process::Command::new("make"), &Grants::new())?
    .wait()?;
```

📖 [Documentation](https://hupe1980.github.io/procage) ·
🔐 [Threat model](crates/procage/THREAT_MODEL.md) ·
📐 [Design records](specs/README.md) ·
📝 [Changelog](CHANGELOG.md) ·
🚨 [Report an escape](SECURITY.md)

> 🚧 **Pre-1.0.** The API may change between minor versions. Read the
> [threat model](crates/procage/THREAT_MODEL.md) for what procage contains
> and where it stops.

## ✨ Features

- 🧩 **One typed policy, lowered per OS.** Anything a host cannot enforce is
  a named capability gap, never a weaker rule. `Cage::fit` relaxes only what
  you name and says what would lift each relaxation.
- 🔒 **A hard-deny tier in every policy.** Secrets, git hooks, shell startup
  files, launch agents, your service manager and container engines are
  denied last and waivable only by name.
- 🧹 **Hygiene and lifetime.** Inherited descriptors are closed,
  secret-looking variables dropped, and every process a run started is
  killed when it ends, double-forked daemons included.
- 🧭 **Explain and diff.** `Cage::explain` names the rule that allows or
  denies reading, writing or executing a path and the narrowest change
  that would allow it; `explain::diff` shows what a policy change allows.
  The kernel checks every answer on every CI lane.
- 🧾 **Receipts.** Every finished run says how it was caged: policy digest,
  backend and tier, and everything accepted short of the policy.
- 🔎 **Violation reports.** A cage can say what the sandbox denied and which
  rule denied it: every denial on macOS, every refused system call on Linux.
- 🌐 **Egress through an allowlist.** With the `proxy` feature, a run
  reaches the hosts an allowlist names through a proxy of its own, and no
  other route (macOS, Linux T1). One canonical host parser, checked
  resolution, no allow-all.
- ⚡ **Async (tokio).** With the `tokio` feature, `Cage::spawn_async`
  returns an awaitable child, and violations arrive as a stream.
- 📦 **Frozen presets and base profiles** that let ordinary programs and
  developer tools start, and `Cage::exec` and `Cage::exec_session` for
  helpers that become the caged command.

## 🖥️ Platforms

| Platform | Mechanism | Needs |
|---|---|---|
| 🍎 macOS | Seatbelt, applied through libsandbox | A caller that is not itself sandboxed |
| 🐧 Linux T1 | Namespaces, mounts, Landlock, seccomp | Unprivileged user namespaces, Landlock ABI 1 (Linux 5.13) |
| 🐧 Linux T2 | Landlock, seccomp | Landlock ABI 1 (Linux 5.13), e.g. Docker's defaults |

procage picks the strongest tier the host allows and never runs a child
unsandboxed.

**Tested releases.** Supported means a green CI lane: every push runs the
kernel facts and all suites on each of these runners.

| Runner | Release | Arch | Tier | Measured |
|---|---|---|---|---|
| `macos-15` | macOS 15 (measuring) | arm64 | — | — |
| `macos-26` | macOS 26.6.2 (25G83) | arm64 | — | 2026-11-02 |
| `xcode-27` | macOS 27 (measuring) | arm64 | — | — |
| `ubuntu-24.04` | Ubuntu 24.04, Linux 7.0.0-1017-azure | x86_64 | T2 as shipped, T1 with the sysctl | 2026-11-02 |
| `ubuntu-24.04-arm` | Ubuntu 24.04 (measuring) | aarch64 | — | — |
| `ubuntu-26.04` | Ubuntu 26.04 (measuring) | x86_64 | — | — |

T1 needs `sysctl kernel.apparmor_restrict_unprivileged_userns=0`, the
setting Ubuntu documents; the tests run as an ordinary user. CI also boots
mainline kernels 5.15 to 7.3 (Landlock ABI 1 to 11). Untested: macOS 14
and earlier, Intel Macs.

**Known limits:** no pseudo-terminals, no Linux PID namespace, no loopback
networking on Linux and no proxy-only networking on tier T2, and Landlock's
file and network denials are not reported.

## ⏱️ Performance

Median overhead of a caged spawn over a plain one (`just bench`):

| Host | procage, cached cage | Comparison |
|---|---|---|
| Apple M4 Pro, macOS 26.6.2 | 1.0 ms | `sandbox-exec -p`: 10.9 ms |
| Linux 7.0 aarch64 (Docker) | T1 1.0 ms, T2 0.27 ms | `bwrap`: 1.4 ms |

On macOS a new policy costs 11.6 ms once, to compile its profile.
Details: [benchmarks](https://hupe1980.github.io/procage/docs/testing/#benchmarks).

## 🎯 Threat model

procage contains adaptive code running as your user inside the child, and
keeps it away from your secrets, files outside the granted paths, your
terminal and session, and persistence locations. An OS sandbox reduces this
risk but does not remove it: kernel and OS service bugs are out of scope, so
use a microVM where such an escape is unacceptable.

The [threat model](crates/procage/THREAT_MODEL.md) lists every known escape
class and its status. A class counts as handled only when caged canaries on
a real kernel show the refusal. Every change is specified,
threat-modelled and verified in the open: see the
[design records](specs/README.md).

## 🛠️ Development

```sh
just ci            # every local gate: fmt, lints, tests, docs, deny, MSRV (1.99), no_std, semver
just escape        # the macOS escape suite
just linux-t1      # the Linux tests in Docker, tier T1 (`just linux` for T2)
just kernel        # the Linux suites on mainline kernels, one per Landlock ABI step
just test-outside  # the kernel facts, from a terminal outside any sandbox
```

The kernel facts (`crates/procage-kernel-facts`) re-verify on the running
kernel the OS behaviour procage relies on. Facts that apply a sandbox fail
rather than skip inside another Seatbelt sandbox, such as an AI agent's.

## 📄 License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT) at your option.
