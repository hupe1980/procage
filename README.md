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
- 🔎 **Violation reports.** A cage can say what the sandbox denied and which
  rule denied it: every denial on macOS, every refused system call on Linux.
- 📦 **Frozen presets and base profiles** that let ordinary programs and
  developer tools start, and `Cage::exec` for helpers that become the caged
  command.

## 🖥️ Platforms

| Platform | Mechanism | Needs |
|---|---|---|
| 🍎 macOS | Seatbelt, applied through libsandbox | A caller that is not itself sandboxed |
| 🐧 Linux T1 | Namespaces, mounts, Landlock, seccomp | Unprivileged user namespaces, Landlock ABI 1 (Linux 5.13) |
| 🐧 Linux T2 | Landlock, seccomp | Landlock ABI 1 (Linux 5.13), e.g. Docker's defaults |

procage picks the strongest tier the host allows and never runs a child
unsandboxed.

**Known limits:** no pseudo-terminals, no Linux PID namespace, no loopback
or proxy networking on Linux, and Landlock's file and network denials are
not reported. Open escape variants: a hard link made before the run (R-08),
and on macOS the arguments and environment of your other processes, which a
caged child can read (R-25).

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
just test-outside  # the kernel facts, from a terminal outside any sandbox
```

The kernel facts (`crates/procage-kernel-facts`) re-verify on the running
kernel the OS behaviour procage relies on. Facts that apply a sandbox fail
rather than skip inside another Seatbelt sandbox, such as an AI agent's.

## 📄 License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT) at your option.
