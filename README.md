# procage

Process sandboxing for Rust. procage runs a child process in a cage on macOS
(Seatbelt, applied through libsandbox rather than the deprecated
`/usr/bin/sandbox-exec`) and on Linux (Landlock, seccomp and namespaces),
without helper binaries.

It is built for programs that run commands on someone else's behalf (coding
agents, MCP servers, build orchestrators), where the code inside the child
runs with your user id: an LLM following injected instructions, or a
project's build script.

```rust
use procage::native::{Cage, Grants};
use procage::policy::{AbsPath, presets};

let workspace = AbsPath::new("/Users/me/project")?;
let cage = Cage::new(&presets::agent_readonly::v2(&workspace))?;
let status = cage
    .spawn(&mut std::process::Command::new("make"), &Grants::new())?
    .wait()?;
```

Documentation: <https://hupe1980.github.io/procage>

**Status: under development.** The published 0.0.1 only reserves the name.
The development version on `main` (0.0.2, unreleased) cages a child on macOS
and on Linux (tier T1: namespaces, Landlock and seccomp; tier T2: Landlock and
seccomp; Landlock ABI 1, Linux 5.13, or later). Do not rely on any release
before 0.1.0 to contain a process.

What it does today:

- one typed policy, lowered per OS; anything a host cannot enforce is a named
  capability gap, never a weaker rule (`Cage::fit` relaxes only what you
  name, and says what would lift each relaxation);
- every policy denies reading secrets and writing git hooks, shell startup
  files and launch agents;
- inherited descriptors are closed, secret-looking variables dropped, and
  every process a run started is killed when the run ends, double-forked
  daemons included;
- a cage can report what the sandbox denied and which kind of rule denied
  it (`CageOptions::with_violations`): every denial on macOS, every refused
  system call on Linux;
- four frozen presets, opt-in base profiles that let ordinary programs and
  developer tools start (V3 also keeps their harmless probes out of violation
  reports), and `Cage::exec` for helper programs that become the
  caged command.

Not yet: pseudo-terminals, a Linux PID namespace, loopback and proxy
networking on Linux, and reports of Landlock's file and network denials. Open escape variants: a
hard link made before the run (R-08), and on macOS the arguments and
environment of your other processes, which a caged child can read (R-25).

## Threat model

procage is meant to contain adaptive code running as your user inside the
child, such as an LLM following injected instructions or a malicious build
script. It is meant to keep that code away from your secrets, files outside
the granted paths, your terminal and session, and persistence locations. An
OS sandbox reduces this risk but does not remove it: bugs in the kernel and OS
services are out of scope, so use a microVM where such an escape is
unacceptable. The full [threat model](crates/procage/THREAT_MODEL.md) lists every known escape
class and its status in the current release. To report a suspected escape, see
the [security policy](SECURITY.md).

Every change is specified, threat-modelled and verified in the open: the
[design records](specs/README.md) hold each change's spec, measurements,
threat model and the verification of its security requirements.

## Development

`just ci` runs every local quality gate: formatting, lints, tests, docs,
dependency policy, the minimum Rust version (1.99), the `no_std` build of the
policy crate, semver checks, a check for internal planning paths, and a docs
build from the packaged crate. The tests include a gate that checks the
threat model's escape-class catalog: its format, stable ids, that every class
has a canary in the escape suite (`crates/procage/tests/escape_macos.rs`,
`crates/procage/tests/escape_linux.rs`) for each platform it applies to, and that no class is
marked handled without passing canaries as evidence. `just escape` runs the
macOS suite; `just linux` and `just linux-t1` run the Linux suite.

The workspace includes a kernel-facts suite (`crates/procage-kernel-facts`). It
re-verifies, on the running kernel, the macOS Seatbelt and Linux Landlock,
seccomp and namespace behaviour procage relies on. Each fact runs a real child
process. Facts that apply a sandbox **fail rather than skip** when the suite
itself runs inside a Seatbelt sandbox (for example an AI agent's), so run them
from a plain terminal: `just test-outside`. On Linux, `just kf-linux` and
`just kf-linux-t1` run the same suite in unprivileged containers, and
`just linux` and `just linux-t1` run the Linux backend's tests there (tier T2
under Docker's defaults, tier T1 with seccomp unconfined).

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT) at your option.
