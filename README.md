# procage

Process sandboxing for Rust, in development. procage is designed to run a
child process in a cage on macOS (Seatbelt, applied through libsandbox rather
than the deprecated `/usr/bin/sandbox-exec`) and on Linux (Landlock, seccomp
and namespaces), without helper binaries.

**Status:** the published 0.0.1 only reserves the name. The development
version on `main` (0.0.2, unreleased) spawns caged children on macOS and on
Linux (tiers T1 and T2), with inherited descriptors closed, every process a
run started killed when the run ends (double-forked daemons included; on
Linux, `setsid` and `setpgid` fail in the cage unless the policy opts out), an
opt-in base profile that lets ordinary programs start, and an entry point for
helper programs that become the caged command (`Cage::exec`). Every policy
denies reading secrets and writing git hooks, shell startup files and launch
agents; on Linux these hold exactly where no rule reaches them, by masks at
spawn on tier T1, and otherwise are a capability gap. Four frozen presets
cover common shapes. An escape suite runs a caged canary for every known
escape class; the threat model shows which classes it proves handled and which
variants are still open: a pre-existing hard link is not reported, and on
macOS a caged child can read the arguments and environment of your other
processes. It does not yet provide pseudo-terminals, a PID namespace, or
loopback and proxy networks on Linux. Do not rely on any release before 0.1.0
to contain a process.

## Threat model

procage is meant to contain adaptive code running as your user inside the
child, such as an LLM following injected instructions or a malicious build
script. It is meant to keep that code away from your secrets, files outside
the granted paths, your terminal and session, and persistence locations. An
OS sandbox reduces this risk but does not remove it: bugs in the kernel and OS
services are out of scope, so use a microVM where such an escape is
unacceptable. The full [threat model](THREAT_MODEL.md) lists every known escape
class and its status in the current release. To report a suspected escape, see
the [security policy](SECURITY.md).

## Development

`just ci` runs every local quality gate: formatting, lints, tests, docs,
dependency policy, the minimum Rust version (1.99), the `no_std` build of the
policy crate, semver checks, a check for internal planning paths, and a docs
build from the packaged crate. The tests include a gate that checks the
threat model's escape-class catalog: its format, stable ids, that every class
has a canary in the escape suite (`tests/escape_macos.rs`,
`tests/escape_linux.rs`) for each platform it applies to, and that no class is
marked handled without passing canaries as evidence. `just escape` runs the
macOS suite; `just linux` and `just linux-t1` run the Linux suite.

The workspace includes a kernel-facts suite (`tests/kernel_facts`). It
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
