# procage

Process sandboxing for Rust, in development. procage is designed to run a
child process in a cage on macOS (Seatbelt, applied through libsandbox rather
than the deprecated `/usr/bin/sandbox-exec`) and on Linux (Landlock, seccomp
and namespaces), without helper binaries.

**Status:** version 0.0.1 only reserves the name. It contains no sandboxing
API and enforces nothing.

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
threat model's escape-class catalog: its format, stable ids, and that no class
is marked handled without a test as evidence.

The workspace includes a kernel-facts suite (`tests/kernel_facts`). It
re-verifies, on the running kernel, the macOS Seatbelt and Linux Landlock,
seccomp and namespace behaviour procage relies on. Each fact runs a real child
process. Facts that apply a sandbox **fail rather than skip** when the suite
itself runs inside a Seatbelt sandbox (for example an AI agent's), so run them
from a plain terminal: `just test-outside`. On Linux, `just kf-linux` and
`just kf-linux-t1` run the same suite in unprivileged containers.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT) at your option.
