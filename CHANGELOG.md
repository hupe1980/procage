# Changelog

All notable changes to procage are listed here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
[Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.1.0] - 2026-11-01

### Added

- macOS backend: Seatbelt applied in the forked child through libsandbox,
  without `sandbox-exec` or helper binaries.
- Linux backend: tier T1 (namespaces, mounts, Landlock, seccomp) and tier T2
  (Landlock, seccomp), from Landlock ABI 1 (Linux 5.13).
- `procage-policy`: a portable, deny-by-default policy, lowered per target to
  an exact plan or a complete list of capability gaps; `no_std`, optional
  versioned data format (`serde`).
- A hard-deny tier in every policy, waivable only by class name.
- Frozen presets (`minimal`, `agent_readonly`, `agent_workspace`, `build`)
  and base profiles V1 to V3.
- `Cage::fit`: named relaxations, each with what would lift it.
- `Cage::exec`: a helper becomes the caged command.
- Violation reports (`CageOptions::with_violations`): every denial on macOS,
  every refused system call on Linux.
- Process hygiene: inherited descriptors closed, secret-looking variables
  dropped, `env_clear` honoured, private `TMPDIR`, every process of a run
  killed when it ends.
- `procage::native`: one import path for both systems.
- The threat model with its escape-class catalog, checked by a test gate.

## [0.0.1] - 2026-10-27

Name reservation; no code.

[Unreleased]: https://github.com/hupe1980/procage/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/hupe1980/procage/releases/tag/v0.1.0
[0.0.1]: https://crates.io/crates/procage/0.0.1
