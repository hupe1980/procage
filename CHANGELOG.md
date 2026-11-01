# Changelog

All notable changes to procage are listed here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Security

- With the network on, a caged child could reach the user's D-Bus bus or
  the systemd service manager on Linux (`systemd-run --user` runs outside
  the sandbox) and container engines' sockets on both systems (a container
  can mount your home directory) — escape class R-34. Every policy, frozen
  presets included, now denies them: the `service-handoff` class covers the
  Linux buses and service managers, and the new `container-engines` class
  the engines. The preset profiles gain exactly one deny rule each.
  **Migration**: builds that need a container engine waive
  `HardDenyClass::ContainerEngines`. On Linux tier T1, a host with such a
  socket needs the spawn-snapshot approximation accepted
  (`LowerOptions::accept_spawn_snapshot()` or by name); on tier T2 the cage
  is refused while one exists unless the class is waived (`Cage::fit` can do
  it by name). Evidence: the escape-suite canaries `r34_*` on macOS and on
  Linux tiers T1 and T2.

### Added

- `HardDenyClass::ContainerEngines` and `Construct::HdContainerEngines`;
  the socket lists in `procage_policy::presets` and
  `procage_policy::linux::SocketPaths`.
- `linux::CageOptions::with_runtime_dir`.
- Receipts: `Child::receipt` on both systems gives a `Receipt` for every
  finished run (policy digest, preset and base, backend and tier, OS build or
  kernel, approximations, relaxations, waivers, `enforced_as_written`,
  violation summary, exit); `Receipt::{to_json, from_json}` (version 1,
  unknown fields refused); `policy_digest`;
  `CageOptions::with_policy_in_receipt`. procage now depends on `serde`,
  `serde_json` and `sha2`.

### Changed

- `LinuxPlan` gains `service_sockets`; `linux::CageOptions` gains
  `runtime_dirs`. `Construct::SPAWN_SNAPSHOT` includes the two socket
  classes.

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
