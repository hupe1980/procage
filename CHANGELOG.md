# Changelog

All notable changes to procage are listed here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Security

- With the network on, a caged child could reach the user's D-Bus bus or
  systemd service manager (Linux) and container engines' sockets (both
  systems), which run code outside the sandbox (R-34). Every policy now
  denies them: `service-handoff` covers the Linux buses and service
  managers, the new `container-engines` class the engines; each preset
  profile gains one rule. **Migration**: builds that need a container engine
  waive `HardDenyClass::ContainerEngines`. On Linux T1 a host with such a
  socket needs `LowerOptions::accept_spawn_snapshot()`; on T2 the cage is
  refused unless the class is waived.
- A hard link made before the run to a protected, hidden or credential file
  now refuses the spawn (R-08): `SpawnError::HardLinks`. **Migration**:
  benign second names: `LinkAudit::Report` or `LinkAudit::Off`.
- macOS: a caged child could read any same-user process's arguments and
  environment (`KERN_PROCARGS2`, R-25). The `process-access` class now
  refuses it in every policy; the run's own processes stay readable. Each
  preset profile gains three rules. **Migration**: a process monitor waives
  `HardDenyClass::ProcessAccess`.

### Added

- Explain and diff (`procage_policy::explain`): `Cage::explain` and
  `Explainer` say whether a path may be read, written or executed, by
  which rule, with any spawn-time caveat and the narrowest change that
  would allow a denial; `explain::diff` lists what one policy allows or
  denies that another does not, per target. Every answer is checked
  against the kernel on every CI lane by the oracle suite
  (`tests/oracle.rs`). `SpawnError::Explain`.
- Receipts: `Child::receipt` describes every finished run (policy digest,
  preset and base, backend and tier, OS build or kernel, approximations,
  relaxations, waivers, violation summary, exit); `Receipt::{to_json,
  from_json}` (version 1); `policy_digest`;
  `CageOptions::with_policy_in_receipt`.
- Audits (`procage::audit`): the link check before every spawn
  (`CageOptions::with_link_audit`), the opt-in handoff audit
  (`CageOptions::with_handoff_audit`, `Child::audit`); macOS
  `CageOptions::with_walk_limit`.
- `HardDenyClass::ContainerEngines`, `Construct::HdContainerEngines`; the
  socket lists in `procage_policy::presets` and
  `procage_policy::linux::SocketPaths`; `linux::CageOptions::with_runtime_dir`.
- `Construct::ProcOtherProcesses`,
  `procage_policy::linux::reaches_other_processes`; Seatbelt filters
  `SysctlName` and `SysctlNamePrefix`.
- A spawn benchmark (`just bench`).

### Changed

- Linux: a rule or grant that reaches other processes under `/proc` (`/`,
  `/proc`, or a symbolic link to them) is an approximation accepted by
  name, `proc-other-processes`: without a PID namespace, other processes'
  arguments become readable (not their environment). **Migration**: a
  policy that reads `/` adds
  `LowerOptions::allow(Construct::ProcOtherProcesses)`.
- `SpawnError` is `#[non_exhaustive]` on both systems.
- `LinuxPlan` gains `service_sockets`; `Construct::SPAWN_SNAPSHOT` includes
  the two socket classes.
- procage depends on `serde`, `serde_json` and `sha2`.

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
