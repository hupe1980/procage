# Changelog

All notable changes to procage are listed here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
[Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.8.0] - 2026-11-12

### Security

- `Exec::Never` let the child execute the base's programs (a caged shell
  under `Base::V3` ran `/bin/echo`), and without a base nothing started
  (macOS, Linux; R-38). It now runs the spawned program and nothing after
  it: the base executes nothing, and on Linux a seccomp supervisor passes
  only the exec that starts the program (`ld.so` and the program itself
  included). Without a supervisor (`Cage::exec`, an enclosing seccomp
  listener) the cage is the gap `exec-never`. On macOS it needs a base,
  and the program may execute itself again. Scripts are refused as the
  program (`SpawnError::Script`). **Migration**: programs that start
  copies of themselves use `Exec::Program`; others use `Exec::Granted`
  with `Exec` rules.

### Added

- `Exec::Program` (JSON `"program"`): the program, as often as it likes.
  Exact on macOS; on Linux the gap `exec-program` (the ELF interpreter
  stays executable).
- Python `Cage(..., allow=[...])`, Node.js `new Cage(policy, { allow })`:
  accept approximations by construct name.
- `DeniedBy::Exec`.

### Changed

- New variants: `Exec::Program`, `linux::Action::Supervise`,
  `linux::RuleTarget::Program`, `linux::Syscall::{Execve, Execveat}`,
  `DenyReason::Exec`; `Hygiene` carries the exec setting.

### Fixed

- macOS: finding a run's processes logged a denial for every sandboxed
  process it checked, tagged with that process's run: false entries in
  other runs' violation records, and a log flood (on macOS 27 most of the
  sandbox log during parallel runs).
- macOS: the violation helper could inherit a pipe another thread was
  creating and hold it open for the life of the process; reading that
  child's output then never ended.
- macOS: a dropped fence report (macOS 27) left a record incomplete; a new
  fence follows every 100 ms.

## [0.7.2] - 2026-11-11

### Fixed

- A spawned child starts with every ignored signal reset to its default
  action (macOS, Linux). A caller that ignored `SIGCHLD` handed that to the
  child, whose `wait` for its own children failed with `ECHILD`; bubblewrap
  0.11.1 fixed the same. `Cage::exec` keeps the caller's dispositions, as
  `execve` does. The job-control signals (`SIGTSTP`, `SIGTTIN`, `SIGTTOU`)
  stay as the caller set them: ignoring them gives a `Tty::Inherit` child
  `EIO` rather than a stop. A failure is reported as `Step::Session`.
- Ending a run whose child was already reaped elsewhere (the caller ignores
  `SIGCHLD` or waits for any child) returned early and left its session and
  process group running (macOS, Linux; R-23). The run now ends them.
- Ending a run after its child was reaped no longer signals a session or
  process group that reuses the child's pid: once no member of the run's
  session or group is left, a live process with that pid is another's and
  is left alone (macOS reuses pids below 100,000 soon).

## [0.7.1] - 2026-11-03

### Fixed

- Release: the npm package is published (0.7.0's upload read the tarball
  path as a GitHub repository and failed; crates.io and PyPI have 0.7.0).
  No code change.

## [0.7.0] - 2026-11-03

### Added

- Node.js bindings: the `procage` package on npm (macOS arm64, Linux x64
  and arm64 with glibc 2.28+, Node.js 22.12+, TypeScript declarations).
  Presets (which run in their workspace) and the versioned JSON format,
  `Cage` with violations, named relaxations and the spawn snapshot,
  `run()` with `shell`, `input`, `timeout`, `AbortSignal`, `check` and
  `encoding`, `Run` with `wait`, `output`, `kill`, violations, the receipt
  and `Symbol.asyncDispose`, typed errors whose gaps name the accepting
  option, and runs that end on abort, timeout, disposal, collection or
  process exit. Built from `bindings/nodejs` (crate `procage-node`, not
  published to crates.io); published by the release workflow with npm
  Trusted Publishing and provenance. A shell tool example.
- `just versions`: the npm package's version is the crates'.

### Changed

- Python: a preset's workspace may end with a slash.

## [0.6.1] - 2026-11-03

### Fixed

- Python wheels: the 0.6.0 wheels carried a stray bytecode file
  (`procage/__pycache__/__init__.cpython-313.pyc`) from a build checkout.
  Python never used it (it checks bytecode against the source and found it
  stale), but a wheel now holds exactly the package sources, its stub and
  marker and one native module, and the build fails otherwise.

### Changed

- Release: the GitHub release is created last, once crates.io and PyPI
  both have the version.

## [0.6.0] - 2026-11-03

### Added

- Python bindings: the `procage` package on PyPI (wheels for macOS arm64
  and Linux x86_64 and aarch64, manylinux_2_28, CPython 3.11+). Presets and
  the versioned JSON format, `Cage` with violations and named relaxations,
  `spawn` with pipes, explicit environment and grants, `Run` with `wait`,
  `communicate`, `kill`, violations and the receipt, `procage.run` in the
  manner of `subprocess.run` (`text`, `check`, `shell`), asyncio twins
  (`run_async`, `communicate_async`, `wait_async`) whose cancellation ends
  the run, typed exceptions whose gaps name the accepting option, and runs that end when their object is collected or the
  interpreter exits. Built from `bindings/python` (crate `procage-py`, not
  published to crates.io); published by the release workflow with PyPI Trusted
  Publishing. A framework-neutral shell tool example.

## [0.5.0] - 2026-11-03

### Added

- `Tty::NewPty`: a new pseudo-terminal per run, on macOS and Linux (both
  tiers). The other end is the child's standard streams and controlling
  terminal; `Child::take_pty()` and `AsyncChild::take_pty()` return the
  controller side as `procage::Pty` (read, write, `set_size`, `device`),
  starting at 80 by 24. The child may use exactly its own device and
  `/dev/tty` (on macOS also the listing of `/dev`), under any base;
  `TIOCSTI` stays denied (R-22). Tested on every lane with an interactive
  shell, `python3 -i` and a full-screen program.
- `procage::suggest(&Policy, &Violation)`: the narrowest change that
  would allow a reported denial on the next spawn, as a
  `procage_policy::Suggestion` (a literal grant, a Unix socket, leaving out
  the covering protect or hide rule, a class waiver or wider signals) with
  `weakens()` and `apply()`, which returns a new policy. Never for the
  `secrets` class, the raw layer, `Lifetime::Run`, the older-kernel guard
  or the proxy.
- `Construct::TtyNewPty` (`tty-new-pty`), `procage_policy::PTY_EXTENSION_CLASS`
  and `procage_policy::linux::TERMINAL_ACCESS`.

### Fixed

- macOS: ending a forking run could kill a process another run had just
  forked, before that process applied its sandbox: the marker search
  checked the run's marker before the probe, and a process sandboxed
  between the two checks matched. The probe is checked first now. Found by
  the concurrent new-terminal test (about one run in three before, none in
  20 after).

### Changed

- `Tty::NewPty` is no longer refused by `Cage::new`; `Cage::exec` and
  `Cage::exec_session` refuse it with `Unsupported::Setting`.

## [0.4.1] - 2026-11-03

### Security

- Linux tier T1: a mount could be moved by a symbolic link or a renamed
  directory planted in a writable tree between the spawn's plan and the
  child's mounts (R-33), so a protected path stayed writable, a hidden one
  readable, and another path was covered. The canary showed it for every
  mount kind before this release. The objects of protect, hide and pin are
  now fixed when the cage is made, and of covers when the spawn plans
  them; the child opens each path without following links, checks its
  device and inode and mounts on that descriptor. A host whose kernel lacks
  `openat2`, `open_tree`, `fsmount`, `mount_setattr` or `move_mount` has no
  tier T1.
- macOS: Seatbelt matches paths case-insensitively on every volume, so an
  allow on a case-sensitive volume also allowed the path's case variants,
  other files there (R-37). An allow rule, an allowed Unix socket, a
  Seatbelt-layer allow or a grant on such a volume is now refused.

### Added

- `linux::SpawnError::MountMoved { path, link }`: a planned mount path that
  now passes a link or names another object.
- `macos::SpawnError::CaseSensitive { path }`.

### Changed

- Linux tier T1: a protected or hidden object replaced after the cage was
  made (for example by an atomic save) refuses later spawns with
  `MountMoved`; make a new cage.
- Tested releases: a CI lane each for macOS 26 and 27 and for Ubuntu 24.04
  (x86_64, arm64) and 26.04, both tiers; the README lists them with their
  builds. macOS 15 is untested.

## [0.4.0] - 2026-11-02

### Added

- `Network::Ip`: any IP address, Unix sockets only at `ipc.unix_sockets`
  (macOS keeps the system resolver's socket). On Linux `socket()` is
  allowed for IPv4 and IPv6 only, so the D-Bus and container-engine
  sockets are out of reach on tier T2 too. Construct `net-ip`.
- `Relax::no_unix_sockets()` answers the `hd-service-handoff` and
  `hd-container-engines` gaps of `Network::All` (tier T2): the network
  becomes `Network::Ip`. `Relaxation::answers(construct)`.

### Changed

- `Network` is `#[non_exhaustive]` (breaking).

## [0.3.2] - 2026-11-02

### Added

- `Cage::exec_session` and `exec_session_with_fds`: the command leads its
  own session; on Linux its descendants may start process groups (test
  runners) but not sessions. `procage::{linux,macos}::end_session(pid)`
  ends that run; macOS cannot refuse `setsid`.
- `SpawnError::GroupLeader`: `exec_session` in a process group leader that
  leads no session.

### Changed

- Every crate takes the workspace version: `procage-proxy` 0.3.2 (no code
  change since 0.3.0).

## [0.3.1] - 2026-11-02

### Fixed

- Linux, `Lifetime::Run`: programs that start process groups
  (cargo-nextest) run; only `setsid` is refused, and ending a run kills the
  child's session. `setpgid` stays refused with `Tty::Inherit` and for
  `Cage::exec`.
- Linux: ending a run kills the child before its descendants, so a shell
  child reports the caller's kill, not its own exit (137).

## [0.3.0] - 2026-11-02

### Added

- Feature `tokio`: `Cage::spawn_async` and `spawn_async_with_fds` return an
  `AsyncChild` (dereferences to `tokio::process::Child`, ends the run on drop
  or `kill_all().await`); `AsyncChild::violation_stream` (`ViolationStream`,
  a `futures_core::Stream`); `SpawnError::NoRuntime`. No async dependency
  without the feature.
- Feature `proxy` and crate `procage-proxy`: with `Network::Proxy` and
  `CageOptions::with_proxy`, each run gets a proxy of its own (HTTP
  `CONNECT`, plain HTTP, SOCKS5) that connects only to the hosts an
  `Allowlist` names, and no other route, on macOS and Linux T1 (a gap on
  T2). Refusals are violations (`DeniedBy::Allowlist`). Escape classes R-35
  (parser differential) and R-36 (direct egress around the proxy).
- Landlock ABI 9 to 11 (`BACKEND_MAX_ABI` 11): from ABI 9 `ipc.unix_sockets`
  is exact on both tiers and the socket classes need no cover while the
  network is off; from ABI 10 a UDP socket the caller hands over cannot send
  with the network off.
- `CageOptions::with_link_exemption(path)`: protected files under a store
  that is never rewritten in place (a local clone's `.git/objects`) are not
  examined by the link check; hidden files still are. `Audit::links_exempt`.
- Kernel matrix: CI and `just kernel` boot mainline kernels 5.15, 6.6, 6.8,
  6.12, 7.0, 7.1, 7.2 and 7.3 with virtme-ng and run the kernel facts and
  every Linux suite in them.

### Fixed

- Linux: files could not move or link between directories (`EXDEV`), so
  `cargo build`, package managers and atomic saves failed. `Write` includes
  Landlock's `REFER` right from ABI 2; protected and hidden targets stay out
  of reach. On ABI 1 such moves still fail.
- Linux: `spawn_with_fds` closed handed-over descriptors that had
  close-on-exec set; they stay open, as on macOS.
- Linux T1: a socket removed by the host after its cover was mounted no
  longer fails the spawn.

### Changed

- The receiver from `Child::violation_receiver` ends once the run's record
  is complete or the run ended.

### Documentation

- Caged git: set `gc.autoDetach=false`, since `setsid` fails under
  `Lifetime::Run`.

## [0.2.0] - 2026-11-02

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
  `Explainer` name the rule that allows or denies reading, writing or
  executing a path, and the narrowest change that would allow a denial;
  `explain::diff` lists what one policy allows that another does not.
  `SpawnError::Explain`. The oracle suite checks every answer against the
  kernel on every CI lane.
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

[Unreleased]: https://github.com/hupe1980/procage/compare/v0.8.0...HEAD
[0.8.0]: https://github.com/hupe1980/procage/compare/v0.7.2...v0.8.0
[0.7.2]: https://github.com/hupe1980/procage/compare/v0.7.1...v0.7.2
[0.7.1]: https://github.com/hupe1980/procage/compare/v0.7.0...v0.7.1
[0.7.0]: https://github.com/hupe1980/procage/compare/v0.6.1...v0.7.0
[0.6.1]: https://github.com/hupe1980/procage/compare/v0.6.0...v0.6.1
[0.6.0]: https://github.com/hupe1980/procage/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/hupe1980/procage/compare/v0.4.1...v0.5.0
[0.4.1]: https://github.com/hupe1980/procage/compare/v0.4.0...v0.4.1
[0.4.0]: https://github.com/hupe1980/procage/compare/v0.3.2...v0.4.0
[0.3.2]: https://github.com/hupe1980/procage/compare/v0.3.1...v0.3.2
[0.3.1]: https://github.com/hupe1980/procage/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/hupe1980/procage/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/hupe1980/procage/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/hupe1980/procage/releases/tag/v0.1.0
[0.0.1]: https://crates.io/crates/procage/0.0.1
