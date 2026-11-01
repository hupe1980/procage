# Implementation Plan: No service handoff over Unix sockets

**Branch**: `041-service-sockets` (local planning; commits on `main`) | **Date**: 2026-11-01 | **Spec**: [spec.md](spec.md)

## Summary

- **Policy crate**:
  - `HardDenyClass::ContainerEngines` (`container-engines`), appended to
    `ALL` (emitted last, so existing profile lines keep their order);
    `Construct::HdContainerEngines`; both socket constructs join
    `Construct::SPAWN_SNAPSHOT`.
  - `presets`: frozen socket lists — `SERVICE_SOCKETS_LINUX`,
    `SERVICE_SOCKET_DIRS_LINUX`, `SERVICE_RUNTIME_LINUX`,
    `SERVICE_RUNTIME_DIRS_LINUX`, `SERVICE_ABSTRACT_LINUX`,
    `ENGINE_SOCKETS_LINUX`, `ENGINE_SOCKET_DIRS_LINUX`,
    `ENGINE_RUNTIME_LINUX`, `ENGINE_RUNTIME_DIRS_LINUX`, `ENGINE_HOME`
    (macOS, relative to every user home), `ENGINE_SYSTEM` (macOS); `patterns()`
    returns the macOS globs of `ContainerEngines`; `linux_socket_paths(class)`
    returns the Linux lists.
  - macOS lowering: `ContainerEngines` → `(deny network-outbound <folded
    pattern>…)` in the hard-deny block (path filters on network operations
    match Unix-socket addresses only, by the resolved socket — measured, see
    research.md). `ServiceHandoff` on macOS is unchanged (Mach).
  - Linux lowering: both classes are `Exact` at lowering; when in force and
    the policy can reach Unix sockets (`Network::All`, or a non-empty
    `ipc.unix_sockets`), the plan carries them in a new
    `LinuxPlan::service_sockets: Vec<SocketPaths>` for the backend.
- **procage, Linux** (`linux/services.rs`, new):
  - `runtime_dirs(extra)`: every readable `/run/user/*`, the caller's
    `XDG_RUNTIME_DIR`, `CageOptions::with_runtime_dir` additions;
    canonicalised, deduplicated.
  - `find(sockets, runtime_dirs, abstract_ok)`: existing sockets (file type
    socket, resolved), existing class directories that hold a socket, and
    abstract names in `/proc/net/unix` with a listed prefix (skipped when the
    child has its own network namespace).
  - `Cage::with_options`: after `home_gaps`, `service_gaps`: T2 + a found
    socket or directory → `Unsupported` gap per path (subject = path);
    T1 + found → `Approximation` (allowed by `accept_spawn_snapshot` or by
    name, recorded as a degradation); abstract found → `ABSTRACT_UNIX_SOCKET`
    scope added to the plan when ABI ≥ 6, else `Unsupported` gap (subject
    `@name`).
  - `prepare` (each spawn): T1 adds `Cover::Hide` for every found socket and
    directory (optional covers: a vanished one is skipped, as in 038); T2
    re-runs `find` and refuses the spawn with the same gaps if a socket
    appeared after the cage was made; an abstract bus found later without a
    scope refuses the spawn.
  - `CageOptions::with_runtime_dir(path)` (Linux), like `with_home`.
- **Tests**:
  - policy: lowering of the new class (macOS rule, Linux `service_sockets`
    only when reachable), the preset fixtures regenerated (only new denies),
    lowering table rows, presets data test.
  - `escape_macos::r34_*`: fake engine socket under `~/.lima/<run>/sock/`,
    `Network::All`, connect denied (also via a symlink in the workspace, and
    a hard link attempt), waived control connects, reporting names
    `container-engines`.
  - `escape_linux::r34_*`: scratch runtime directory (`with_runtime_dir`)
    with `bus`, `systemd/private`, `docker.sock`; T1 connects fail
    (`accept_spawn_snapshot`), T2 `Cage::new` gap naming the path; waived
    controls; a project socket in the workspace stays reachable; abstract
    `@/tmp/dbus-procage-<pid>` refused on ABI ≥ 6; a socket bound after the
    cage on T2 refuses the spawn; T1 directory cover holds for a socket
    bound after spawn.
  - Existing tests that use `Network::All` as a control waive the two
    classes where the host may have a bus (CI runners).
- **Docs**: THREAT_MODEL row R-34 (+ `PUBLISHED`), crate docs (hard-deny
  classes, Linux limits), site pages (hard denies, Linux), CHANGELOG
  (Security + Added), README platform notes.
- **Version**: workspace to 0.2.0 (`[Unreleased]` in the changelog); the
  policy crate's plan types gain fields (a minor-version change before 1.0).

## Technical Context

Rust 1.99.1, edition 2024; `libc` 0.2. Lanes: macOS 26.6.2 (local), Docker
Linux 7.0.14 aarch64 T1 and T2 (local), CI as configured.

## Constitution Check

| Principle | Check | Status |
|---|---|---|
| I. Fail closed | T2 cannot deny a socket inside an allowed namespace → typed gap per socket; T1 snapshot → approximation needing the caller's name for it; a socket appearing later on T2 refuses the spawn; abstract without ABI 6 → gap | PASS |
| II. Types | One new `HardDenyClass` (non-exhaustive enum), new `Construct`; socket lists as typed data; waivable by name only | PASS |
| III. Kernel oracle | R-34 canaries on macOS, T1, T2, each with a waived positive control; macOS rule measured before design | PASS |
| IV. fork/exec, unsafe | No new child step: covers reuse the existing mount sequence; discovery runs in the parent; no new unsafe | PASS |
| V. Hygiene | Strengthens: service sockets out of reach under every network setting | PASS |
| VI. Private interfaces | None new | PASS |
| VII. Library | No global state; presets tighten (never loosen) with a Security entry; migration note: waive `container-engines` for builds that need an engine | PASS |

## Project Structure

```text
crates/procage-policy/src/{policy.rs, presets.rs, linux.rs, lower/mod.rs, lower/macos.rs, lower/linux.rs, lowering.md}
crates/procage-policy/tests/{presets.rs, lowering_table.rs, fixtures/presets/*.sb}
crates/procage/src/linux/{mod.rs, services.rs (new), spawn.rs}
crates/procage/src/lib.rs
crates/procage/tests/{escape_macos.rs, escape_linux.rs, spawn_linux.rs, threat_model.rs}
crates/procage/THREAT_MODEL.md, CHANGELOG.md, README.md, site/content/docs/*.md
Cargo.toml, Cargo.lock (version 0.2.0)
```

## Complexity Tracking

| Item | Why | Simpler alternative rejected |
|---|---|---|
| Spawn-time discovery on Linux | Landlock below ABI 9 cannot deny one socket; whether a gap exists depends on the host | Always a gap with `Network::All` on Linux: would break every network-on policy on hosts without any service socket (containers) |
| Two classes | Builds need engines; Launch Services must stay denied | One class: a build waiving it would re-open Launch Services on macOS |
