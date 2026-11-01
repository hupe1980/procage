# Research: Lifetime

Host: macOS 26.6.2 arm64 (Darwin 25.6.0); probes in the session scratchpad
(C against libsandbox, a Rust crate against procage at `99c653d`).

## R1 — Identifying a run's processes on macOS

- **Decision**: per-run marker in the profile, checked from the parent with
  `sandbox_check(pid, "mach-lookup", 2 /* global name */, name)`.
- **Measured**:
  - A nonexistent *path* reads as denied for every process, the unsandboxed
    caller included (`sandbox_check` returned 1 for self). Path markers would
    need an existing file per run, so a path filter is rejected.
  - A *global name* needs no registered service. With
    `(deny mach-lookup (global-name-prefix P))` then
    `(allow mach-lookup (global-name P.slot))` last in the profile, the
    run's processes allow `P.slot` and deny `P.probe`; the unsandboxed
    caller allows both; an `(allow default)` sandbox allows both; a
    deny-default sandbox denies `P.slot` unless it names it exactly.
  - A perl process that forked twice, called `setsid` and was reparented to
    `launchd` (ppid 1, own pgid) was found. Scan of 716 processes, three
    checks each: 1.92 ms.
- **Alternatives**: parent links (`proc_listchildpids`, today) lose
  orphans; `p_puniqueid` is rewritten on reparenting; the responsible pid is
  inherited from the caller, not set per run; a sandbox extension per run
  would keep the cache but the child can release its own extension and
  vanish from the scan (rejected, threat.marker-evasion).

## R2 — Linux: lock or PID namespace

- **Decision**: seccomp `EPERM` for `setsid` and `setpgid` under
  `Lifetime::Run` when fork is allowed.
- **Rationale**: a process changes its process group only through these two
  calls (fork inherits the group; `clone(CLONE_PARENT)` too). The filter is
  installed after procage's own `setsid`/`setpgid(0, 0)` step
  (`src/linux/sys.rs`: session step precedes `seccomp`). A group id is not
  reused while a member lives, so `killpg(child_pid)` reaches every
  descendant after the child was reaped. Works on T1 and T2; no init process
  needed. glibc `setpgrp()` is `setpgid(0, 0)`; x86_64 and aarch64 have no
  separate `setpgrp` syscall, and foreign-architecture calls are already
  killed by the filter.
- **Compatibility**: programs that daemonize (`setsid(1)`, `daemon(3)`,
  Python `start_new_session`) fail with `EPERM`; job-control shells cannot
  create job groups. `timeout(1)` and libuv ignore the error. The opt-out is
  `Lifetime::Tree`.
- **Alternatives**: PID namespace (needs an init in the cage and user
  namespaces: no T2); `PR_SET_CHILD_SUBREAPER` on the child (covers only a
  living child, and the child can clear it); cgroups (not delegated in
  common setups).

## R3 — Parameters instead of per-run profile text

- **Decision**: the lowering emits the marker block with two SBPL parameters,
  `procage-run-prefix` and `procage-run-marker`; the backend binds them.
- **Measured**: `(global-name-prefix (param …))` and
  `(global-name (param …))` compile and behave as literals (marker 0, probe 1,
  other slot 1, unrelated service 0).
- **Rationale**: the profile text stays identical per policy; the existing
  cache key (profile, params) separates slots; `procage-policy` stays free of
  randomness.

## R4 — Compile cost and the slot pool

- **Measured**: `Cage::new` with a new profile: median 6.7–7.1 ms (Base V1 or
  none); a cached spawn costs about 2 ms (012).
- **Decision**: a process-wide prefix
  `org.procage.run.<caller pid hex>.<64-bit random hex>` (random from std's
  `RandomState`, no `unsafe`) and a pool of slot numbers. A spawn takes the
  lowest free slot; sequential runs reuse slot 0 and hit the cache.
  `Cage::new` compiles slot 0 eagerly (validation and warm cache); other
  slots compile at spawn, before fork.
- **Release rule**: a slot returns to the pool only after a `kill_all` round
  found no live process with the marker; `detach` and a failed final kill
  retire it for the life of the process.
- **Constitution**: VII's closed list of global state gains the slot pool
  (amendment 2.1.0).

## R5 — Killing in rounds

- **Decision**: round = scan + SIGKILL each match; stop when a scan finds
  none; at most 64 rounds with a 1 ms pause after a round that killed;
  survivors → `io::Error` naming the pids, slot kept.
- **Filters**: `proc_pidinfo(PROC_PIDT_SHORTBSDINFO)` per pid: skip other
  uids (`pbsi_uid`) and zombies (`pbsi_status == SZOMB`), then two
  `sandbox_check` calls (marker 0, probe 1).
- **Race**: between a check and `kill` a process may exit and its pid be
  reused; macOS has no process handle to close the window. Pids wrap at
  99,999 and are assigned sequentially, so reuse within microseconds needs
  pid exhaustion. Documented.

## R6 — Probe for the private check

- **Decision**: before the first marker spawn, the backend checks the
  caller itself: an unsandboxed caller must read the marker as allowed (0)
  for both names; a fresh run's child must match. The second half is the
  escape-suite canary and the spawn test; at runtime, a `sandbox_check`
  that returns an error code (−1) for a live same-uid process makes the
  scan fail (`kill_all` error), never silently skip.
