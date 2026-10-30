Lowering: from a [`Policy`](crate::Policy) to a plan for one target.

[`lower()`] turns a policy into a [`SeatbeltPlan`] for macOS or a
[`LinuxPlan`](crate::linux::LinuxPlan) for Linux tier T1 or T2. Each
construct of the policy is expressed exactly, approximated, or not at all,
as the table below states. The result is either a complete plan or the
complete list of [`CapabilityGap`]s:

- **exact**: the plan expresses the construct as written.
- **approximated**: the plan can only come close. Lowering returns a gap
  unless the caller names the construct in
  [`LowerOptions::allow_degrade`]. When allowed, the plan lists it in its
  degradations.
- **unsupported**: the target cannot express the construct. It is always a
  gap; no option turns it into a weaker rule.
- **n/a**: the construct has no meaning on the target and adds nothing to the
  plan.

A cell of the form `exact (ABI ≥ 9) / unsupported` depends on the Landlock
ABI the kernel reports. Tier T2 needs Landlock ABI 4 or later, and tier T1
needs ABI 1 or later; a lower ABI is refused, and lowering never substitutes
another tier.

A plan is data for procage's spawn backends. This crate applies nothing, and
a plan says nothing about enforcement on its own: what a running kernel
enforces is established by procage's tests that cage a real child. Seatbelt
forms marked as compiling were compiled by libsandbox on macOS 26.6.2
(25G83) on 2026-10-30. Compiling only shows that a profile is well-formed.

A Seatbelt profile is written in fixed blocks:

1. `(deny default)`;
2. every allow (file rules, grants, network, process, IPC, raw allows);
3. every deny inside an allow (protect, hide, raw denies);
4. the hard-deny tier, last.

Within a block, rules are sorted, so the order of the policy's rules never
changes the profile.

## Lowering table

| Construct | macOS | Linux T1 | Linux T2 | Note |
|---|---|---|---|---|
| `fs-read-subpath` | exact | exact | exact | |
| `fs-write-subpath` | exact | exact | exact | Write includes read. Landlock's cross-directory rename right (REFER) is never granted. |
| `fs-exec-subpath` | exact | exact | exact | Exec includes read. |
| `fs-literal` | exact | approximated | approximated | Linux binds the rule to the file's inode at spawn; a rename-replace loses it. |
| `fs-glob` | exact | approximated | approximated | macOS: one anchored, escaped regex. Linux: expanded at spawn, so files created later are not covered. Protect or hide with a glob is unsupported on Linux. |
| `fs-protect` | exact | exact | unsupported | T1: a read-only bind mount. |
| `fs-hide` | exact | exact | approximated | T1: masked, so the child sees "not found" where macOS reports "operation not permitted". T2: its siblings are allowed as listed at spawn. |
| `grant` | exact | exact | exact | macOS: a sandbox extension `procage.<name>`. Linux: a Landlock rule for the path bound at spawn. |
| `net-none` | exact | exact | exact | Linux: `socket` is denied for every family (`socketpair` stays available); T1 also gets an empty network namespace. |
| `net-loopback` | exact | approximated | unsupported | T1: host loopback ports are relayed into the namespace. Landlock filters ports, not addresses. |
| `net-unix-sockets` | exact | exact (ABI ≥ 9) / approximated | exact (ABI ≥ 9) / unsupported | Below ABI 9, T1 masks the unix sockets it finds under granted paths at spawn. |
| `net-proxy` | exact | exact | unsupported | macOS: outbound to the loopback proxy ports. T1: a network namespace bridged to them. |
| `net-all` | exact | exact | exact | |
| `exec-any` | exact | exact | exact | |
| `exec-never` | exact | exact | exact | |
| `fork-denied` | exact | exact | exact | Linux: seccomp denies `fork`, `vfork` and process-creating `clone`; `clone3` returns ENOSYS. |
| `signals-self-and-children` | exact | exact | exact (ABI ≥ 6) / unsupported | T1: the PID namespace. T2: the Landlock signal scope. |
| `signals-none` | exact | exact | exact | |
| `posix-shm` | exact | exact | approximated | T1: a private `/dev/shm`. T2 shares the host's `/dev/shm`. |
| `sysv-ipc` | exact | exact | approximated | T1: an IPC namespace. T2 shares the host's System V IPC. |
| `seatbelt-layer` | exact | approximated | approximated | Ignored on Linux when allowed. |
| `linux-layer` | approximated | exact | exact | Ignored on macOS when allowed. |
| `hygiene` | exact | exact | exact | Environment, limits and terminal are carried into the plan unchanged. |
| `base-v1` | exact | exact | exact | The curated base profile (see the `base` module). The Linux content is verified once Linux spawning exists. |
| `hd-fcntl-modify` | exact | n/a | n/a | `(deny system-fcntl (fcntl-command 80 110))`; compiles. |
| `hd-privilege` | exact | exact | exact | macOS: setugid writes and setuid/setgid exec denied; compiles. Linux: `no_new_privs`, which is always set. |
| `hd-service-handoff` | exact | n/a | n/a | Launch Services, Apple events, pasteboard and XPC service lookups, `lsopen`, `appleevent-send`; compiles. |
| `hd-process-access` | exact | exact | exact | macOS: task ports, `process-info*` outside the sandbox, signals to others; compiles. Linux: `ptrace`, `process_vm_*`, `pidfd_getfd`, `kcmp`. |
| `hd-rename-anchors` | exact | exact | exact | macOS: unlink denied on writable roots and on ancestors of protected or hidden paths; compiles. Linux: REFER is never granted, and T1 protect or hide targets are mountpoints. |
| `hd-terminal-injection` | exact | exact | exact | macOS: the TIOCSTI ioctl is denied; this compiles, but whether it holds is not yet established. Linux: `ioctl` with TIOCSTI or TIOCLINUX. |
| `hd-kernel-surface` | n/a | exact | exact | io_uring, `bpf`, `perf_event_open`, `userfaultfd`, keyrings. |
| `hd-namespaces` | n/a | exact | exact | `unshare`, `setns`, namespace-creating `clone`, `clone3`, mount syscalls. |
| `hd-socket-families` | n/a | exact | exact | `socket` with AF_VSOCK or AF_NETLINK. |
