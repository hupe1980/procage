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
| `fs-glob` | exact | unsupported | unsupported | macOS: one anchored, escaped regex. Linux: expanding globs at spawn is not implemented; protect or hide with a glob is unsupported too. |
| `fs-protect` | exact | exact | unsupported | T1: a read-only bind mount of the path onto itself, keeping the mount flags the kernel locks. |
| `fs-hide` | exact | exact | unsupported | T1: a directory is covered by an empty tmpfs with mode 000 and a file by `/dev/null` bound read-only with `nodev`, so the child gets "permission denied" where macOS reports "operation not permitted". |
| `grant` | exact | exact | exact | macOS: a sandbox extension `procage.<name>`. Linux: a Landlock rule for the path bound at spawn. |
| `net-none` | exact | exact | exact | Linux: `socket` is denied for every family (`socketpair` stays available); T1 also gets an empty network namespace. |
| `net-loopback` | exact | unsupported | unsupported | Linux needs a relay into the network namespace, which is not implemented. Landlock filters ports, not addresses. |
| `net-unix-sockets` | exact | exact (ABI ≥ 9) / unsupported | exact (ABI ≥ 9) / unsupported | Below ABI 9 Landlock cannot restrict connecting to a pathname socket. |
| `net-proxy` | exact | unsupported | unsupported | macOS: outbound to the loopback proxy ports. Linux needs a bridge into the network namespace, which is not implemented. |
| `net-all` | exact | exact | exact | |
| `exec-any` | exact | exact | exact | |
| `exec-never` | exact | exact | exact | |
| `fork-denied` | exact | exact | exact | Linux: seccomp denies `fork`, `vfork` and process-creating `clone`; `clone3` returns ENOSYS. |
| `signals-self-and-children` | exact | exact (ABI ≥ 6) / unsupported | exact (ABI ≥ 6) / unsupported | Linux: the Landlock signal scope. There is no PID namespace yet. |
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
| `hd-secrets` | exact | approximated | unsupported | Read and write denied for credential paths in every home (see the `presets` module). Linux, when a rule can reach them (otherwise exact: Landlock denies by default): T1 masks the paths that exist at spawn, so paths created later are not covered; T2 cannot deny inside an allowed tree. On T2 a grant whose path reaches them is refused at spawn. |
| `hd-trust-handoff` | exact | approximated | unsupported | Write denied for git hooks and config, rc files, editor and agent config, PATH bins; `.git` cannot be removed or renamed. Linux, when a rule can reach them (any write rule or grant can): T1 makes the existing paths read-only and pins every existing `.git` under writable trees at spawn; T2 as for `hd-secrets`. |
| `hd-persistence` | exact | approximated | unsupported | Write denied for launch agents, launch daemons and login items (macOS) and autostart entries, systemd user units and cron directories (Linux). Linux as for `hd-secrets`. |
