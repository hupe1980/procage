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
ABI the kernel reports. Both tiers need Landlock ABI 1 or later; a lower ABI
is refused, and lowering never substitutes another tier. Below ABI 3,
Landlock cannot deny truncation, so every Linux plan there also denies
`truncate` (EPERM), `open` and `openat` with `O_TRUNC` unless the access
mode is `O_WRONLY` or `O_RDWR` (EPERM), and `openat2` (ENOSYS). These
refuse more than any policy asks: inside writable paths too, a file can then
be truncated only through a descriptor opened for writing.

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
| `fs-hide` | exact | exact | approximated | T1: a directory is covered by an empty tmpfs with mode 000 and a file by `/dev/null` bound read-only with `nodev`, so the child gets "permission denied" where macOS reports "operation not permitted". T2: the trees around the hidden path are granted entry by entry as listed at spawn (symbolic links are skipped): entries added later on the way are denied, the directories on the way cannot be listed, and `stat` of the hidden path still works. A write rule that reaches the hidden path makes it unsupported on T2, and a write grant bound around it fails the spawn. Accepted by `accept_spawn_snapshot`. |
| `grant` | exact | exact | exact | macOS: a sandbox extension `procage.<name>`. Linux: a Landlock rule for the path bound at spawn. |
| `net-none` | exact | exact | exact | Linux: `socket` is denied for every family (`socketpair` stays available); T1 also gets an empty network namespace. |
| `net-loopback` | exact | unsupported | unsupported | Linux needs a relay into the network namespace, which is not implemented. Landlock filters ports, not addresses. |
| `net-proxy` | exact | unsupported | unsupported | macOS: outbound to the loopback proxy ports. Linux needs a bridge into the network namespace, which is not implemented. |
| `net-all` | exact | exact | exact | |
| `exec-any` | exact | exact | exact | |
| `exec-never` | exact | exact | exact | |
| `fork-denied` | exact | exact | exact | Linux: seccomp denies `fork`, `vfork` and process-creating `clone`; `clone3` returns ENOSYS. |
| `lifetime-run` | exact | exact | exact | With fork only. Linux: seccomp denies `setsid` and `setpgid` (EPERM), installed after the child's own session or group, so every descendant stays in the child's process group. macOS: the run-marker block ends the profile; the spawn backend binds `procage-run-prefix` and `procage-run-marker` and finds the run's processes by it. |
| `lifetime-tree` | exact | exact | exact | With fork only. Linux: no lock; the run kills the group and the descendants found from the child. macOS: the same marker block as `lifetime-run`. |
| `signals-self-and-children` | exact | exact (ABI ≥ 6) / unsupported | exact (ABI ≥ 6) / unsupported | Linux: the Landlock signal scope. There is no PID namespace yet. Below ABI 6 a caller may choose `signals-same-user` instead. |
| `signals-same-user` | exact | exact | exact | Signals reach every process the operating system allows: on Linux, every process of the same user. macOS: `signal` allowed; `hd-process-access` still denies signals to processes outside the sandbox. |
| `signals-none` | exact | exact | exact | |
| `posix-shm` | exact | exact | approximated | T1: a private `/dev/shm`. T2 shares the host's `/dev/shm`. |
| `sysv-ipc` | exact | exact | approximated | T1: an IPC namespace. T2 shares the host's System V IPC. |
| `ipc-unix-sockets` | exact | exact (ABI ≥ 9) / approximated | exact (ABI ≥ 9) / unsupported | `ipc.unix_sockets`: create Unix sockets, bind and connect at or under the paths. macOS: `system-socket` plus `network-bind`, `network-inbound`, `network-outbound` with subpath filters (they match Unix-socket addresses only); hidden paths deny those operations. Linux with the network off: `socket()` for `AF_UNIX` only. ABI ≥ 9: Landlock's Unix-socket right on the paths and the abstract-socket scope. T1 below ABI 9: abstract sockets stay in the cage's network namespace, and every listening socket outside the paths listed in `/proc/net/unix` at spawn is masked; sockets bound later, or in another network namespace, stay reachable. T2 below ABI 9 has no mount namespace to mask with. Accepted by `accept_spawn_snapshot`. |
| `seatbelt-layer` | exact | approximated | approximated | Ignored on Linux when allowed. |
| `linux-layer` | approximated | exact | exact | Ignored on macOS when allowed. |
| `hygiene` | exact | exact | exact | Environment, limits and terminal are carried into the plan unchanged. |
| `base-v1` | exact | exact | exact | The curated base profile (see the `base` module). The Linux content is verified once Linux spawning exists. |
| `base-v2` | exact | exact | exact | V1 plus what developer tools need, measured on macOS 26.6.2 (see the `base` module): the Command Line Tools and Xcode bundles, `xcode-select`'s link, the Xcode license state, system Ruby and Perl paths, Homebrew's and `/usr/local`'s code directories, Homebrew's OpenSSL configuration, CoreFoundation's encoding setting and path-lookup metadata. No Mach service beyond V1 (`dirhelper` would point tools at the shared per-user temporary directory). Linux: the same as V1. |
| `base-v3` | exact | exact | exact | V2, with the probes every program makes denied quietly (`(with no-report)`, before every allow so a granted target still wins): the logging services (`logd`, `diagnosticd`), `dirhelper`, group membership lookups, the dyld DTrace helper's ioctl and `/dev/tty`. Allows nothing V2 does not. Linux: the same as V2. |
| `hd-fcntl-modify` | exact | n/a | n/a | `(deny system-fcntl (fcntl-command 80 110))`; compiles. |
| `hd-privilege` | exact | exact | exact | macOS: setugid writes and setuid/setgid exec denied; compiles. Linux: `no_new_privs`, which is always set. |
| `hd-service-handoff` | exact | exact | exact | macOS: Launch Services, Apple events, pasteboard and XPC service lookups, `lsopen`, `appleevent-send`; compiles. Linux: connecting to the D-Bus buses and the systemd managers' sockets is denied: with the network off and no `ipc.unix_sockets` by the socket deny; otherwise the backend looks for the sockets at cage creation and at each spawn — T1 covers them (an approximation reported when it finds one: sockets bound later outside the class's directories are not covered), T2 reports a gap per socket found, an abstract bus is scoped from ABI 6. |
| `hd-process-access` | exact | exact | exact | macOS: task ports, `process-info*` outside the sandbox, signals to others; compiles. Linux: `ptrace`, `process_vm_*`, `pidfd_getfd`, `kcmp`. |
| `hd-rename-anchors` | exact | exact | exact | macOS: unlink denied on writable roots and on ancestors of protected or hidden paths; compiles. Linux: REFER is never granted, and T1 protect or hide targets are mountpoints. |
| `hd-terminal-injection` | exact | exact | exact | macOS: the TIOCSTI ioctl is denied, and it holds (R-22, `escape_macos.rs::r22_terminal_input_injection_is_refused`). Linux: `ioctl` with TIOCSTI or TIOCLINUX. |
| `hd-kernel-surface` | n/a | exact | exact | io_uring, `bpf`, `perf_event_open`, `userfaultfd`, keyrings. |
| `hd-namespaces` | n/a | exact | exact | `unshare`, `setns`, namespace-creating `clone`, `clone3`, mount syscalls. |
| `hd-socket-families` | n/a | exact | exact | `socket` with AF_VSOCK or AF_NETLINK. |
| `hd-secrets` | exact | approximated | unsupported | Read and write denied for credential paths in every home (see the `presets` module). Linux, when a rule can reach them (otherwise exact: Landlock denies by default): T1 masks the paths that exist at spawn, so paths created later are not covered; T2 cannot deny inside an allowed tree. On T2 a grant whose path reaches them is refused at spawn. T2: reached only by read rules, the paths that exist at spawn are hidden like `fs-hide` (approximated); reached by a write rule, unsupported. |
| `hd-trust-handoff` | exact | approximated | unsupported | Write denied for git hooks and config, rc files, editor and agent config, PATH bins; `.git` cannot be removed or renamed. Linux, when a rule can reach them (any write rule or grant can): T1 makes the existing paths read-only and pins every existing `.git` under writable trees at spawn; T2 as for `hd-secrets`. |
| `hd-persistence` | exact | approximated | unsupported | Write denied for launch agents, launch daemons and login items (macOS) and autostart entries, systemd user units and cron directories (Linux). Linux as for `hd-secrets`. |
| `hd-container-engines` | exact | exact | exact | Connecting to the container engines' sockets is denied: macOS by `network-outbound` path rules (the resolved socket, case-folded); Linux as for `hd-service-handoff`. |
