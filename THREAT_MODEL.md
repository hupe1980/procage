# Threat model

This document defines what procage is meant to defend against, what it
trusts and where it stops. It also lists every known escape class with its
status in the current release. The same text is published in the repository
and in the crate documentation.

## Release status

This is procage 0.0.2, an unreleased development version. The published
0.0.1 only reserves the crate name.

On macOS this version spawns a caged child: it resolves policy paths to the
spelling the kernel matches, compiles the policy once, and applies it in the
child with system calls only. If any step fails, the target never runs. Its
integration tests observe the kernel refusing access outside the policy.

On Linux it spawns a caged child on tier T1 (user, mount, IPC, UTS and
network namespaces, mounts, Landlock and seccomp) or tier T2 (Landlock and
seccomp), whichever the host allows, and refuses to spawn without Landlock.
A construct the tier cannot enforce is an error unless the caller accepts
it by name. Its integration tests run in containers for both tiers on one
kernel (7.0, aarch64).

On both systems it also closes every inherited descriptor the caller did not
hand over, kills every process the run started when the run ends (also
descendants that double-forked into a session of their own, and those of a
child that already exited), drops secret-looking variables from a
passed-through environment, and can give each run a private temporary
directory. To keep descendants in the run, `setsid` and `setpgid` fail inside
a Linux cage unless the policy opts out with `Lifetime::Tree`; this also
applies to the frozen presets.

A helper program can also become the caged command (`Cage::exec`) instead
of spawning it, for callers whose own code starts and kills the process.
The confinement is the same; the lifetime then belongs to whoever started
the helper. On Linux the command's descendants stay in its process group
and the command dies with the helper's parent; on macOS a descendant that
starts its own session is not reached when that group is killed.

It does **not** yet:

- keep a caged child on macOS from reading the arguments and environment of
  other processes of the same user (R-25): the sandbox does not mediate
  that query, so do not pass secrets to the calling program through its
  arguments or environment;
- report or refuse a hard link made before the run that gives a protected
  file a second name (R-08);
- protect a helper program from replacement (R-26): this release runs no
  helper, so the class does not apply yet;
- provide pseudo-terminals (its macOS base profile, V1, is curated for
  macOS 26.6.2 and grants nothing in the user's home);
- deny secrets, trust-handoff files and persistence locations on Linux
  where a rule reaches them, except by approximations the caller must
  accept: on tier T1 the paths that exist at spawn are masked; on tier T2
  secrets that only read rules reach are hidden by granting the trees
  around them entry by entry, and any class a write rule reaches is
  refused unless waived;
- hide or protect a path inside a writable tree on Linux tier T2;
- give Linux children a PID namespace or loopback or proxy networking, or
  restrict which Unix sockets they reach on tier T2 below Landlock ABI 9
  (on tier T1, listening sockets outside the allowed paths are masked at
  spawn, which does not cover sockets bound later).

Do not rely on any release before 0.1.0 to contain a process.

Everything below describes the design that upcoming releases implement. The
escape-class catalog shows, per class, whether this release has escape-suite
tests that prove the class is handled, and which variants remain open.

## Adversary

The adversary is arbitrary code running inside the caged child process, with
the same user id as the caller. It is adaptive. Examples are a language model
following injected instructions, or a malicious build script. It can fork and
exec, read and write whatever the policy grants, and use the network as the
policy grants.

## Assets

- Secrets: SSH, cloud and registry credentials, tokens in the environment,
  the Keychain, browser profiles.
- Files outside the paths the policy grants.
- The host session: the terminal, the parent shell, the graphical session.
- Persistence locations: launch agents, cron, login items, shell startup
  files, version-control hooks.
- Other runs, and the calling program's own binary and state.

## Trusted

- The parent process and the policy it passes to procage.
- The kernel.
- The OS sandbox facilities: on macOS, libsandbox and libSystem; on Linux,
  the kernel's Landlock, seccomp and namespace implementations.

## In scope

- Escapes caused by misconfiguration, and the known escape classes listed
  below.
- Leaks through state the child inherits: file descriptors, environment,
  the controlling terminal, Mach ports.
- Persistence, and descendants that outlive the run.

## Out of scope

- Bugs in the kernel, XPC services, TCC or Linux security modules.
- Side channels.
- Denial of service beyond the resource limits procage will set.
- **Trust handoff beyond the shipped presets**: a program *outside* the
  sandbox later runs or trusts something the sandbox wrote. procage will ship
  write-deny presets for the known locations. Every other such location is
  the responsibility of the calling harness (see R-07 below).

## Strength

An OS sandbox (macOS Seatbelt, or Linux Landlock with namespaces and seccomp)
*reduces* the risk from adaptive same-user code. It does not eliminate it: the
kernel and the OS services stay reachable, and a bug in them is an escape. In
exchange, it adds far less start-up latency than a virtual machine, and the
caged process keeps full fidelity with the host's tools.

When a kernel or service escape is unacceptable, for example for code from
unknown parties with access to valuable secrets, use a microVM (a hypervisor
boundary). You can also combine the two: a microVM for the boundary, and
procage inside it for finer-grained policy.

## Dependencies on undocumented interfaces

These are design commitments for upcoming releases, not behaviour of this
release.

- **macOS.** procage will compile and apply Seatbelt profiles through
  libsandbox functions that Apple does not document or support. It will
  resolve them at run time, before starting a child. If they are missing or
  behave differently, the result will be an "unsupported" error, never a
  silent fallback to running without a sandbox. A future macOS release may remove them.
- **Linux.** procage will measure what the running kernel offers (Landlock
  ABI, seccomp, unprivileged user namespaces) and assign a tier. A policy the
  tier cannot enforce will be an error that names the missing capability. It
  will never be applied best-effort.
- **Finding a run's processes (macOS).** A forking run's profile carries a
  marker, and procage asks libsandbox, for every process of the user,
  whether that process's sandbox allows it. This query form is undocumented;
  procage checks it once before the first forking spawn and reports an
  "unsupported" error if it fails. Between finding a process and killing it,
  the process could exit and its process id be reused; macOS offers no
  process handle that would close that window. On Linux, descendants stay in
  the child's process group instead, unless the policy chooses
  `Lifetime::Tree`, in which case a descendant that double-forks into a
  session of its own outlives the run.
- **Nesting.** Inside another Seatbelt sandbox (for example an AI agent's
  own), applying a second profile fails or has no effect. procage will
  report this as an error up front instead of running uncaged.
- **Profile size.** libsandbox rejects or aborts on very large profiles, so
  procage will bound profile size and report a limit error.

## Non-goals

- Defending against kernel, XPC, TCC and Linux security module bugs, and
  against side channels.
- App Sandbox, entitlements, Endpoint Security, eBPF security modules: they
  need code signing, Apple approval or root.
- TLS interception.
- Windows.

## Escape classes

Each row is one way a caged process could escape or leak. The fields are:

- **Disposition**: how procage intends to handle the class. `mitigate`:
  procage is designed to prevent it. `detect`: procage is designed to report
  it. `harness`: the calling program must handle it, with help from procage.
- **Status**: what the current release does. `planned` and `documented` make
  no enforcement claim. `mitigated` or `detected` is only used together with
  evidence on every platform the class applies to, and only when no variant
  of the class is known to be open. `partial` means the evidence covers some
  variants or platforms and the rest are listed under
  [Open variants](#open-variants). `retired` marks a class that no longer
  applies.
- **Evidence**: canaries of procage's escape suite: tests that spawn a
  caged child on a real kernel, attempt the escape and assert the refusal,
  next to a control showing the same operation succeeds where the policy
  allows it. They ran on macOS 26.6.2 (25G83, arm64) and Linux
  7.0.14-linuxkit (aarch64, Landlock ABI 8) in containers for tier T1 and
  tier T2. On Linux, a class that a tier cannot enforce is refused before
  any child runs, which the canary asserts for that tier.
- **Observed on**: kernel facts from procage's kernel-facts suite that
  observe the underlying OS behaviour. They were recorded on macOS 26.6.2
  (25G83) and Linux 7.0.14-linuxkit on 2026-10-29. An observation shows how
  the OS behaves; it does not make a class mitigated.

Ids are stable and never reused or renumbered. They share one numbering with
procage's other design risks (private-interface removal, profile limits,
nesting, the Linux tier), which are covered in the sections above. This is
why the numbering has gaps.

| Id | Class | Description | Platforms | Disposition | Status | Evidence | Observed on |
|---|---|---|---|---|---|---|---|
| R-02 | Non-canonical path rules | A rule spelled through an alias or symbolic link (`/etc` instead of `/private/etc`) silently matches nothing. | macOS, Linux | mitigate | mitigated | tests/escape_macos.rs::r02_a_protect_rule_spelled_through_a_symlink_holds, tests/escape_linux.rs::r02_a_rule_spelled_through_a_symlink_binds_its_target | KF-M07, KF-M08 |
| R-03 | Pattern characters in paths | A resolved path that contains glob or regular-expression characters widens a rule beyond the intended file. | macOS | mitigate | mitigated | tests/escape_macos.rs::r03_glob_characters_in_a_path_stay_literal | — |
| R-04 | Ancestor rename | Renaming a parent directory moves protected files out from under path-based rules. | macOS, Linux | mitigate | mitigated | tests/escape_macos.rs::r04_a_protected_ancestor_cannot_be_renamed, tests/escape_linux.rs::r04_a_protected_file_stays_protected_when_an_ancestor_is_renamed | — |
| R-05 | Writes through read-only descriptors | Some file-control operations modify a file through a descriptor that was opened read-only. | macOS | mitigate | mitigated | tests/escape_macos.rs::r05_modifying_fcntl_commands_are_refused | — |
| R-06 | Work handed to unsandboxed services | Launch Services, Apple events, the pasteboard or XPC services act on the child's behalf outside the sandbox. | macOS | mitigate | mitigated | tests/escape_macos.rs::r06_service_handoff_lookups_are_refused | — |
| R-07 | Trust handoff | The child writes files that an unsandboxed program later runs or trusts: version-control config and hooks, shell startup files, tool config, programs on the search path. | macOS, Linux | harness | documented | tests/escape_macos.rs::r07_trust_handoff_files_are_refused_in_a_writable_workspace, tests/escape_linux.rs::r07_trust_handoff_files_are_protected_in_a_writable_workspace | — |
| R-08 | Pre-existing hard links | A hard link created before the run gives a protected file a second name that a literal-path deny does not cover. | macOS, Linux | detect | planned | — | — |
| R-09 | Local daemons | Loopback ports or Unix-domain sockets reach privileged local daemons, such as a container engine's socket. | macOS, Linux | mitigate | mitigated | tests/escape_macos.rs::r09_other_ports_and_daemon_sockets_are_unreachable, tests/escape_macos.rs::r09_unix_sockets_reach_only_their_paths, tests/escape_linux.rs::r09_daemons_are_unreachable_without_network_access, tests/escape_linux.rs::r09_unix_sockets_reach_only_their_paths | — |
| R-10 | Shared temporary directory | Runs that share the per-user temporary directory can read or change each other's files. | macOS, Linux | mitigate | mitigated | tests/escape_macos.rs::r10_runs_do_not_share_temporary_files, tests/escape_linux.rs::r10_runs_do_not_share_temporary_files | — |
| R-11 | Unsandboxed exec modifier | A Seatbelt profile modifier that runs an exec'd program without any sandbox reaches the compiled profile. | macOS | mitigate | mitigated | tests/escape_macos.rs::r11_executed_programs_stay_caged | KF-M12 |
| R-12 | Firmlink spelling | A rule spelled with the data-volume path does not cover the path as programs see it. | macOS | mitigate | mitigated | tests/escape_macos.rs::r12_a_data_volume_spelling_protects_the_visible_path | KF-M21 |
| R-21 | Inherited file descriptors | A descriptor opened before the sandbox was applied reads or writes past every path rule. | macOS, Linux | mitigate | mitigated | tests/escape_macos.rs::r21_an_inherited_descriptor_does_not_reach_the_child, tests/escape_linux.rs::r21_an_inherited_descriptor_does_not_reach_the_child | KF-M19 |
| R-22 | Terminal input injection | A child that shares the caller's terminal pushes keystrokes into its input queue, which the shell then runs outside the sandbox. | macOS, Linux | mitigate | mitigated | tests/escape_macos.rs::r22_terminal_input_injection_is_refused, tests/escape_linux.rs::r22_terminal_input_injection_is_refused | KF-M26 |
| R-23 | Outliving the run | Descendants keep running after the run ends, or register launch agents, cron jobs or login items that later run unsandboxed. | macOS, Linux | mitigate | mitigated | tests/escape_macos.rs::r23_descendants_die_with_the_run, tests/escape_macos.rs::r23_a_double_forked_descendant_dies_with_the_run, tests/escape_macos.rs::r23_descendants_of_an_exited_child_die_with_the_run, tests/escape_macos.rs::r23_concurrent_runs_are_separate, tests/escape_macos.rs::r23_a_launch_agent_cannot_be_planted, tests/escape_linux.rs::r23_descendants_die_with_the_run, tests/escape_linux.rs::r23_a_double_forked_descendant_dies_with_the_run, tests/escape_linux.rs::r23_descendants_of_an_exited_child_die_with_the_run, tests/escape_linux.rs::r23_sessions_are_locked, tests/escape_linux.rs::r23_a_user_unit_cannot_be_planted | — |
| R-24 | Secrets in the environment | Inherited environment variables carry tokens, keys or agent sockets into the child. | macOS, Linux | mitigate | mitigated | tests/escape_macos.rs::r24_secret_variables_do_not_reach_the_child, tests/escape_linux.rs::r24_secret_variables_do_not_reach_the_child | — |
| R-25 | Process introspection | The child reads other processes' arguments and environment through same-user process information. | macOS, Linux | mitigate | partial | tests/escape_macos.rs::r25_other_processes_cannot_be_signalled, tests/escape_linux.rs::r25_other_processes_are_opaque | — |
| R-26 | Helper replacement | A helper program that procage runs is overwritten from inside the sandbox and runs uncaged at the next start. | macOS, Linux | mitigate | planned | — | — |
| R-28 | Filter-bypassing kernel interfaces | io_uring, VM sockets or netlink perform I/O that socket and file filters do not see. | Linux | mitigate | mitigated | tests/escape_linux.rs::r28_filter_bypassing_interfaces_are_refused | — |
| R-29 | Nested user namespaces | A user namespace created inside the sandbox is used to remount, unmount or remap and so undo the sandbox's mounts. | Linux | mitigate | mitigated | tests/escape_linux.rs::r29_nested_user_namespaces_and_mount_changes_are_refused | KF-L09, KF-L10 |
| R-30 | Landlock rule loss | Landlock rules attach to existing files: replacing a file by rename drops its rule, and paths that do not exist yet cannot be ruled. On a tier without mount isolation this is reported as a capability gap. | Linux | mitigate | mitigated | tests/escape_linux.rs::r30_a_protected_file_cannot_be_replaced | — |

### Harness responsibilities

- **R-07** On macOS, this development version denies writes to the known
  trust-handoff locations in every policy, last and waivable only by name:
  version-control hooks and config, shell startup files, common tool
  configuration, editor and agent directories, user program directories and
  launch agents. On Linux, tier T1 makes the paths of these locations that
  exist at spawn read-only, and tier T2 refuses a policy whose rules reach
  them unless the class is waived. The calling harness must
  still treat everything the sandbox wrote as untrusted before an
  unsandboxed program uses it. This covers project-specific build scripts,
  generated code, and any location outside these lists.

### Open variants

- **R-08** Neither system reports or refuses a hard link made before the
  run; a protected or hidden file stays reachable through its second name.
- **R-25** On macOS any process of the same user can read another's
  arguments and environment through the `KERN_PROCARGS2` query, which the
  sandbox does not mediate (observed on macOS 26.6.2). Signals to other
  processes and task ports are refused. On Linux the base profile does not
  grant `/proc`; a policy that grants it exposes other processes'
  arguments, because Linux children have no PID namespace yet, while their
  environment stays out of reach.
- **R-26** procage runs no helper program in this release; the class
  applies once it does.

Report a suspected escape privately as described in the security policy:
<https://github.com/hupe1980/procage/blob/main/SECURITY.md>.
