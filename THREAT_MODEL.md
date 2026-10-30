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

It also closes every inherited descriptor the caller did not hand over,
kills the child and the descendants it can find when the run ends, drops
secret-looking variables from a passed-through environment, and can give
each run a private temporary directory.

It does **not** yet:

- stop a descendant that double-forks and starts its own session on macOS
  from outliving the run;
- provide pseudo-terminals or the preset hard-deny data (its base profile,
  V1, is curated for macOS 26.6.2 and grants nothing in the user's home);
- support Linux.

Do not rely on any release before 0.1.0 to contain a process.

Everything below describes the design that upcoming releases implement. The
escape-class catalog shows, per class, whether a release has an escape-suite
test that proves the class is handled. In this version none has.

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
  evidence: a test in this repository that runs a caged child on a real
  kernel. `retired` marks a class that no longer applies.
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
| R-02 | Non-canonical path rules | A rule spelled through an alias or symbolic link (`/etc` instead of `/private/etc`) silently matches nothing. | macOS, Linux | mitigate | planned | — | KF-M07, KF-M08 |
| R-03 | Pattern characters in paths | A resolved path that contains glob or regular-expression characters widens a rule beyond the intended file. | macOS | mitigate | planned | — | — |
| R-04 | Ancestor rename | Renaming a parent directory moves protected files out from under path-based rules. | macOS, Linux | mitigate | planned | — | — |
| R-05 | Writes through read-only descriptors | Some file-control operations modify a file through a descriptor that was opened read-only. | macOS | mitigate | planned | — | — |
| R-06 | Work handed to unsandboxed services | Launch Services, Apple events, the pasteboard or XPC services act on the child's behalf outside the sandbox. | macOS | mitigate | planned | — | — |
| R-07 | Trust handoff | The child writes files that an unsandboxed program later runs or trusts: version-control config and hooks, shell startup files, tool config, programs on the search path. | macOS, Linux | harness | documented | — | — |
| R-08 | Pre-existing hard links | A hard link created before the run gives a protected file a second name that a literal-path deny does not cover. | macOS, Linux | detect | planned | — | — |
| R-09 | Local daemons | Loopback ports or Unix-domain sockets reach privileged local daemons, such as a container engine's socket. | macOS, Linux | mitigate | planned | — | — |
| R-10 | Shared temporary directory | Runs that share the per-user temporary directory can read or change each other's files. | macOS, Linux | mitigate | planned | — | — |
| R-11 | Unsandboxed exec modifier | A Seatbelt profile modifier that runs an exec'd program without any sandbox reaches the compiled profile. | macOS | mitigate | planned | — | KF-M12 |
| R-12 | Firmlink spelling | A rule spelled with the data-volume path does not cover the path as programs see it. | macOS | mitigate | planned | — | KF-M21 |
| R-21 | Inherited file descriptors | A descriptor opened before the sandbox was applied reads or writes past every path rule. | macOS, Linux | mitigate | planned | — | KF-M19 |
| R-22 | Terminal input injection | A child that shares the caller's terminal pushes keystrokes into its input queue, which the shell then runs outside the sandbox. | macOS, Linux | mitigate | planned | — | KF-M26 |
| R-23 | Outliving the run | Descendants keep running after the run ends, or register launch agents, cron jobs or login items that later run unsandboxed. | macOS, Linux | mitigate | planned | — | — |
| R-24 | Secrets in the environment | Inherited environment variables carry tokens, keys or agent sockets into the child. | macOS, Linux | mitigate | planned | — | — |
| R-25 | Process introspection | The child reads other processes' arguments and environment through same-user process information. | macOS, Linux | mitigate | planned | — | — |
| R-26 | Helper replacement | A helper program that procage runs is overwritten from inside the sandbox and runs uncaged at the next start. | macOS, Linux | mitigate | planned | — | — |
| R-28 | Filter-bypassing kernel interfaces | io_uring, VM sockets or netlink perform I/O that socket and file filters do not see. | Linux | mitigate | planned | — | — |
| R-29 | Nested user namespaces | A user namespace created inside the sandbox is used to remount, unmount or remap and so undo the sandbox's mounts. | Linux | mitigate | planned | — | KF-L09, KF-L10 |
| R-30 | Landlock rule loss | Landlock rules attach to existing files: replacing a file by rename drops its rule, and paths that do not exist yet cannot be ruled. On a tier without mount isolation this is reported as a capability gap. | Linux | mitigate | planned | — | — |

### Harness responsibilities

- **R-07** procage will ship versioned write-deny presets for the known
  trust-handoff locations (version-control config and hooks, shell startup
  files, common tool config, user program directories, launch agents). The
  calling harness must still treat everything the sandbox wrote as untrusted
  before an unsandboxed program uses it. This covers project-specific build
  scripts, editor and agent configuration, and any location outside the
  presets.

Report a suspected escape privately as described in the security policy:
<https://github.com/hupe1980/procage/blob/main/SECURITY.md>.
