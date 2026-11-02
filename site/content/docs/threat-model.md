+++
title = "Threat model"
description = "What procage defends against (adaptive same-user code in the child), what it trusts, where an OS sandbox stops, and the status of its escape classes. A summary of the canonical THREAT_MODEL.md."
weight = 100

[extra]
group = "Security"
+++

This page summarises procage's threat model. The canonical text, with every escape class, its evidence and its open variants, is [**THREAT_MODEL.md**](https://github.com/hupe1980/procage/blob/main/crates/procage/THREAT_MODEL.md), also published as the `procage::threat_model` module. Where they differ, the file is right.

## Adversary

Arbitrary, adaptive code inside the caged child, **with the same user id as the caller**: a language model following injected instructions, or a malicious build script. It can fork and exec, and use files and network as the policy grants.

## Assets

- **Secrets:** SSH, cloud and registry credentials, tokens in the environment, the Keychain, browser profiles.
- **Files** outside the paths the policy grants.
- **The host session:** the terminal, the parent shell, the graphical session.
- **Persistence locations:** launch agents, cron, login items, shell startup files, version-control hooks.
- **Other runs**, and the calling program's own binary and state.

## Trusted

The parent process and the policy it passes; the kernel; the OS sandbox facilities (libsandbox and libSystem on macOS; Landlock, seccomp and namespaces in the Linux kernel).

## In scope and out of scope

In scope: escapes caused by misconfiguration, the known escape classes, leaks through inherited state (file descriptors, environment, the controlling terminal, Mach ports), persistence, and descendants that outlive the run.

Out of scope: bugs in the kernel, XPC services, TCC or Linux security modules; side channels; denial of service beyond the resource limits; and **trust handoff beyond the shipped lists**: when a program outside the sandbox later runs or trusts something the sandbox wrote, procage covers the known locations with its [hard-deny classes](@/docs/hard-deny.md), and every other location is the calling harness's job (R-07).

## How strong an OS sandbox is

An OS sandbox *reduces* the risk from adaptive same-user code; it does not eliminate it. The kernel and the OS services stay reachable, and a bug in them is an escape. In exchange it starts far faster than a virtual machine and runs the host's own tools.

When a kernel or service escape is unacceptable, use a **microVM** (a hypervisor boundary), optionally with procage inside it for finer-grained policy.

## Undocumented interfaces

- **macOS:** Seatbelt profiles are compiled and applied through libsandbox functions Apple does not document or support, resolved at run time; finding a run's processes uses an undocumented query. Any macOS release may remove them. Missing or changed behaviour is an `Unsupported` error, never a silent fallback.
- **Linux:** procage measures the kernel (Landlock ABI, seccomp, unprivileged user namespaces) and assigns a tier. A policy the tier cannot enforce is an error naming the missing capability, never applied best-effort.
- **Nesting:** inside another Seatbelt sandbox a second profile fails or has no effect; procage refuses up front.

## Escape classes

Each way a caged process could escape or leak is an **escape class** with a stable id (R-02 to R-34, with gaps). Each has a disposition (`mitigate`, `detect` or `harness`) and a status. A class is `mitigated` only with evidence on every platform it applies to (caged canaries on a real kernel, next to a control showing the operation succeeds where allowed) and only when no variant is known to be open.

- **Mitigated:** non-canonical path rules (R-02), pattern characters in paths (R-03), ancestor rename (R-04), writes through read-only descriptors (R-05), work handed to unsandboxed services (R-06), pre-existing hard links (R-08, refused before each spawn), local daemons (R-09), a shared temporary directory (R-10), the unsandboxed exec modifier (R-11), firmlink spelling (R-12), inherited file descriptors (R-21), terminal input injection (R-22), outliving the run (R-23), secrets in the environment (R-24), process introspection (R-25; on Linux, reaching other processes' `/proc` entries is the approximation `proc-other-processes`, accepted by name), filter-bypassing kernel interfaces (R-28), nested user namespaces (R-29), Landlock rule loss (R-30), truncation without write access (R-31), seccomp listener hijack (R-32) and service handoff over Unix sockets (R-34).
- **Harness responsibility:** trust handoff (R-07). procage denies writes to the known locations, and its [handoff audit](@/docs/audits.md) lists what a run created or changed; anything else the sandbox wrote must be treated as untrusted.
- **Not applicable:** helper replacement (R-26) concerns a helper program procage installs, and it installs none. A `Cage::exec` helper is your own binary: keep it outside every writable path.

The [catalog](https://github.com/hupe1980/procage/blob/main/crates/procage/THREAT_MODEL.md#escape-classes) lists the evidence (test names) and kernel facts for each class; [Kernel facts and testing](@/docs/testing.md) describes how it is produced.

## Reporting an escape

Report a suspected sandbox escape **privately** through GitHub's [private vulnerability reporting](https://github.com/hupe1980/procage/security/advisories/new). Do not open a public issue. Include the OS and version (macOS build or Linux kernel release), the procage version, and the smallest policy and program that show the problem. See the [security policy](https://github.com/hupe1980/procage/blob/main/SECURITY.md).
