+++
title = "Threat model"
description = "What procage defends against (adaptive same-user code in the child), what it trusts, where an OS sandbox stops, and the status of its escape classes. A summary of the canonical THREAT_MODEL.md."
weight = 100

[extra]
group = "Security"
+++

This page summarises procage's threat model. The canonical text, with every escape class, its evidence and its open variants, is [**THREAT_MODEL.md**](https://github.com/hupe1980/procage/blob/main/crates/procage/THREAT_MODEL.md) in the repository; the same text is published as the `procage::threat_model` module in the crate documentation. Where this page and that file differ, the file is right.

> [!WARNING]
> procage 0.0.2 is an unreleased development version. Do not rely on any release before 0.1.0 to contain a process.

## Adversary

Arbitrary code running inside the caged child, **with the same user id as the caller**. It is adaptive: a language model following injected instructions, or a malicious build script. It can fork and exec, read and write whatever the policy grants, and use the network as the policy grants.

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

An OS sandbox *reduces* the risk from adaptive same-user code. It does not eliminate it: the kernel and the OS services stay reachable, and a bug in them is an escape. In exchange it starts far faster than a virtual machine and keeps full fidelity with the host's tools.

When a kernel or service escape is unacceptable, for example for code from unknown parties with access to valuable secrets, use a **microVM** (a hypervisor boundary). The two combine: a microVM for the boundary, procage inside it for finer-grained policy.

## Undocumented interfaces

- **macOS:** procage compiles and applies Seatbelt profiles through libsandbox functions Apple does not document or support, resolved at run time. If they are missing or behave differently, the result is an `Unsupported` error, never a silent fallback. A future macOS release may remove them. Finding a run's processes also uses an undocumented query, checked before the first forking spawn.
- **Linux:** procage measures the kernel (Landlock ABI, seccomp, unprivileged user namespaces) and assigns a tier. A policy the tier cannot enforce is an error that names the missing capability, never applied best-effort.
- **Nesting:** inside another Seatbelt sandbox, a second profile fails or has no effect; procage reports this up front instead of running uncaged.

## Escape classes

Each way a caged process could escape or leak is an **escape class** with a stable id (R-02 to R-31, with gaps where ids belong to other design risks). Each has a disposition (`mitigate`, `detect`, or `harness`) and a status. A class is `mitigated` only with evidence on every platform it applies to (caged canaries on a real kernel, next to a control showing the operation succeeds where allowed) and only when no variant is known to be open.

As of the development version 0.0.2:

- **Mitigated**, with canaries on each applicable platform: non-canonical path rules (R-02), pattern characters in paths (R-03), ancestor rename (R-04), writes through read-only descriptors (R-05), work handed to unsandboxed services (R-06), local daemons (R-09), a shared temporary directory (R-10), the unsandboxed exec modifier (R-11), firmlink spelling (R-12), inherited file descriptors (R-21), terminal input injection (R-22), outliving the run (R-23), secrets in the environment (R-24), filter-bypassing kernel interfaces (R-28), nested user namespaces (R-29), Landlock rule loss (R-30) and truncation without write access (R-31).
- **Documented, harness responsibility:** trust handoff (R-07). procage denies writes to the known locations; anything else the sandbox wrote must be treated as untrusted.
- **Partial:** process introspection (R-25). On macOS a caged child can read other same-user processes' arguments and environment through `KERN_PROCARGS2`, which the sandbox does not mediate. On Linux, a policy that grants `/proc` exposes other processes' arguments, because there is no PID namespace yet.
- **Planned:** pre-existing hard links (R-08): a hard link made before the run gives a protected file a second name that a path rule does not cover, and is neither reported nor refused. Helper replacement (R-26) applies once procage runs a helper program.

The [catalog in THREAT_MODEL.md](https://github.com/hupe1980/procage/blob/main/crates/procage/THREAT_MODEL.md#escape-classes) lists the evidence (test names) and the kernel facts observed for each class. How that evidence is produced is described in [Kernel facts and testing](@/docs/testing.md).

## Reporting an escape

Report a suspected sandbox escape **privately** through GitHub's [private vulnerability reporting](https://github.com/hupe1980/procage/security/advisories/new). Do not open a public issue. Include the OS and version (macOS build or Linux kernel release), the procage version, and the smallest policy and program that show the problem. See the [security policy](https://github.com/hupe1980/procage/blob/main/SECURITY.md).
