+++
title = "Kernel facts and testing"
description = "How procage's claims are tested: an escape suite with a caged canary per escape class, a gate on the threat model's catalog, and a kernel-facts suite that re-verifies the OS behaviour procage relies on."
weight = 110

[extra]
group = "Security"
+++

Generated profile text proves nothing about what a kernel enforces, so procage's evidence always comes from **real child processes on a real kernel**.

## The escape suite

For every escape class in the [threat model](@/docs/threat-model.md), the escape suite (`crates/procage/tests/escape_macos.rs` and `escape_linux.rs`) has one or more **canaries**: tests that spawn a caged child, attempt the escape and assert the refusal, next to a control showing the same operation succeeds where the policy allows it. On Linux, a class a tier cannot enforce must be refused before any child runs, which the canary asserts for that tier.

A test gate (`crates/procage/tests/threat_model.rs`) checks the catalog itself: its format, stable ids, a canary for each platform a class applies to, and no class marked handled without passing canaries.

## The explain oracle

`crates/procage/tests/oracle.rs` asks every preset a target can express, and a policy with every rule kind, about 1,280 questions on each lane: once of [`Cage::explain`](@/docs/explain.md), once of the kernel, through a caged child that opens every file and caged spawns of copies of `true`. Any disagreement, or a kernel result that is neither success nor a refusal, fails the suite.

## The kernel-facts suite

`crates/procage-kernel-facts` re-verifies, on the running kernel, the macOS Seatbelt and Linux Landlock, seccomp and namespace behaviour procage builds on. Each fact has an id (`KF-M…` for macOS, `KF-L…` for Linux) and a statement, for example:

- KF-M07: a literal `/etc/hosts` rule does not block reading it; `/private/etc/hosts` does (why procage resolves paths);
- KF-M09: a different second profile fails with `EPERM` and is not enforced (why procage refuses to nest);
- KF-M12: the `no-sandbox` exec modifier runs an executed program unsandboxed (why procage keeps it out of every profile).

Every fact runs a real child through a one-step probe binary and records short, fixed observations. *Enforcement* facts show the kernel refusing something; *observations* show how the OS behaves and never make a class mitigated.

Facts that apply a sandbox **fail rather than skip** inside a Seatbelt sandbox, such as an AI agent's: run them from a plain terminal.

## Running the suites

The repository uses [just](https://just.systems) as its task runner:

```sh
just ci            # the local gates: fmt, clippy, tests, docs, cargo-deny, MSRV, no_std, semver
just test-outside  # the kernel facts, from a terminal outside any sandbox
just escape        # the macOS escape suite
just linux         # the Linux backend's tests in Docker, tier T2 (Docker's defaults)
just linux-t1      # the same with seccomp and AppArmor unconfined, tier T1
just kf-linux      # the Linux kernel facts in Docker (T2); kf-linux-t1 for T1
just kernel        # the Linux facts and suites on mainline kernels, one per Landlock ABI step (virtme-ng)
just fuzz-all      # fuzz the policy crate (nightly, cargo-fuzz)
just bench         # the spawn benchmark (indicative)
```

## Benchmarks

`just bench` spawns a no-op program 300 times per case and prints median,
p90 and p99 (`-- --quick` for 30; CI runs that and never fails on timing).
It refuses to run inside another sandbox. Median overhead over a plain
spawn, measured 2026-11-02:

| Case | macOS 26.6.2, M4 Pro | Linux 7.0 T1 (Docker) | Linux 7.0 T2 (Docker) |
|---|---|---|---|
| cached cage | 1.03 ms | 0.99 ms | 0.27 ms |
| cached cage, link check off | 0.58 ms | 0.95 ms | 0.25 ms |
| new policy per spawn | 11.6 ms (profile compiled) | 1.17 ms | 0.50 ms |
| with violation reporting | 1.81 ms | 0.98 ms | 0.26 ms |
| `sandbox-exec -p` / `bwrap --unshare-all` | 10.9 ms | 1.45 ms | — |

On macOS the link check (R-08) is about half the cached cost; a cage reused
across spawns compiles its profile once.

The bench also times `Cage::explain`'s evaluator: 0.61 ms per question for a
4,000-byte path under `agent_workspace` v3 on macOS.

## Where they have run

The evidence in the threat model was recorded on macOS 26.6.2 (25G83, arm64) and Linux 7.0.14-linuxkit (aarch64, Landlock ABI 8) in containers for tiers T1 and T2; older Landlock ABIs are exercised through `CageOptions::with_landlock_abi`. CI runs the kernel facts, the escape suites and the explain oracle on every push, on GitHub's macOS 26 and Ubuntu 24.04 (x86_64, tiers T1 and T2) runners.

On Linux, CI also boots Ubuntu mainline kernels with virtme-ng, one job per Landlock ABI step: 5.15 (ABI 1), 6.6 (3), 6.8 (4), 6.12 (6), 7.0 (8), 7.1 (9), 7.2 (10) and 7.3 (11). Each runs the kernel facts with the expected ABI and every Linux suite. `just kernel` boots the same kernels locally under QEMU.

The measurements and security requirements behind each change are in the [design records](https://github.com/hupe1980/procage/tree/main/specs) on GitHub.
