+++
title = "Kernel facts and testing"
description = "How procage's claims are tested: an escape suite with a caged canary per escape class, a gate on the threat model's catalog, and a kernel-facts suite that re-verifies the OS behaviour procage relies on."
weight = 110

[extra]
group = "Security"
+++

A sandbox library is only as good as what the kernel actually enforces, and generated profile text proves nothing about that. procage's evidence therefore always comes from **real child processes on a real kernel**.

## The escape suite

For every escape class in the [threat model](@/docs/threat-model.md), the escape suite (`crates/procage/tests/escape_macos.rs` and `escape_linux.rs`) has one or more **canaries**: tests that spawn a caged child, attempt the escape and assert the refusal, next to a control showing that the same operation succeeds where the policy allows it. On Linux, a class a tier cannot enforce must be refused before any child runs, which the canary asserts for that tier.

A test gate checks the threat model's catalog itself: its format, that ids are stable, that every class has a canary for each platform it applies to, and that no class is marked handled without passing canaries as evidence.

## The kernel-facts suite

`crates/procage-kernel-facts` re-verifies, on the running kernel, the macOS Seatbelt and Linux Landlock, seccomp and namespace behaviour procage builds on. Each fact has an id (`KF-M…` for macOS, `KF-L…` for Linux) and a statement, for example:

- KF-M07: a literal `/etc/hosts` rule does not block reading it; `/private/etc/hosts` does (why procage resolves paths);
- KF-M09: a different second profile fails with `EPERM` and is not enforced (why procage refuses to nest);
- KF-M12: the `no-sandbox` exec modifier runs an executed program unsandboxed (why procage keeps it out of every profile).

Every fact runs a real child through a one-step probe binary and records only short, fixed observations. Facts are either *enforcement* facts (the kernel refuses something) or *observations* (how the OS behaves); an observation never makes a class mitigated.

Facts that apply a sandbox **fail rather than skip** when the suite itself runs inside a Seatbelt sandbox, such as an AI agent's. Run them from a plain terminal.

## Running the suites

The repository uses [just](https://just.systems) as its task runner:

```sh
just ci            # every local gate: fmt, clippy, tests, docs, cargo-deny, MSRV, no_std, semver, packaging
just test-outside  # the kernel facts, from a terminal outside any sandbox
just escape        # the macOS escape suite
just linux         # the Linux backend's tests in Docker, tier T2 (Docker's defaults)
just linux-t1      # the same with seccomp and AppArmor unconfined, tier T1
just kf-linux      # the Linux kernel facts in Docker (T2); kf-linux-t1 for T1
just fuzz-all      # fuzz the policy crate (nightly, cargo-fuzz)
```

## Where they have run

The escape suite's evidence in the threat model was recorded on macOS 26.6.2 (25G83, arm64) and Linux 7.0.14-linuxkit (aarch64, Landlock ABI 8) in containers for tiers T1 and T2. Older Landlock ABIs are exercised through `CageOptions::with_landlock_abi`. That is a narrow base: more kernels, x86_64 hosts and later macOS releases are what moves procage toward 0.1.0. Reports from other systems are welcome.
