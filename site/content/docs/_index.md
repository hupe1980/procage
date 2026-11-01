+++
title = "procage documentation"
description = "How procage cages child processes on macOS and Linux: policies, presets, hard-deny classes, the Seatbelt and Landlock backends, fitting a policy to the host, helpers, lifetime, hygiene and the threat model."
sort_by = "weight"
template = "docs.html"
page_template = "doc.html"

[extra]
seo_title = "Documentation · procage"
+++

procage is a Rust library that runs a child process in an OS sandbox. You describe what the child may do in a portable **policy**; procage lowers it for the system it runs on and spawns the child under it, or refuses and says exactly which part this host cannot enforce.

> [!NOTE]
> These pages describe procage 0.1. It is pre-1.0: the API may change between minor versions.

## The idea in four steps

1. **Write a policy** with the `procage-policy` crate, re-exported as `procage::policy`: file rules, network, process creation, IPC, environment, limits, terminal. Everything not granted is denied. Or start from a [preset](@/docs/presets.md).
2. **Prepare a cage.** `Cage::new` lowers the policy for this host: a Seatbelt profile on macOS, a Landlock ruleset, seccomp filter and mount plan on Linux. A construct the host cannot enforce is a typed capability gap, never a quietly weaker rule.
3. **Spawn.** `Cage::spawn` forks a child that confines itself with system calls only and then executes the target. If any step fails, the target never runs.
4. **End the run.** Dropping the handle kills every process the run started.

## Core concepts

- **Intent layer and lowering.** The [policy](@/docs/policies.md) states intent; a lowering table states, for every construct and target, whether it is exact, approximated (only with your consent) or unsupported.
- **Hard-deny tier.** Thirteen [classes](@/docs/hard-deny.md), such as secrets, trust handoff, persistence and container engines, are denied last in every policy and can only be waived by name.
- **Tiers.** On [Linux](@/docs/linux.md), tier T1 adds user namespaces and mounts to Landlock and seccomp; tier T2 has only the latter two. The [macOS backend](@/docs/macos.md) has one mechanism, Seatbelt.
- **Fitting.** When a host cannot enforce a policy, [`Cage::fit`](@/docs/fitting.md) relaxes only what you name and reports what would lift each relaxation.
- **Receipts.** Every finished run gives a [receipt](@/docs/receipts.md): the policy digest, backend and tier, and everything accepted short of the policy.
- **Audits.** A protected file with a second name refuses the spawn; the opt-in [handoff audit](@/docs/audits.md) lists what a run left behind.
- **Evidence.** Every known escape class has a stable id and a status in the [threat model](@/docs/threat-model.md); statuses rest on caged [canaries and kernel facts](@/docs/testing.md).
