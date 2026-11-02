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
> procage is pre-1.0: the API may change between minor versions.

## How it works

1. **Write a policy** with `procage::policy` (the `procage-policy` crate), or start from a [preset](@/docs/presets.md). Everything not granted is denied.
2. **Prepare a cage.** `Cage::new` lowers the policy for this host: a Seatbelt profile on macOS; a Landlock ruleset, seccomp filter and mount plan on Linux. A construct the host cannot enforce is a typed capability gap, never a weaker rule.
3. **Spawn.** `Cage::spawn` forks a child that confines itself with system calls only, then executes the target. If any step fails, the target never runs.
4. **End the run.** Dropping the handle kills every process the run started.

## Core concepts

- **Lowering.** The [policy](@/docs/policies.md) states intent; the lowering table says, per construct and target, whether it is exact, approximated (only with your consent) or unsupported.
- **Hard-deny tier.** Thirteen [classes](@/docs/hard-deny.md), such as secrets, trust handoff, persistence and container engines, are denied last in every policy and can only be waived by name.
- **Tiers.** On [Linux](@/docs/linux.md), tier T1 adds user namespaces and mounts to Landlock and seccomp; tier T2 has only the latter two. [macOS](@/docs/macos.md) has one mechanism, Seatbelt.
- **Fitting.** When a host cannot enforce a policy, [`Cage::fit`](@/docs/fitting.md) relaxes only what you name and says what would lift each relaxation.
- **Violations.** An opt-in [record](@/docs/violations.md) of what the sandbox denied, and which rule denied it.
- **Receipts.** Every finished run gives a [receipt](@/docs/receipts.md): policy digest, backend and tier, and everything accepted short of the policy.
- **Audits.** A protected file with a second name refuses the spawn; the opt-in [handoff audit](@/docs/audits.md) lists what a run left behind.
- **Evidence.** Every known escape class has a stable id and a status in the [threat model](@/docs/threat-model.md), backed by caged [canaries and kernel facts](@/docs/testing.md).
