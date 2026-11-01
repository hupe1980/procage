+++
title = "Linux backend and tiers"
description = "How procage combines Landlock, seccomp and namespaces on Linux into tiers T1 and T2, what each Landlock ABI changes, how to test against older kernels, and what is not done yet."
weight = 60

[extra]
group = "Backends"
nav = "Linux (tiers)"
+++

Linux has no single sandbox call. procage combines kernel features into a **tier**, chosen by what the host allows:

| Tier | Uses | Needs | Typical hosts |
|---|---|---|---|
| **T1** | User, mount, IPC, UTS and (unless the policy allows all networking) network namespaces, mounts, Landlock, seccomp | Unprivileged user namespaces and Landlock ABI 1+ | Most desktop distributions |
| **T2** | Landlock and seccomp only | Landlock ABI 1+ | A Docker container with default settings; hosts that restrict user namespaces (for example Ubuntu's AppArmor restriction) |
| none | | | Preparing a cage fails with `Unsupported`; procage never runs a child unsandboxed |

`procage::linux::probe()` measures the host once per process: the Landlock ABI (asked of the kernel, not guessed from its version, because distributions backport Landlock), and whether a user namespace with mounts works, tried in a throwaway child. `Cage::with_options` picks the strongest tier unless `CageOptions::with_tier` asks for one; asking for T1 where it is unavailable is `Unsupported`.

## Spawning

A `Cage` lowers the policy for the tier and the kernel's Landlock ABI; a construct the tier cannot enforce is a capability gap at preparation. `Cage::spawn` builds everything in the parent (the Landlock ruleset on descriptors opened for that spawn, the seccomp filter, the mounts and id maps) and forks a child that applies it with system calls only, in this order:

1. session (or process group);
2. parent-death signal;
3. namespaces, id maps and mounts (T1);
4. capabilities dropped;
5. resource limits;
6. inherited descriptors marked close-on-exec;
7. `no_new_privs`;
8. Landlock;
9. seccomp;
10. a check that seccomp and `no_new_privs` hold.

If any step fails, the target never runs and `SpawnError::Apply` names the step. The child holds no capabilities, not even in its bounding set.

## Landlock ABIs

Both tiers accept Landlock ABI 1 (Linux 5.13) and later. Each newer ABI makes more of a policy exact; what an older one cannot express is a capability gap or, where noted, a stricter rule.

| ABI | Linux | For example | Below it |
|---|---|---|---|
| 1 | 5.13 | Ubuntu 22.04 (5.15) | No sandbox at all |
| 3 | 6.2 | Ubuntu 22.04 HWE, 23.10 | Landlock cannot deny truncation, so procage refuses `truncate` by path and `open` with `O_TRUNC` without write access *everywhere*, also inside writable paths (truncate through a descriptor opened for writing instead), and `openat2` fails with `ENOSYS`. Debian 12 (6.1) is at ABI 2 |
| 4 | 6.7 | Ubuntu 24.04 (6.8) | No TCP rules: with the network off seccomp still refuses IP sockets, but an IP socket the caller hands over can connect (tier T2) |
| 6 | 6.12 | Debian 13, RHEL 10 | No signal scope: `Signals::SelfAndChildren` is a gap. Abstract Unix sockets are not scoped |
| 9 | | | Unix-socket rules on T2 |

RHEL 9.6 has ABI 5 through backports. procage uses Landlock rights up to ABI 8 for now (`procage::linux::BACKEND_MAX_ABI`); later rights have not been verified on a kernel.

### Testing against older kernels

`CageOptions::with_landlock_abi` lowers and enforces a policy as on an older kernel, so you can see which gaps your users' kernels give, or give every host of a fleet the same plan. A cap above the kernel's ABI has no effect.

```rust
use procage::linux::{Cage, CageOptions};
use procage::policy::Policy;

// What does this policy get on Debian 12 (Linux 6.1, ABI 2)?
let cage = Cage::with_options(&Policy::default(), &CageOptions::default().with_landlock_abi(2))?;
assert_eq!(cage.landlock_abi(), 2);
```

## Reading everything except secrets

A policy that reads `/` reaches the paths of the `secrets`, `trust-handoff` and `persistence` classes.

- On **T1** the paths that exist at spawn are masked.
- On **T2** a hidden path (an `Access::Hide` rule, or the secrets class) that no write rule reaches is kept out by granting the trees around it entry by entry, as listed at spawn: entries added later on the way are denied, the directories on the way cannot be listed, symbolic links on the way are not followed, and `stat` of the hidden path still works.
- A hidden or protected path **inside a writable tree** cannot be kept out on T2, and a write grant bound around one fails the spawn.

Each of these is an approximation you accept with `LowerOptions::accept_spawn_snapshot()`. Looking for class paths under writable trees walks them; a tree with more entries than `CageOptions::walk_limit` (200,000 by default) fails the spawn rather than going unchecked.

## Unix sockets

`ipc.unix_sockets` allows only `AF_UNIX` sockets when the network is otherwise off. On T1 below ABI 9, abstract sockets stay inside the cage's network namespace, and every listening socket outside the allowed paths, as listed in `/proc/net/unix` at spawn, is masked; sockets bound later stay reachable (an approximation accepted with the same option). T2 below ABI 9 cannot restrict pathname sockets and refuses the setting.

## What the tests observe

The Linux tests run in containers on tier T1 (seccomp unconfined) and tier T2 (Docker's defaults), with T2 also forced on the T1 host. Among what they observe:

- granted files work; every other file access fails with "permission denied"; `ptrace`, `io_uring_setup`, `bpf`, `keyctl`, `unshare`, `setns`, `perf_event_open` and `userfaultfd` fail;
- without network access, the host's loopback is unreachable (T1: a network namespace; T2: no sockets);
- on T1 a protected subtree is a read-only file system that neither `umount` nor a read-write remount undoes; `.ssh` and `.aws` in a readable home are unreadable; git hooks, `.vscode` and `.bashrc` in a writable workspace cannot be written, and a systemd user unit cannot be planted;
- on T2, protecting a subtree inside a writable one is a capability gap, and a grant bound to a home holding `.ssh` is refused;
- under `Lifetime::Run`, `setsid` and `setpgid` fail with `EPERM`, and descendants die with the child's process group;
- with the Landlock ABI capped at 1, 2, 3 and 5, on both tiers, writes stay in the workspace, the network is off, `ptrace` is refused and no file outside the writable paths can be truncated.

## Not done yet

- No PID namespace or fresh `/proc`, so keeping signals within the run needs Landlock ABI 6. A policy that grants `/proc` exposes other processes' arguments (R-25); their environment stays out of reach.
- With `Lifetime::Tree`, a descendant that double-forks into a session of its own outlives the run.
- Loopback and proxy networks need a relay into the network namespace: a gap on both tiers.
- Protect, and hide inside a writable tree, are gaps on T2; glob rules are gaps on both tiers.
- The tests have run on one kernel (7.0.14, aarch64, Docker Desktop), older ABIs through the cap; other kernels and x86_64 run in CI.
- The probe is cached per process, not per boot.

## Options

| `CageOptions` | Purpose |
|---|---|
| `with_lower(LowerOptions)` | Lowering options: accepted approximations, rule limit |
| `with_tier(Tier)` | Ask for T1 or T2 instead of the strongest available |
| `with_landlock_abi(u8)` | Behave as on an older kernel |
| `with_home(path)` | One more home directory for the data-driven classes |
| `with_walk_limit(usize)` | Entries one spawn may visit looking for class paths under writable trees |

## Violation reports

With `CageOptions::with_violations`, every system call the seccomp filter refuses is reported to the harness, exactly, with the process, the call and why (a hard-deny class, not granted, the lifetime lock, the older-kernel truncation guard). It needs no privileges and works on both tiers. Landlock's file, network and signal denials are not reported. See [Violations](@/docs/violations.md).
