+++
title = "Linux backend and tiers"
description = "How procage combines Landlock, seccomp and namespaces on Linux into tiers T1 and T2, what each Landlock ABI changes, how to test against older kernels, and its limits."
weight = 60

[extra]
group = "Backends"
nav = "Linux (tiers)"
+++

Linux has no single sandbox call. procage combines kernel features into a **tier**, chosen by what the host allows:

| Tier | Uses | Needs | Typical hosts |
|---|---|---|---|
| **T1** | User, mount, IPC, UTS and (unless the policy allows all networking) network namespaces, mounts, Landlock, seccomp | Unprivileged user namespaces, mounts by descriptor (`openat2`, `open_tree`, `fsmount`, `mount_setattr`, `move_mount`) and Landlock ABI 1+ | Most desktop distributions |
| **T2** | Landlock and seccomp only | Landlock ABI 1+ | A Docker container with default settings; hosts that restrict user namespaces (for example Ubuntu's AppArmor restriction) |
| none | | | Preparing a cage fails with `Unsupported`; procage never runs a child unsandboxed |

`procage::linux::probe()` measures the host once per process: the Landlock ABI (asked of the kernel, since distributions backport Landlock) and whether a user namespace with mounts works, tried in a throwaway child with the same calls the T1 child makes. `Cage::with_options` picks the strongest tier unless `CageOptions::with_tier` asks for one; asking for T1 where it is unavailable is `Unsupported`.

## Spawning

A `Cage` lowers the policy for the tier and the kernel's Landlock ABI; a construct the tier cannot enforce is a capability gap at preparation. `Cage::spawn` builds everything in the parent (Landlock ruleset, seccomp filter, mounts and id maps) and forks a child that applies it with system calls only, in this order:

1. ignored signals reset to their default action, then session (or process group);
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

Both tiers accept Landlock ABI 1 (Linux 5.13) and later. What an older ABI cannot express is a capability gap or, where noted, a stricter rule.

| ABI | Linux | For example | Below it |
|---|---|---|---|
| 1 | 5.13 | Ubuntu 22.04 (5.15) | No sandbox at all |
| 2 | 5.19 | Debian 12 (6.1) | Files cannot move or link between directories: such a move fails with `EXDEV` |
| 3 | 6.2 | Ubuntu 22.04 HWE, 23.10 | Landlock cannot deny truncation, so procage refuses `truncate` by path and `open` with `O_TRUNC` without write access *everywhere*, also inside writable paths (truncate through a descriptor opened for writing instead), and `openat2` fails with `ENOSYS`. |
| 4 | 6.7 | Ubuntu 24.04 (6.8) | No TCP rules: with the network off seccomp still refuses IP sockets, but a TCP socket the caller hands over can connect (tier T2) |
| 6 | 6.12 | Debian 13, RHEL 10 | No signal scope: `Signals::SelfAndChildren` is a gap. Abstract Unix sockets are not scoped |
| 9 | 7.1 | | No Unix-socket rules: `ipc.unix_sockets` is approximated on T1 and refused on T2 |
| 10 | 7.2 | | No UDP rules: with the network off, a UDP socket the caller hands over can send |

RHEL 9.6 has ABI 5 through backports. procage uses Landlock rights up to ABI 11 (`procage::linux::BACKEND_MAX_ABI`); the [kernel matrix](@/docs/testing.md#where-they-have-run) runs every step of the table, and ABI 11, on a mainline kernel. ABI 11's no-new-privileges flag changes nothing: the child sets no-new-privileges itself before its seccomp filter on every kernel.

### Testing against older kernels

`CageOptions::with_landlock_abi` lowers and enforces a policy as on an older kernel: to see which gaps your users' kernels give, or to give every host of a fleet the same plan. A cap above the kernel's ABI has no effect.

```rust
use procage::linux::{Cage, CageOptions};
use procage::policy::Policy;

// What does this policy get on Debian 12 (Linux 6.1, ABI 2)?
let cage = Cage::with_options(&Policy::default(), &CageOptions::default().with_landlock_abi(2))?;
assert_eq!(cage.landlock_abi(), 2);
```

## Mounts that cannot be moved

On T1 the child mounts after the parent planned the mounts, and another process with write access to the tree could replace a planned path with a symbolic link or rename another directory into its place in between (R-33). procage fixes the object of each protect, hide and pin when the cage is made, and of each cover when the spawn plans it. The child opens every path from `/` without following any link (`openat2` with `RESOLVE_NO_SYMLINKS`), checks the device and inode, and mounts on that descriptor with the mount's flags set before it is attached. Otherwise the spawn fails with `SpawnError::MountMoved`, naming the path and the link, if any. A cover whose file was removed is skipped, as a file created after the spawn is never covered. A protected or hidden object replaced after the cage was made (an editor's atomic save, for example) refuses every later spawn: make a new cage.

## Reading everything except secrets

A policy that reads `/` reaches the paths of the `secrets`, `trust-handoff` and `persistence` classes, and other processes' `/proc` entries.

- On **T1** the class paths that exist at spawn are masked.
- On **T2** a hidden path (an `Access::Hide` rule, or the secrets class) that no write rule reaches is kept out by granting the trees around it entry by entry, as listed at spawn: entries added later on the way are denied, the directories on the way cannot be listed, symbolic links on the way are not followed, and `stat` of the hidden path still works.
- A hidden or protected path **inside a writable tree** cannot be kept out on T2, and a write grant bound around one fails the spawn.

Each of these is an approximation accepted with `LowerOptions::accept_spawn_snapshot()`. Without a PID namespace, a rule or grant that reaches `/proc` beyond `/proc/self` and `/proc/thread-self` (on `/` or `/proc`, through a symbolic link to them, or a grant bound to such a path) exposes other processes' arguments, though not their environment (R-25): the approximation `proc-other-processes`, accepted only by name (`LowerOptions::allow(Construct::ProcOtherProcesses)`).

Looking for class paths under writable trees walks them; a tree with more entries than `CageOptions::walk_limit` (200,000 by default) fails the spawn with `SpawnError::Walk` rather than going unchecked.

## Unix sockets

`ipc.unix_sockets` allows `AF_UNIX` sockets when the network is off or `Network::Ip`. From ABI 9 Landlock enforces it exactly on both tiers: a pathname socket outside the allowed paths cannot be connected to, abstract sockets are scoped to the run, and the D-Bus, systemd and engine sockets need no cover. With `Network::All`, every pathname socket stays reachable, on every ABI. On T1 below ABI 9, abstract sockets stay inside the cage's network namespace, and every listening socket outside the allowed paths, as listed in `/proc/net/unix` at spawn, is masked; sockets bound later stay reachable (an approximation accepted with `accept_spawn_snapshot()`). With `Network::Ip` there is no network namespace, so on T1 abstract sockets are kept out by the scope from ABI 6 and the setting is refused below it. T2 below ABI 9 cannot restrict pathname sockets and refuses the setting.

The D-Bus, systemd and container-engine sockets are kept out by the [socket classes](@/docs/hard-deny.md#the-socket-classes).

## What the tests observe

The tests (`tests/spawn_linux.rs`, `tests/escape_linux.rs`) run in containers on tier T1 (seccomp unconfined) and tier T2 (Docker's defaults), with T2 also forced on the T1 host; the [threat model](@/docs/threat-model.md) lists the canaries per escape class. Beyond those:

- a denied file access fails with "permission denied" (macOS says "operation not permitted");
- on T1 a protected subtree is a read-only file system that neither `umount` nor a read-write remount undoes;
- on T1, 1,000 spawns of a policy with every mount kind, from four threads while four others allocate and lock, all run caged;
- with the Landlock ABI capped at 1, 2, 3 and 5, on both tiers, writes stay in the workspace, the network is off, `ptrace` is refused and no file outside the writable paths can be truncated.

## Limits

- No PID namespace or private `/proc`: keeping signals within the run needs Landlock ABI 6, and reaching other processes' `/proc` entries is an [approximation](#reading-everything-except-secrets).
- With `Lifetime::Tree`, a descendant that double-forks into a session of its own outlives the run.
- No loopback networking: a gap on both tiers. Proxy-only networking needs T1 and a [proxy of the cage's own](@/docs/proxy.md); it is a gap on T2.
- Protect, and hide inside a writable tree, are gaps on T2; glob rules are gaps on both tiers.
- Below Landlock ABI 2 no file moves or links between directories (`EXDEV`). From ABI 2 they do within the writable trees and the run's `TMPDIR`; Landlock refuses a move that would give a file a right it lacks, or take it out of a read-only tree.
- The probe is cached per process, not per boot.
- Case-folding directories (ext4 `casefold`) are untested: no lane has one. Landlock rules and the T1 mounts follow inodes, not spellings; how the data-class names found at spawn match in such a directory is not measured.

## Options

| `CageOptions` | Purpose |
|---|---|
| `with_lower(LowerOptions)` | Lowering options: accepted approximations, rule limit |
| `with_tier(Tier)` | Ask for T1 or T2 instead of the strongest available |
| `with_landlock_abi(u8)` | Behave as on an older kernel |
| `with_home(path)` | One more home directory for the data-driven classes |
| `with_runtime_dir(path)` | One more runtime directory for the socket classes |
| `with_walk_limit(usize)` | Entries one spawn may visit looking for class paths under writable trees |
| `with_violations()` | [Violation reports](@/docs/violations.md) |
| `with_link_audit(LinkAudit)`, `with_link_exemption(path)`, `with_handoff_audit()` | [Audits](@/docs/audits.md) |
| `with_policy_in_receipt()` | The policy in each [receipt](@/docs/receipts.md) |

## Violation reports

With `CageOptions::with_violations`, every system call the seccomp filter refuses is reported exactly, on both tiers and without privileges; Landlock's file, network and signal denials are not. See [Violations](@/docs/violations.md#how-it-works-on-linux).
