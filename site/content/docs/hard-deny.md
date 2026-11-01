+++
title = "Hard-deny classes"
description = "The twelve hard-deny classes procage emits last in every policy (secrets, trust handoff, persistence, privilege, process access, terminal injection and more), how to waive one by name, and how Linux tiers enforce them."
weight = 40

[extra]
group = "Policies"
nav = "Hard-deny classes"
+++

Some things a caged child should never do, whatever the rest of the policy says: read your SSH keys, plant a git hook your shell will later run, register a launch agent. procage puts these in a **hard-deny tier** that every policy carries. On macOS it is emitted last in the profile, after every allow, so no allow rule can override it. A class can be removed only by naming it in `Policy::waive`, and every waiver is listed in the plan.

```rust
use procage::policy::{presets, AbsPath, HardDenyClass};

let workspace = AbsPath::new("/path/to/repo")?;
let mut policy = presets::agent_workspace::v3(&workspace);
// `git init` and `git clone` write hooks and config: allow exactly that class.
policy.waive.insert(HardDenyClass::TrustHandoff);
```

## The classes

| Class (name) | Denies | Platforms |
|---|---|---|
| `fcntl-modify` | `fcntl` commands that modify a file through a read-only descriptor | macOS |
| `privilege` | setuid and setgid writes and execution; on Linux `no_new_privs`, always set | macOS, Linux |
| `service-handoff` | Handing work to unsandboxed services: Launch Services, Apple events, the pasteboard, XPC service lookups | macOS |
| `process-access` | Task ports, process information outside the sandbox, signals to others; on Linux `ptrace`, `process_vm_*`, `pidfd_getfd`, `kcmp` | macOS, Linux |
| `rename-anchors` | Renaming a writable root or an ancestor of a protected or hidden path | macOS, Linux |
| `terminal-injection` | Pushing keystrokes into a terminal (`TIOCSTI`, `TIOCLINUX`) | macOS, Linux |
| `kernel-surface` | io_uring, `bpf`, `perf_event_open`, `userfaultfd`, keyrings | Linux |
| `namespaces` | Creating or entering namespaces, mount system calls | Linux |
| `socket-families` | `AF_VSOCK` and `AF_NETLINK` sockets, which bypass socket and file filters | Linux |
| `secrets` | Reading and writing credentials and private data in every home | macOS, Linux |
| `trust-handoff` | Writing files an unsandboxed tool later runs or reads as configuration; removing or renaming `.git` | macOS, Linux |
| `persistence` | Writing launch agents, launch daemons and login items (macOS); autostart entries, systemd units and cron directories (Linux) | macOS, Linux |

The threat model tracks the escapes these classes answer, such as terminal input injection (R-22) and work handed to unsandboxed services (R-06), each with caged canaries as evidence.

## The data-driven classes

`secrets`, `trust-handoff` and `persistence` are lists of paths (version 1), case-folded on macOS:

- **secrets**, in every home: `.ssh`, `.aws`, `.gnupg`, `.kube`, `.netrc`, `.git-credentials`, `.pypirc`, `.docker/config.json`, `.cargo/credentials.toml`, `.config/gcloud`, `.config/gh`; on macOS also the Keychains, browser profiles, Cookies, Mail, Messages and Safari; on Linux also browser profiles, `.local/share/keyrings` and `.password-store`.
- **trust-handoff**, in any directory: `.git/hooks`, `.git/config`, `.gitmodules`, `.gitconfig`, shell startup files (`.bashrc`, `.zshrc`, `.profile`, …), `.envrc`, `.npmrc`, `.cargo/config.toml`, editor and agent directories (`.vscode`, `.idea`, `.cursor`, `.claude`, `.codex`, `.mcp.json`); in every home: `.cargo/bin`, `.local/bin`, `.ssh/config`. Objects, refs, the index and the working tree stay writable.
- **persistence**: `Library/LaunchAgents` and `Library/LaunchDaemons` in every home and system-wide, and login items (macOS); `.config/autostart`, systemd user units, `/etc/systemd/system`, `/etc/cron.d`, `/var/spool/cron` and `/etc/xdg/autostart` (Linux).

On macOS homes are the directories under `/Users`; on Linux `/root`, every directory under `/home`, `$HOME`, and any you add with `CageOptions::with_home`. The authoritative lists are the constants in `procage_policy::presets`.

## How Linux enforces them

Landlock cannot deny inside a tree it allows. So:

- Where **no rule** of the policy can reach a class's paths, Landlock's default deny enforces the class exactly.
- Where one can, **tier T1** masks the paths that exist at spawn (trust-handoff and persistence paths become read-only, secrets unreadable) and pins every existing `.git` under writable trees. This is an approximation, because paths created later are not covered; accept it with `LowerOptions::accept_spawn_snapshot()`.
- **Tier T2** cannot enforce a class a write rule reaches; the policy is refused unless the class is waived. Secrets reached only by read rules are hidden by granting the trees around them entry by entry (an approximation accepted the same way). A grant bound to a path that reaches a class path is refused at spawn.

## What remains the harness's job

The trust-handoff lists cover known locations. Anything else the child writes, such as project build scripts, generated code or files outside these lists, may later be run or trusted by an unsandboxed program. The calling harness must treat everything the sandbox wrote as untrusted before it uses it (escape class R-07, disposition `harness`).
