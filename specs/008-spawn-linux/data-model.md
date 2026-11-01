# Data model

- **Probe** `{ tier: Option<Tier>, landlock_abi: u8, errata: u32, userns: Result<(), i32> }` — per process; `tier` None means unsupported.
- **ClassPaths** (policy crate) `{ class, hide: bool, home: Vec<String>, anywhere: Vec<String>, system: Vec<AbsPath>, pin_git: bool }` — one per data class in force in a `LinuxPlan.classes`; `hide` true for secrets (mask), false for read-only.
- **Mount** (policy crate) `ReadOnlyBind | Mask | PrivateDevShm | Pin(AbsPath)` — `Pin` added for `.git`.
- **ChildMount** (backend) `Bind { path, recursive } | Remount { path, flags } | Tmpfs { path, flags, data } | DevNull { path }` — CStrings built in the parent.
- **ChildPlan** (backend) — session flag, parent pid, T1 flags + id map bytes + mounts, limits, keep fds, ruleset fd, BPF program, all owned by the parent's closure.
- **SpawnError** adds `Walk { root, limit }` and `Grant(GrantError::CoversClass { name, class })`; `Unsupported` gains `Tier`, `Landlock`, `Syscall`.
