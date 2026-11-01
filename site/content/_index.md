+++
title = "procage"
description = "procage cages child processes that run untrusted, adaptive code (LLM agents, build scripts) on macOS (Seatbelt, without sandbox-exec) and Linux (Landlock, seccomp, namespaces). One typed policy, lowered per OS, never silently weaker."
template = "index.html"
+++

```rust
use std::process::Command;
use procage::native::{Cage, CageOptions, Grants};
use procage::policy::{presets, AbsPath, LowerOptions};

// Read the workspace; no writes, no network. Secrets,
// git hooks and launch agents are denied in any policy.
let workspace = AbsPath::new("/path/to/project")?;
let policy = presets::agent_readonly::v2(&workspace);

let options = CageOptions::default()
    .with_lower(LowerOptions::default().accept_spawn_snapshot());
let cage = Cage::with_options(&policy, &options)?;

let mut child = cage.spawn(
    Command::new("/usr/bin/grep")
        .args(["-rn", "TODO", "."])
        .current_dir("/path/to/project"),
    &Grants::new(),
)?;
let status = child.wait()?;
// Dropping `child` kills every process the run started.
```

A preset, prepared once and spawned. Linux hosts that cannot enforce part of it refuse with a list of gaps.
