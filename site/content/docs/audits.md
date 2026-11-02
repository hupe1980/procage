+++
title = "Audits: hard links and what a run left behind"
description = "Before every spawn procage refuses a protected, hidden or credential file with a second name outside the protected set; with the handoff audit, Child::audit lists the trust-handoff files, symbolic links and repositories a run created or changed."
weight = 78

[extra]
group = "Guides"
nav = "Audits"
+++

Path rules see names. Two things slip past them: a **hard link** that gives a protected file a second name, and a file the child writes that a program **outside** the sandbox later runs or follows.

## Hard links (before every spawn, on by default)

A protected or hidden file with another name can be written or read through it (R-08). The other name may lie anywhere, but the file's link count shows it. Before every spawn (and every `Cage::exec`) procage examines the policy's protect and hide targets and the files of the secrets, trust-handoff and persistence classes. When one has a name outside that set, or a literal target has become a symbolic link, the spawn is refused:

```rust
use procage::native::{Cage, CageOptions, SpawnError};
use procage::LinkAudit;

match cage.spawn(&mut command, &grants) {
    Err(SpawnError::HardLinks(found)) => eprintln!("refused: {}", found[0]),
    other => { /* … */ }
}
// Or: list them instead of refusing.
let options = CageOptions::default().with_link_audit(LinkAudit::Report);
```

Names that all lie inside the protected set are not findings (GnuPG's lock files, for example). Large application data and privacy-guarded folders (browser profiles, Mail, Messages, Safari, Cookies) are not examined. A second name cannot be made during the run: Seatbelt refuses to link a file the child cannot write, and Landlock never grants linking across directories. `LinkAudit::Off` turns the check off.

## What a run left behind (after the run, opt-in)

Trust handoff (R-07) is a program outside the sandbox running or following what the child wrote. procage denies writes to the known locations; where that cannot hold (a file that did not exist at spawn on Linux, a symbolic link your harness would follow), the handoff audit reports it:

```rust
let options = CageOptions::default().with_handoff_audit();
let mut child = Cage::with_options(&policy, &options)?.spawn(&mut command, &grants)?;
child.wait()?;
for finding in child.audit().unwrap().handoff.unwrap_or_default() {
    println!("{finding}"); // ".vscode/settings.json created", "build -> /etc/passwd", …
}
```

It notes before the run the trust-handoff files, symbolic links and `.git` directories of the writable trees, and lists after it what was **created**, **modified**, **linked** or a new **repository**. It walks the trees twice, so it is opt-in. `Child::audit` is `None` until the child exits, and reading it ends the run.

Both audits stay on one device, never follow a link and stop at the walk limit (`CageOptions::with_walk_limit`, default 200,000); past it the result says it is incomplete, never clean. Receipts carry the counts, and the paths only with the policy included.
