+++
title = "Explain and diff: why a path is denied, and what a change allows"
description = "Cage::explain names the rule that allows or denies reading, writing or executing a path, and the narrowest change that would allow it; explain::diff lists what one policy allows that another does not."
weight = 76

[extra]
group = "Guides"
nav = "Explain and diff"
+++

`Cage::explain` answers, for one path, whether a child of the cage may open it for reading, open it for writing or execute it, which rule decides, and what would change a denial. The answer comes from the cage's plan, without running anything.

```rust
use procage::native::{Cage, Grants};
use procage::policy::explain::{Decision, Op};

let answer = cage.explain(Op::Write, "/Users/me/project/.git/hooks/pre-commit", &Grants::new())?;
assert_eq!(answer.decision, Decision::Denied);
println!("denied by {:?}", answer.by);            // HardDeny(TrustHandoff)
if let Some(remedy) = answer.remedy {
    println!("would need {:?}", remedy.changes);  // [Waive(TrustHandoff)]
}
```

## Proven operations

`explain` models exactly the operations procage's oracle suite proves on every target. On each CI lane the suite asks every preset and a policy with every rule kind more than 1,000 questions about a generated tree, of the explainer and of the kernel (a caged child that opens each file, and caged spawns of copies of `true`), and fails on any disagreement.

| Operation | macOS | Linux T1 | Linux T2 |
|---|---|---|---|
| `read` | proven | proven | proven |
| `write` | proven | proven | proven |
| `exec` | proven | proven | proven |

`read` is opening a file for reading, `write` opening an existing file for writing, `exec` executing a file. Any other operation answers `NotModelled`, and so does a rule the evaluator cannot read for the operation asked; neither is ever a guess.

## What an answer holds

- `decision`: `Allowed`, `Denied` or `NotModelled`.
- `by`: the deciding rule: a file rule of the policy (an allow, a protect or a hide rule), a grant, a hard-deny class, the base profile, the raw layer, a setting, or the default deny. On Linux, `Unhandled` means Landlock does not handle the right (`Exec::Any`).
- `caveat`: set when the answer holds only for what existed at spawn: on tier T1 the class covers are mounted over the paths found then; on tier T2 the tree around a hidden path is granted entry by entry as listed then.
- `remedy`: for a denial, the narrowest change that allows it: a literal rule for the path asked, a waiver when a hard-deny class decides, or removing the deciding protect or hide rule (up to three, in order). It is offered only after lowering the changed policy confirms it, lists any approximation the change needs accepted, and carries the change's `diff`, so it names everything else the change allows.

`Cage::explain` resolves symbolic links in the path, reads the file's mode (set-user-ID files are denied on macOS), binds the grants as a spawn would, and on Linux uses the cage's homes. The grant of the private temporary directory is left out: its path exists only during a run. Without a cage, `procage::policy::explain::Explainer` takes a canonical path and a `Context` of grants and homes; a path that is not canonical (`/a/../b`, or `/etc/hosts` on macOS) is an error naming its canonical form.

An answer names the policy's rules. Show it to the user deciding about the policy; do not relay it into the cage unfiltered.

## Diff

`explain::diff(&old, &new, &targets, &options)` lists, per target, every rule one plan has and the other lacks, with its operations, its paths, where it comes from, and whether it loosens (an added allow, a removed deny) or tightens. Every other difference (the base, the preset version, waivers, network, hygiene and the like) is listed as a changed setting. Any question whose answer differs between the two policies is covered by an entry with the right direction.

```rust
use procage::policy::explain::{Direction, diff};

let d = diff(&presets::build::v2(&root), &presets::build::v3(&root), &[Target::MacOs], &LowerOptions::default())?;
for e in d.entries.iter().filter(|e| e.direction == Direction::Loosens) {
    println!("{:?} now allows {:?} on {:?}", e.by, e.ops, e.paths);
}
```
