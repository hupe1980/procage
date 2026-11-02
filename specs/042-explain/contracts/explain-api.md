# Contract: the explain API

## `procage_policy::explain`

```rust
let ex = Explainer::new(&policy, Target::MacOs, &LowerOptions::default())?;
let q = Question::new(Op::Write, "/work/.git/hooks/pre-commit");
let a = ex.explain(&q, &Context::default())?;
assert_eq!(a.decision, Decision::Denied);
assert_eq!(a.by, Decider::HardDeny(HardDenyClass::TrustHandoff));
assert_eq!(a.remedy.unwrap().changes, [Change::Waive(HardDenyClass::TrustHandoff)]);

let d = diff(&old, &new, &[Target::MacOs], &LowerOptions::default())?;
for e in &d.entries { /* e.target, e.direction, e.ops, e.paths, e.by */ }
```

- `explain` never touches the filesystem and never guesses: an operation
  outside `MODELLED`, or a rule it cannot evaluate on the asked operation,
  answers `NotModelled`.
- A non-canonical path is `ExplainError::NotCanonical` naming the
  canonical spelling (`/a/../b` → `/b`; on macOS `/etc/hosts` →
  `/private/etc/hosts`).
- `caveat` is set when the answer holds only for what existed at spawn.
- An answer names the policy's rules: it is for the user, not for the
  caged code.

## `procage::{macos,linux}::Cage::explain`

```rust
let a = cage.explain(Op::Read, Path::new("/home/me/.ssh/id_ed25519"), &Grants::new())?;
```

Resolves the path (`realpath` of the path, or of its parent for a missing
file), binds the grants as a spawn would, adds the homes on Linux, and asks
the cage's explainer. Errors: `ExplainError` via `SpawnError::Explain`, and
grant errors as for a spawn.
