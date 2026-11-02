+++
title = "Receipts: evidence of how a run was caged"
description = "Child::receipt gives, for every finished run, the policy digest, preset, backend and tier, OS build or kernel, everything accepted short of the policy, the violation summary and the exit: a record a harness can attach to a command's output."
weight = 77

[extra]
group = "Guides"
nav = "Receipts"
+++

A receipt records that a command ran caged, and in which cage. Once the child has exited, `Child::receipt()` returns a `Receipt` (`None` before). Reading it ends the run, as `kill_all` does, so its audit summary covers a finished run.

```rust
use procage::native::{Cage, Grants};
use procage::policy::presets;

let cage = Cage::new(&presets::minimal::v3())?;
let mut child = cage.spawn(&mut std::process::Command::new("/bin/ls"), &Grants::new())?;
child.wait()?;
let receipt = child.receipt().expect("the child exited");
std::fs::write("/var/log/my-harness/run-42.receipt.json", receipt.to_json())?;
```

## What a receipt holds

| Field | Meaning |
|---|---|
| `policy_digest` | `sha256:…` of the policy's canonical serialised form: equal policies have equal digests on every system |
| `preset`, `base` | The preset tag and base profile version |
| `backend` | macOS: apply method, OS release and build. Linux: tier, Landlock ABI and errata, kernel release |
| `approximations`, `relaxations`, `waivers` | Everything the cage accepted short of the policy; a relaxation says what would lift it |
| `enforced_as_written` | `true` only when all three lists are empty |
| `violations` | The record's coverage (`off`, `observed`, `system-calls`, `unavailable`), whether it was complete, and the count (absent when nothing was observed) |
| `exit` | The exit code or signal, and whether the caller ended the run (`kill_all`) |
| `audit` | The [audits](@/docs/audits.md)' mode, finding counts and completeness; their paths only with the policy included |
| `grants`, `procage` | The grant names bound for this run, and the procage version |
| `policy` | The policy itself, only with `CageOptions::with_policy_in_receipt()` |

## What a receipt is not

- **Not an attestation.** It is the caller's own unsigned record, built in the calling process. Keep it outside every path a later run may write.
- **Not proof that nothing was denied.** macOS violation reports are best effort, so a complete, empty record proves nothing. With reporting off the receipt says `off`, never "none".
- **Not anonymous.** It names the OS release and build or the kernel release of the machine.
- **Not for `Cage::exec`**, which leaves no handle.

## Privacy and format

A receipt holds no environment value, command argument, file content or process name. Paths appear only with `CageOptions::with_policy_in_receipt()`, which adds the whole policy, the subjects of relaxations and the audits' paths.

`Receipt::to_json` writes a versioned form (`"version": 1`); `Receipt::from_json` refuses another version and any unknown field, at any depth, rather than show a receipt it understood only in part.
