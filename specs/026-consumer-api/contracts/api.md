# Contract: consumer API

## Environment

| Command | Allowlist(names) | Passthrough { deny } |
|---|---|---|
| no `env_clear` | named caller vars + set vars | caller vars − deny − default denylist + set vars |
| `env_clear` | set vars only | set vars only |
| `env_clear` unobservable | as without `env_clear` | `SpawnError::Unsupported(Unsupported::EnvClear)` before fork |

`env_remove` removes from the result in every case; procage adds `TMPDIR`
for the `tmpdir` grant unless the command set it.

## `procage::native`

`procage::macos` on macOS, `procage::linux` on Linux.

## `LowerOptions::accept_spawn_masks`

Accepts `hd-secrets`, `hd-trust-handoff`, `hd-persistence` approximations;
nothing else.
