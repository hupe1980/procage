# Quickstart: validating grant on denial

```sh
cargo test -p procage --lib suggest                       # the derivation table
cargo test -p procage-policy --lib suggest                # apply, weakens, covers
cargo test -p procage --test suggest_macos                # macOS kernel
just linux-t1 && just linux                               # spawn_linux: a_refused_call_suggests_its_class_waiver
```

## Measured (2026-11-03)

| Denial | Suggestion | Respawn | Neighbour | Diff |
|---|---|---|---|---|
| macOS: read outside the policy | `Allow` read, literal | reads | sibling still denied | the rule and the base's metadata reads on its way |
| macOS: create a file outside | `Allow` write, literal | creates | sibling still denied | same |
| macOS: exec a script outside | `Allow` exec, literal | runs | — | same |
| macOS: connect to a Unix socket | `UnixSocket` | connects | — | loosens only |
| macOS: write under a protect rule | `LeaveOut` (weakens) | writes | — | the rule and its rename anchors |
| macOS: read a hidden file | `LeaveOut` (weakens) | reads | — | the rule |
| macOS: write `.git/hooks` | `Waive(trust-handoff)` (weakens) | writes; the receipt lists the waiver | — | the class |
| macOS: list `~/Library/Keychains` | none (`secrets`) | — | — | — |
| Linux T1, T2: `ptrace` | `Waive(process-access)` (weakens) | no longer refused | — | — |
| Linux T1, T2: `socket` family, `setsid` under `Lifetime::Run` | none | — | — | — |

macOS 26.6.2; Linux 7.0 (container), Landlock ABI 8. The old policy still
denies after each apply: nothing widens a cage in place.
