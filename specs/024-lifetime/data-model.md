# Data model: Lifetime

## `procage_policy::Lifetime` (new, in `Process`)

| Variant | Serialized | Meaning |
|---|---|---|
| `Run` (default) | `"run"` | Every process the child starts belongs to the run until it ends. Linux: `setsid`/`setpgid` → `EPERM`. macOS: found by marker. |
| `Tree` | `"tree"` | Programs may start sessions and groups. Linux: the run kills the child's group and the descendants found from the child (R-23 residual). macOS: as `Run`. |

- `Process { exec, fork, signals, lifetime }`; `#[serde(default)]` already on
  `Process`, so older documents parse with `Run`.
- Only meaningful with `fork: true`; with `fork: false` neither the lock nor
  the marker is emitted and the ledger reports nothing for lifetime.

## Ledger constructs (new)

| Construct | Name | Linux | macOS |
|---|---|---|---|
| `LifetimeRun` | `lifetime-run` | Exact (seccomp lock) | Exact (marker block) |
| `LifetimeTree` | `lifetime-tree` | Exact | Exact (marker block; stricter than asked) |

## Seccomp syscalls (new variants)

`Syscall::Setsid` (`"setsid"`), `Syscall::Setpgid` (`"setpgid"`); numbers in
`src/linux/seccomp.rs` for x86_64 and aarch64.

## macOS marker block (lowering output, last block of the profile)

```
(deny mach-lookup (global-name-prefix (param "procage-run-prefix")))
(allow mach-lookup (global-name (param "procage-run-marker")))
```

Constants in `procage_policy::lower` (`RUN_PREFIX_PARAM`, `RUN_MARKER_PARAM`);
the plan's `params` list does not carry them (the backend binds them per spawn).

## Run marker (backend, `src/macos/lifetime.rs`)

- **Prefix**: `org.procage.run.<pid hex>.<random hex>.` — once per process.
- **Slot**: `u32`, lowest free; states: free → in use (spawn) → free (clean
  kill) | retired (detach, failed final kill, failed spawn after fork is
  impossible: a failed spawn frees it).
- **Marker** = prefix + slot (decimal); **probe** = prefix + `probe`.
- **Validation**: names are ASCII `[0-9a-z.]`, never input-derived.

## `Child` (macOS) additions

- `run: Option<Run>`: the slot, present when the policy allows forking.
- `kill_all`: walk + group kill (as before), then rounds of marker scan +
  SIGKILL (≤ 64), then wait for the child. Survivors → `Err` (kind `Other`,
  message lists pids), run kept. Clean → slot freed, `run = None`.
- `detach`: retires the slot.
