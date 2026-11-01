# Contract: lifetime

## Policy

```rust
pub enum Lifetime { #[default] Run, Tree }
pub struct Process { pub exec: Exec, pub fork: bool, pub signals: Signals, pub lifetime: Lifetime }
```

JSON: `"process": { "fork": true, "lifetime": "tree" }`; absent → `"run"`.

## Behaviour per system (fork allowed)

| | `Run` | `Tree` |
|---|---|---|
| Linux `setsid()`, `setpgid()` in the cage | `-1`, `EPERM` | allowed |
| Linux run end | `killpg(child)` reaches every descendant, before or after the child exits | group + descendants found from a living child |
| macOS `setsid()` | allowed | allowed |
| macOS run end | every process whose sandbox allows the run marker, wherever it was reparented | same |

## Handle (`macos::Child`, `linux::Child`)

- The run ends at `kill_all()` or drop. A child that exits by itself does not
  end the run.
- `kill_all() -> io::Result<()>`: `Ok` only when no live process of the run
  was found after killing (macOS: after the last scan; Linux: after the
  group kill). macOS: after 64 rounds that still find live processes, `Err`
  with kind `Other` and the message
  `processes of the run survived: [<pid>, …]`.
- `detach()`: the run's processes keep running; on macOS their marker is
  never given to another run of this process.

## Cost

- macOS forking run: one extra scan per round at run end (~2 ms per 700
  processes); repeated spawns of one policy compile once.
- Linux: two extra seccomp rules; no run-end cost.
