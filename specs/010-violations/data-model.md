# Data model: 010-violations

| Entity | Fields | Rules |
|---|---|---|
| `DenyReason` (policy) | `HardDeny(class)`, `Protect`, `Hide`, `Layer` | `from_code(code())` round-trips; codes contain no space or newline |
| `Violation` | pid, process, operation, target, denied_by, received | built only from a line whose last line is a live run's exact marker |
| `DeniedBy` | `NotGranted` (no code), `HardDeny`, `Protect`, `Hide`, `Layer`, `Unknown(code)` | an unknown code is kept, not dropped |
| `Coverage` | `Off`, `Observed`, `Unavailable(reason)`, `NotObserved` | `Off` without the option; `NotObserved` on Linux |
| `Violations` (record) | list (≤ 10,000), complete, coverage, dropped | complete only after a fence following the child's exit |
| Run sink (internal) | marker, record, optional bounded sender (1,024) | registered before the fork; removed after the slot's fence |
| Monitor (internal, one per process) | helper child, stdin pipe, reader thread, sinks by marker, fence counter, state (`Starting`, `Ready`, `Down(reason)`) | restarts on the next spawn after `Down` |

State of a run record: `Collecting` → (child exited, fence seen) →
`Complete`; any `Down` or fence timeout → stays incomplete, with the
coverage reason updated to `Unavailable` when the stream died.

Slot release: `kill_all` → marker search → fence (≤ 1 s) → free; timeout →
retire the slot (never reused), as `detach` does.
