# Data model: `Exec::Never` and `Exec::Program`

## `Exec` (policy, `procage-policy`)

| Variant | serde | Meaning |
|---|---|---|
| `Granted` (default) | `granted` | unchanged: where an `Exec` rule, grant or the base allows |
| `Any` | `any` | unchanged |
| `Never` | `never` | the program only, no exec after start (macOS: the program may execute itself again) |
| `Program` (new) | `program` | the program only, as often as it likes |

Validation: `Never` and `Program` with any `Exec` rule or grant →
`PolicyError::ExecConflict`.

## Program allowance (per spawn, not stored)

| Field | Source | Rules |
|---|---|---|
| program | `find_program(command)` after the environment is final, canonicalised | regular file, an exec bit; first bytes `#!` → `SpawnError::Script` |
| interpreter (Linux) | `PT_INTERP` of the program | absolute, regular file, else `SpawnError::Interpreter`; none for a static program |

Lifetime: one spawn. macOS: an extension token of class
`procage.exec.program` for `program`. Linux: Landlock file rules
(`READ_FILE | EXECUTE`) on descriptors opened in the parent for `program`
and `interpreter`.

## Linux plan additions

- `RuleTarget::Program` — resolved per spawn to the allowance's files.
- `Syscall::{Execve, Execveat}`, `Action::Supervise`, `DenyReason::Exec`
  — under `Never`, both calls `Supervise`.

## Run supervisor states (Linux, a run with a listener)

```text
Waiting  --handover(listener, sentinel?)--> Serving
Waiting  --spawn returned, nothing sent-->   Ended (reporting: Unavailable)
Serving: Supervise notification: sentinel open -> CONTINUE
                                 sentinel hung up -> EPERM (+ record)
         other notification     -> EPERM (+ record)
Serving  --listener hung up-->              Ended (record complete)
```

## Constructs and outcomes

| Construct | macOS | Linux |
|---|---|---|
| `exec-never` | exact | exact; `Approximated` (backend gap) with no supervisor or with `Cage::exec` |
| `exec-program` (new) | exact | `Approximated` (lowering) |
