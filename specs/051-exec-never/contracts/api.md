# Contract: public API changes (0.8.0)

## Rust — `procage-policy`

```rust
pub enum Exec { Granted, Any, Never, Program }      // + Program (serde "program")
impl Exec { pub fn program_only(self) -> bool; }   // + Program or Never

pub enum Construct { /* … */ ExecNever, ExecProgram }   // + "exec-program"

pub mod linux {
    pub enum Syscall { /* … */ Execve, Execveat }        // non_exhaustive already
    pub enum Action  { Eperm, Enosys, Supervise }        // + Supervise
    pub enum RuleTarget { /* … */ Program }              // + Program
}
pub enum DenyReason { /* … */ Exec }                     // code "exec"

#[doc(hidden)]
pub mod elf {
    pub fn interpreter(file_start: &[u8]) -> Result<Option<&[u8]>, ElfError>;
}
```

Breaking for exhaustive matches on `Exec`, `Action`, `RuleTarget`,
`DenyReason`: minor version (0.8.0), migration note.

## Rust — `procage`

```rust
pub enum SpawnError {           // non_exhaustive already
    /* … */
    Script { program: PathBuf },                       // `#!` under Never/Program
    Interpreter { program: PathBuf, reason: String },  // Linux PT_INTERP unusable
}
pub enum DeniedBy { /* … */ Exec }                     // non_exhaustive already
```

Behaviour:
- `Cage::{spawn, spawn_with_fds, spawn_async*, exec*}` under
  `Never`/`Program`: resolve the program before forking; refuse a script.
- Linux `Cage::with_options` under `Never` without a supervisor, and
  `Cage::exec*` under `Never`: `SpawnError::Lower(LowerError::Gaps([
  exec-never Approximated ]))` unless `LowerOptions::allow(Construct::ExecNever)`.
- Linux `Exec::Program`: gap `exec-program` unless
  `LowerOptions::allow(Construct::ExecProgram)`.
- A gap's message ends with the accepting call, e.g.
  ``accept it with `LowerOptions::allow(Construct::ExecProgram)` (Python: allow=["exec-program"], Node.js: allow: ["exec-program"])``.

## Bindings

Python:

```python
Cage(policy, *, violations=False, relax=[], accept_spawn_snapshot=False,
     allow=[])                       # + allow: construct names
```

Node.js:

```ts
interface CageOptions { violations?; relax?; acceptSpawnSnapshot?;
                        allow?: string[] }   // + allow
```

Policy JSON: `"process": {"exec": "program"}`. A gap's `accept` lists
`allow=["exec-program"]` (Python) / `allow: ["exec-program"]` (Node.js).
Unknown construct names in `allow` are refused with `PolicyError`, as
unknown `relax` names are.
