# Research: Consumer API before the freeze

## R1 — Observing `env_clear`

- std 1.99 has no getter (`get_envs` is empty after `env_clear`; checked in
  `library/std/src/process.rs`).
- `impl Debug for Command` (unix), alternate form, prints
  `env: CommandEnv { clear: <bool>, vars: {…} }` when the environment was
  changed and omits `env` when it was not
  (`library/std/src/sys/process/unix/common.rs`, `sys/process/env.rs`).
- Measured with rustc 1.99.1: `{:#?}` puts `env: CommandEnv {` and
  `clear: true,` on their own lines; argument and value strings are quoted
  and escaped on one line, so an argument `"\n        clear: true,\n"` and a
  value `"x\nclear: true,"` print as quoted single lines.
- **Decision**: after the trimmed line `env: CommandEnv {`, the next trimmed
  line must be `clear: true,` or `clear: false,` (else unknown); no `env`
  field → not cleared. Self-check once per process: cleared probe → true,
  changed-not-cleared probe → false, unchanged probe → false. Any other
  outcome → the observer is unusable for this process.
- **Alternatives**: refusing passthrough when the command sets variables
  (breaks "explicit wins", used by procage's own tests via `PROCAGE_CHILD`);
  removing passthrough (a larger behaviour change); docs only (already done,
  did not prevent the leak).

## R2 — Where the decision changes

- `crate::unix::environment(command, policy)` is the only caller of
  `hygiene::environment` on both backends. Cleared → caller vars = empty;
  the pure function and its tests stay as they are.
- macOS: move the call before `run_and_bytecode`.

## R3 — Common subset

Both modules export `Cage::{new, with_options, spawn, spawn_with_fds}`,
`CageOptions::{default, with_lower}`, `Grants::{new, bind}`,
`Child::{kill_all, detach, dropped_env, tmpdir}`, `SpawnError: Display`
with matching signatures (checked by reading both). A module alias is
enough; no trait.

## R4 — Spawn-time masks

The three data-driven classes are the only constructs whose Linux T1
outcome is "masked at spawn" (lowering table rows `hd-secrets`,
`hd-trust-handoff`, `hd-persistence`). One method inserts exactly those.
