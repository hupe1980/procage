# Quickstart: validate the consumer API

1. `cargo test -p procage --lib unix` — observer and decision unit tests.
2. `cargo test -p procage --test spawn_macos env_clear` and
   `--test native` on macOS.
3. `just linux` and `just linux-t1` (include `--test native` and the Linux
   env_clear test).
4. `cargo test -p procage-policy --test gaps spawn_masks`.
5. `just ci`.

## Recorded outcomes (2026-10-31)

- Baseline: lib 9 passed.
- macOS 26.6.2: lib 13 (observer self-check, values cannot fake a clear,
  unknown shape, fail-closed decision); `spawn_macos`
  `env_clear_keeps_the_caller_environment_out` passes (passthrough and
  allowlist both give `A,PROCAGE_CHILD`); negative control without honouring
  the clear: the child got the whole caller environment (~90 names);
  `native` 3/3; `procage-policy` `gaps` spawn-masks test passes.
- Linux T2 and T1 (Docker): lib 21, `native` 3/3, `spawn_linux` 27 incl.
  the env_clear test, `escape_linux` 19 (2 ignored), `unsafe_confined` 2;
  Linux clippy (`-D warnings`) and rustdoc clean.
- `just ci`: all 10 gates.
