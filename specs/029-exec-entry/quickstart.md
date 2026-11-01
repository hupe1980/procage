# Quickstart: validate the exec entry

1. `cargo test -p procage --test exec` (macOS).
2. `just linux` / `just linux-t1` with `--test exec` (Linux T2, T1 + T2).
3. `cargo run --example exec_helper -- "$PWD/target" -- /bin/sh -c 'echo hi > "$0"/x; echo hi > ~/x' "$PWD/target"`.
4. `just ci`.

## Recorded outcomes (2026-10-31)

- macOS 26.6.2: `tests/exec.rs` 6/6 (pid identity + inside/outside write +
  exit 7; env_clear keeps a secret out under passthrough; group kill with
  the helper *not* leading the group ends command and background sleeper;
  threaded helper execs; tmpdir grant and missing program refused, process
  unconfined afterwards). Negative control: with the session step set to
  `New` instead of `Keep`, the group-kill case fails (the command survives).
- Linux T2 (9/9) and T1 (18/18, T1 and T2 cages): the cases above plus
  `setsid` refused for a descendant (`setsid=1`), the command dies with the
  helper's parent, and a two-thread caller refused on T1 (`ExecThreads`)
  while a threaded helper execs on T2. Lib 22, spawn 27, escape 19, native
  3. Linux clippy, rustdoc, doctests clean.
- Example: `exec_helper <tmp> /bin/sh -c …` printed the helper's pid,
  `in=ok`, `out=denied`, exited 3; a missing program gives exit 126 and
  "program no-such-program not found in /usr/bin:/bin (the command's
  environment has no PATH: set one on the command, or name the program by
  its path)"; no arguments gives the usage and exit 2. 13 procage-specific
  lines (SC-002).
- `just ci`: all 10 gates (the example is built and linted).
