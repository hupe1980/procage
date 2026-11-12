# Quickstart: validating `Exec::Never` and `Exec::Program`

## Prerequisites

macOS 26 (arm64) for the macOS lanes; Docker for the Linux lanes
(`just linux` = T2, `just linux-t1` = T1).

## Scenarios

| # | Scenario | Command | Expected |
|---|---|---|---|
| 1 | Base exec gone under both settings | `cargo test -p procage --test escape_macos r38_` | sh cannot run `/bin/echo`, `/usr/bin/env`; `Exec::Granted` control runs them |
| 2 | Same on Linux, plus `ld.so` and re-exec under `Never` | `just linux` and `just linux-t1` (run `r38_*`) | every exec after the first fails `EPERM` |
| 3 | `Base::None` + `Never` starts the program | `cargo test -p procage --test spawn_macos exec_never_` / Linux lanes | program exits 0 |
| 4 | Script refused | same suites, `…_refuses_a_script` | `SpawnError::Script` before forking |
| 5 | Program re-executes itself | `…_program_reexecutes_itself` | macOS: runs; Linux: gap without `allow`, runs with it |
| 6 | No supervisor | Linux suites, outer listener test | gap `exec-never`; accepted → runs, receipt lists it |
| 7 | `Cage::exec` | `cargo test -p procage --test exec` | macOS runs; Linux gap unless allowed |
| 8 | explain agrees | `cargo test -p procage --test oracle` | every exec probe agrees for both settings |
| 9 | Lowering table | `cargo test -p procage-policy --test lowering_table` | rows `exec-never`, `exec-program` match |
| 10 | ELF reader | `cargo +nightly fuzz run elf -- -max_total_time=300` (in `crates/procage-policy/fuzz`) | no crash |
| 11 | Bindings | `bindings/python` pytest, `bindings/nodejs` test | `"program"` policy runs; `allow` accepts the gap |
| 12 | Cost | `cargo bench -p procage` (spawn benchmark, `exec-never` case) | ≤ +0.5 ms median over `Exec::Granted` |
| 13 | Everything | `just ci` (macOS) and `just ci-all` | green |

## Results, 2026-11-12

macOS 26.6.2 (25G83), Apple M4 Pro; Linux 7.0.14-linuxkit aarch64
(Landlock ABI 8) in Docker, tiers T1 and T2.

| # | Result |
|---|---|
| 1 | `r38_only_the_program_executes`, `r38_never_on_macos_lets_the_program_execute_itself_only`: pass, also with `PROCAGE_ESCAPE_VIOLATIONS=1` |
| 2 | `r38_only_the_program_executes`, `r38_never_refuses_every_exec_after_the_first` (self, `ld.so /bin/echo`, `exec` of the program: EPERM), `r38_the_program_holds_no_supervisor_descriptor`: pass on T1, T2 and T1 with reporting |
| 3 | macOS `Base::V1` + `Never`/`Program` start `/bin/echo` and `echo`; `Base::None` refused with a gap naming `Base::V1` (dyld aborts without a base, status 6). Linux `Base::None` and `V1` start the program on T1 and T2; async variant passes on both systems |
| 4 | `SpawnError::Script` before forking (both); `SpawnError::Interpreter` for a relative `PT_INTERP` (Linux) |
| 5 | macOS: the program re-executes itself, `/bin/echo` refused. Linux: gap naming `allow(Construct::ExecProgram)`; accepted: re-exec works, `/bin/echo` refused, receipt lists `exec-program` |
| 6 | outer listener: gap `exec-never` naming the accepting call; accepted: runs, other programs refused (Landlock), receipt lists `exec-never` |
| 7 | `exec_never_runs_the_command_and_nothing_else`: macOS runs; Linux T1/T2 refused without `allow`, runs with it |
| 8 | oracle: every exec probe agrees for `exec never/program` × V1/V3 on macOS (1,278 questions per policy), T1 and T2 (1,277) |
| 9 | lowering table: rows `exec-never`, `exec-program` match |
| 10 | `elf` fuzz target: 40,426,256 runs in 301 s, no crash |
| 11 | Python wheel 31/31 (macOS and `just python-linux`), Node.js package 26/26 (macOS) and 27/27 (`just node-linux`), with the `"program"` policy and `allow` |
| 12 | median spawn, cached cage → `exec never`: macOS 1.590 → 1.645 ms (+0.055); T1 1.199 → 1.299 ms (+0.100); T2 0.523 → 0.583 ms (+0.060): within +0.5 ms |
| 13 | `just ci` (macOS): every gate passes; `just kf-linux` (7 pass, 8 n/a), `just kf-linux-t1` (14 pass, 1 n/a), `just linux` and `just linux-t1`: every suite passes (the rename test retries `ETXTBSY`, which a file just written can return while a parallel test's child still holds it) |

Found during implementation and recorded in the spec: macOS needs a base
under both settings (dyld maps the system's code), and macOS `/bin/sh` is a
launcher that executes another shell, so it cannot be the program.
