# Quickstart: checking 025

```sh
cargo test -p procage-policy --all-features   # class rules, fixtures, /proc reach
just escape                                   # macOS escape suite: default, with reporting, base V3 with reporting
just linux && just linux-t1                   # Docker, tiers T2 and T1
just ci
```

## Results, 2026-11-02

| Lane | Result |
|---|---|
| macOS 26.6.2 (25G83), outside any sandbox | `cargo test --workspace` and `cargo test -p procage-policy --all-features` green; preset fixtures v1–v3 regenerated (+3 lines each); `just escape` green in all three variants, `r25_other_processes_arguments_are_unreadable` passes (other process's `KERN_PROCARGS2`, `KERN_PROCARGS`, pidinfo EPERM; own and own child's readable; readable with `ProcessAccess` waived) |
| Docker Linux 7.0.14 aarch64, T1 and T2 | `escape_linux` 31 passed + 1 open (R-26) on both tiers; `r25_other_processes_are_opaque` and `r25_proc_through_a_link_or_a_grant_is_an_approximation` pass (rule, symbolic link and grant refused unless accepted; accepted: plan or receipt lists it, environ EACCES, cmdline readable) |

Findings during implementation:

- Seatbelt does not report `sysctl-read` denials: a deny is enforced (EPERM)
  but never logged; the canary's EPERM is the measurement.
- `ps` is setuid (refused in any cage) and `pgrep` needs `sysmond`: limits,
  not tested.
- On Linux, a policy that reads `/` now needs `proc-other-processes` by name
  (the documented reading-everything recipe and the reference harness policy
  in the tests accept it).
