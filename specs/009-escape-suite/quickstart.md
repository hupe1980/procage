# Quickstart: validating the escape suite

Prerequisites: macOS host outside any other sandbox; Docker Desktop.

1. `cargo test --test threat_model`: the gate and its defect tests pass.
2. `cargo test --test escape_macos`: every active canary passes.
   `cargo test --test escape_macos -- --ignored` shows the open variants
   failing and leaves no process behind.
3. `just linux` (T2) and `just linux-t1` (T1): `spawn_linux` and
   `escape_linux` pass. On T1, the R-28/R-29 canaries print
   `informative=true`.
4. `PROCAGE_EXPECT_TIER=T1 just linux` in the T2 container: tier mismatch,
   fails.
5. Defect injection (one at a time, reverted after):
   - (a) macOS: emit no `FcntlModify` rules → R-05 canary fails;
   - (b) macOS: drop the ServiceHandoff deny → R-06 fails;
   - (c) Linux: drop TIOCSTI from the seccomp rules → R-22 fails on both tiers;
   - (d) Linux: drop the AF_NETLINK/AF_VSOCK rule → R-28 fails;
   - (e) both: skip the fd sweep → R-21 fails.
6. `just ci` passes.

## Recorded outcomes

Recorded 2026-10-30, macOS 26.6.2 (25G83) arm64; Docker Desktop Linux
7.0.14-linuxkit aarch64, Landlock ABI 8.

| Suite | Lane | Active | Open (ignored) | Time |
|---|---|---|---|---|
| escape_macos | macOS host | 17 pass | 4 (R-08, R-23 double fork, R-25 procargs, R-26) all fail when run | 0.7 s |
| escape_linux | T2 (Docker default) | 15 pass | 3 (R-08 n/a on T2, R-23 double fork, R-26) | < 0.1 s |
| escape_linux | T1 (unconfined) | 15 pass | 3 fail when run (escape shown) | < 0.1 s |
| spawn_linux | T1, T2 | 26 pass each | — | — |
| threat_model gate | any | 26 pass | — | — |

Informative lanes: on T2 (Docker default) every R-28/R-29 control was
already refused by the host (`informative=false`); on T1 `unshare_user`,
`setns`, `io_uring_setup`, `socket_netlink` and `socket_vsock` were
informative. `clone3` returns ENOSYS caged and waived (the filter's ENOSYS
rule stays), so it is reported, not counted.

Findings during the run:

- R-25 macOS: `KERN_PROCARGS2` returns any same-user process's arguments and
  environment to a caged child; no SBPL rule tested blocks it (`deny
  sysctl-read`, `sysctl-name(-prefix)`, `process-info*`). Open variant.
- R-25 Linux: with `/proc` granted, the parent's `cmdline` is readable
  (no PID namespace); `environ` stays EACCES (Landlock ptrace scope).
- R-22 macOS: TIOCSTI is checked as `hid-control`; deny-default refuses it,
  the ioctl hard deny is a second layer. Canary tests both.
- R-22 Linux: Landlock's device-ioctl right refuses TIOCSCTTY (EACCES);
  seccomp refuses TIOCSTI with EPERM first.
- Canary defects found and fixed: the double-fork relay waited for EOF
  (false pass); R-06 and R-28 first tested only the base deny-default /
  `Network::None`, so defects (b) and (d) slipped through; both canaries
  now also run with the access opened so only the hard deny can refuse.

Defect injection (each reverted):

| Defect | Caught by |
|---|---|
| (a) macOS: no `FcntlModify` rules | r05_modifying_fcntl_commands_are_refused |
| (b) macOS: no `ServiceHandoff` rules | r06_service_handoff_lookups_are_refused (after strengthening) |
| (c) Linux: no TIOCSTI seccomp rule | r22_terminal_input_injection_is_refused (T1, T2) |
| (d) Linux: no AF_NETLINK/AF_VSOCK rule | r28_filter_bypassing_interfaces_are_refused (after strengthening) |
| (e) Linux: no `ProcessAccess` rules | r25_other_processes_are_opaque |

