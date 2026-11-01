# Quickstart

1. `just ci` (policy tests, macOS fitted cage).
2. `just linux`, `just linux-t1` (fitted cages on T2 and T1 with the cap).

## Recorded outcomes

2026-11-01, macOS 26.6.2 and Docker Desktop (Linux 7.0.14, ABI 8):

| Gate | Result |
|---|---|
| `just ci` | pass (policy `tests/fit.rs` 8/8; macOS `fitting_on_macos_relaxes_nothing_it_can_enforce`; `native::fitting_has_the_same_shape`) |
| `just linux` (T2) | pass; `a_fitted_cage_gives_up_only_what_was_named`, `fitting_has_the_same_shape` ran |
| `just linux-t1` (T1, T2 forced) | pass; same tests ran |

The harness-shaped policy on T2 at ABI 5 gets exactly five gaps
(fs-protect, fs-hide, hd-trust-handoff, ipc-unix-sockets,
signals-self-and-children), the five a consumer harness handles by hand.
