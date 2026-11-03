# Quickstart: validating a new terminal

```sh
cargo test -p procage --test pty                         # macOS
cargo test -p procage --test escape_macos r22            # R-22 with a new terminal
just linux-t1 && just linux                              # T1 and T2 (include pty)
just kernel                                              # mainline kernels 5.15 to 7.3
```

## Measured (2026-11-03)

| Check | macOS 26.6.2 | Linux 7.0 container, T1 and T2 |
|---|---|---|
| `sh -i`: input through the controller, `tty` names the device, `test -t 0`, `/dev/tty` opens | passed | passed |
| `python3 -q -i` evaluates `print(6*7)` | passed | passed |
| Full-screen program draws and quits | `vi` | `top` (no `vi` in the container; the CI hosts ship `vi`) |
| Starts at 80 by 24; `set_size(50, 132)` seen by `stty size` | passed (base V1) | passed (no base) |
| The run end kills a background job; the controller read ends | passed | passed |
| `Cage::exec` and `exec_session` refuse | passed | passed |
| 200 concurrent runs from a busy parent: descriptors 0 to 3 only | passed, 20 consecutive runs | passed |
| R-22: TIOCSTI on the own terminal | EPERM; waived: echoed on the own controller | EPERM; waived: same |
| R-22: another terminal | refused, also waived | refused, also waived |

Findings on the way:

- macOS `ttyname` lists `/dev`; without `file-read*` on the literal `/dev`
  `tty` prints "not a tty". The new-terminal rule allows that listing.
- macOS TIOCSTI also needs `hid-control`; the canary allows it so the
  terminal-injection class alone refuses.
- On macOS, output the controller has not read when every device
  descriptor closes is discarded after the exit's drain, about 0.6 s
  (measured); holding a copy of the device would keep it but block the
  exit until it is read, so procage does not. A harness reads while the
  run runs. The R-22 canary read on a thread started after the spawn and
  lost the output twice in 15 loaded runs (CI run 41675095393); it now
  reads on the spawning thread.
- The concurrent test exposed a marker-search race on macOS (plan, step
  11): about one run in three failed before the fix, none in 20 after.
