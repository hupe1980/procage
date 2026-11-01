# Contract

| Setting | macOS | Linux T1 | Linux T2 |
|---|---|---|---|
| `ipc.unix_sockets` | exact | exact (ABI ≥ 9) / approximated: AF_UNIX only, abstract in netns, listening sockets outside masked at spawn | exact (ABI ≥ 9) / refused |
| `Hide` in a read-only tree | exact | exact (mask) | approximated: piecewise grants at spawn |
| `Hide`/`Protect` in a writable tree | exact | exact | refused |
| secrets class, reached by read only | exact | approximated (mask) | approximated (piecewise) |
| secrets class, reached by write | exact | approximated (mask) | refused |

`accept_spawn_snapshot()` accepts the approximated cells above; nothing else.
