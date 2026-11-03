# Quickstart: validating the Node.js bindings

```sh
just node                     # macOS: build the addon, pack, test from the tarball
just node-linux T1 22         # Linux T1 in containers, on Node 22
just node-linux T2 26         # Linux T2, on Node 26
just versions                 # package.json matches the crates
```

`bindings/nodejs/build.sh build`, `pack OUT` and `test TGZ` are what CI
and the release run.

## Measured (2026-11-03)

| Host | Addon | Node | Tests |
|---|---|---|---|
| macOS 26.6.2, arm64 | `procage.darwin-arm64.node` | 26.13 | 24 passed, 1 skipped (the Linux-only gap hint) |
| Linux 7.0 container, aarch64, T1 | `procage.linux-arm64-gnu.node` (zig, glibc 2.28) | 22 | 25 passed |
| same, T2 | same | 26 | 25 passed |

The tests: reads and writes outside the workspace, a secret and the
network are refused; `process.env` is not copied; unknown fields, presets
and relaxations throw `PolicyError`; a gap throws `CapabilityGapError`
naming the accepting option; `input`, `encoding`, `shell` and `check`;
timeout, `AbortSignal`, disposal and the exit of a Node process end runs;
six runs at once while a 20 ms timer keeps firing; violations and the
receipt; an undeclared grant; the loader ignoring an override variable;
the shell tool example. The packed tarball holds exactly the module, its
declarations, the addons, the README and the licences.
