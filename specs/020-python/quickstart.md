# Quickstart: validating the Python bindings

```sh
just python                    # macOS: build the wheel as released, install fresh, run the tests and example
just python-linux T1           # Linux in a container, tier T1
just python-linux T2           # and T2
```

`bindings/python/wheel.sh build OUT` and `test DIR` are what CI and the
release run.

## Measured (2026-11-03)

| Host | Wheel | Tests |
|---|---|---|
| macOS 26.6.2, arm64 | `procage-…-cp311-abi3-macosx_11_0_arm64.whl` | 29 passed |
| Linux 7.0 container, aarch64, T1 | `…-cp311-abi3-manylinux_2_28_aarch64.whl` (zig) | 29 passed |
| same, T2 | same | 29 passed |

The tests: reads and writes outside the workspace, a secret (macOS:
listing `~/Library/Keychains`; Linux: a file under `~/.aws`) and the
network are refused; `os.environ` is not copied; unknown fields, presets
and relaxations raise `PolicyError`; a gap raises `CapabilityGapError`
and names the accepting option; collection, `kill` and interpreter exit
end runs; spawns from four threads complete; waiting releases the
interpreter; `wait_async`, four `run_async` at once, and a cancelled
`run_async` ending its run; `text`, `check`, `shell` and paths; violations
and the receipt; the shell tool example.
