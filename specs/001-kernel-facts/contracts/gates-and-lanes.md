# Contract: local gates (justfile) and CI lanes

## just recipes

| Recipe | Does | Fails when |
|---|---|---|
| `ci` | `fmt-check lint test doc deny msrv no-std semver planning-paths`, in order; stops at the first failure | any gate fails |
| `fmt-check` | `cargo fmt --all --check` | unformatted code |
| `lint` | `cargo clippy --workspace --all-targets -- -D warnings` | any lint, including unsafe outside `sys` and an unsafe block without `SAFETY:` |
| `test` | `cargo test --workspace` (unit, doc, and the `kernel_facts` runner) | any FAIL or SETUP-FAILED fact |
| `facts *ARGS` | `cargo test -p procage-kernel-facts --test kernel_facts -- ARGS` | as `test` |
| `test-outside` | prints how to run outside an agent sandbox, then runs `facts` | — |
| `bisect` | `PROCAGE_KF_BISECT=1 just facts KF-M24` (opt-in compile-abort bisection) | bracket wider than 10% or over the time budget |
| `doc` | `RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps` | doc warnings |
| `deny` | `cargo deny check` | advisory, licence, source or ban violation |
| `msrv` | `cargo +1.99.0 check --workspace --all-targets` | an API newer than 1.99 |
| `no-std` | `cargo build -p procage-policy --target thumbv7em-none-eabihf` | std pulled into the policy crate |
| `semver` | `cargo semver-checks -p procage` | a breaking change against crates.io |
| `planning-paths` | grep the published tree (`src/`, `crates/`, `tests/`, `README.md`, `.github/`, `Cargo.toml`) for the private notes directory, `specs/`, `.specify/` | any match (SR-015) |
| `kf-linux` | Docker T2 recipe (research R8), `PROCAGE_KF_EXPECT_TIER=T2` | facts fail or tier ≠ T2 |
| `kf-linux-t1` | Docker T1 recipe, `PROCAGE_KF_EXPECT_TIER=T1` | facts fail or tier ≠ T1 |
| `kf-rosetta` | `just facts` with `--target x86_64-apple-darwin` | facts fail |
| `ci-all` | `ci kf-linux kf-linux-t1 kf-rosetta` | any |

## Environment variables

| Variable | Effect |
|---|---|
| `PROCAGE_KF_EXPECT_TIER` | `T1`/`T2`/`T3`: fail if the measured tier differs (Linux) |
| `PROCAGE_KF_BISECT` | `1`: run the compile-abort bisection (10-minute budget per shape) |

## CI lanes (`.github/workflows/ci.yml`)

`permissions: contents: read`; actions pinned by full SHA; checkout with
`persist-credentials: false`; no secrets (SR-010).

| Job | Runner | Config | Expected tier | Allowed missing |
|---|---|---|---|---|
| gates | ubuntu-24.04 | `fmt-check lint doc deny msrv no-std semver planning-paths` | — | no |
| macos | macos-26 (arm64) | `just facts` | — | no |
| macos-newest | macos-latest, or the newest image (27 when offered) | `just facts` | — | yes (`continue-on-error`) |
| macos-x86 | macos-26 under Rosetta (`--target x86_64-apple-darwin`) | `just facts` | — | yes |
| linux | ubuntu-24.04, ubuntu-24.04-arm | shipped | T2 | no |
| linux-userns | ubuntu-24.04, ubuntu-24.04-arm | `sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0` | T1 | no |
| linux-next | ubuntu-26.04 | shipped | recorded only (no expectation) | yes |
| linux-container | ubuntu-24.04, `container: debian:13` | Docker default seccomp | T2 | no |

Each lane's job log contains the report header (OS build or kernel, arch,
date, tier). No lane runs inside an agent sandbox.
