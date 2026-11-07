# Quickstart: Windows backend

## Prerequisites

- Windows 11 24H2 (26100.9278+), 25H2 (26200.9278+), 26H2 or 26H1 at the
  builds in research R1. Arm64 is the lane architecture.
- Rust 1.99 with the `aarch64-pc-windows-msvc` target, and Git for Windows.
- No administrator rights. Run from a normal user session, not inside
  another sandbox (that is `AlreadySandboxed`).

## Checks

```powershell
# 1. The facts: the OS behaviour the lowering relies on (KF-W1…KF-W19)
cargo run -p procage-kernel-facts --bin kf-probe
cargo test -p procage-kernel-facts

# 2. Lowering and encoding (also run on macOS and Linux lanes)
cargo test -p procage-policy lower::windows
cargo test -p procage windows::psec

# 3. Spawn, hygiene, lifetime, escape suite
cargo test -p procage --test spawn_windows --test escape_windows --test native --test receipts
cargo test -p procage --features tokio --test tokio

# 4. Overhead (SC-004)
cargo bench -p procage --bench spawn
```

## Expected outcomes

- `kf-probe` prints the build, the schema version and the support flags,
  and every KF-W fact passes or reports the outcome its decision rule
  maps to a gap.
- On a host without the feature, every test fails with
  `Unsupported::NoSecurityEnvironment`. None is skipped (SR-013).
- The workspace preset runs `cargo build` and `git status` in a temporary
  workspace (SC-001). It refuses `%USERPROFILE%\.ssh`, writes outside the
  workspace, the Docker and OpenSSH agent pipes, HKCU `Run` writes and any
  outbound connection.
- After the stress test (1,000 runs, kills, one parent killed), the recorded
  security descriptors are byte-identical and no process of a run remains
  (SC-003, SR-005).

## Results

None yet: no Windows lane has run this record.
