# Quickstart: validating moves and link exemptions

```sh
cargo test -p procage-policy --lib linux                # REFER only with write
cargo test -p procage --test audit an_exempt            # the exemption (macOS)
just linux-t1 && just linux                              # canaries on T1 and T2
```

## Results (2026-11-02)

| Where | Run | Result |
|---|---|---|
| macOS 26 (arm64) | policy and audit unit tests, `tests/audit.rs` | passed |
| Linux T1 (container, 7.0, ABI 8) | `just linux-t1`, r04, r08, r30, the exemption test in full | passed |
| Linux T2 (container, 7.0, ABI 8) | `just linux` | passed (the exemption test is not applicable: T2 cannot protect) |
| macOS | `just ci` | every gate green |

ABI 1 (moves between directories fail with `EXDEV`) is asserted by the
kernel lane's 5.15 job in CI.

Security convergence: SR-001 to SR-006 verified (see
`security/convergence-report.md`).
