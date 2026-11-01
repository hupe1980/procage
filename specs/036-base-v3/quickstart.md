# Quickstart: 036-base-v3

```sh
cargo test -p procage-policy                 # strip-equals-V2, quiet list, fixtures v3
cargo test -p procage --test spawn_macos v3  # quiet records, Tty::Inherit, merging
just facts KF-M30                            # no-report semantics
just ci && just linux && just linux-t1       # Linux merge, escape with presets v3
```

## Results (2026-11-01, macOS 26.6.2; Docker Linux 7.0.14)

- Reports of the developer-tool test set: V2 5,495 → V3 296 (−94.6 %);
  `ls`, `sed`/`grep`, `perl` leave empty records; every command succeeds.
- macOS: spawn 62/62, escape 23/23 on V1, with reporting, and on V3 with
  reporting; KF-M30 passes; `just ci` all gates.
- Linux T2/T1: spawn 46/46 (flood merged into one entry ×20,000), escape
  22/22 without and with reporting, lib 36/36; kernel facts pass.
- Analyze miss, corrected during implementation: SC-001 asked for 95 % fewer
  entries, which contradicted the decision to keep the Xcode shim's reads of
  user files reported; revised to reports (≥ 90 %, measured 94.6 %).
