# Quickstart: 010-violations

```sh
cargo test --test spawn_macos violations      # stories 1–3 on macOS
cargo test --test escape_macos                 # every canary, reporting on included
cargo test -p procage-policy                   # rendering and identical-off
cargo test --test native                       # same shape on both
just kf                                        # KF-M29: format and ordering
just linux && just linux-t1                    # Linux: NotObserved, nothing else changes
just ci
```

Expected: a hidden-file read and an outside write are listed with
`Hide` and `NotGranted`, the record is complete within 1 s of exit, a
cage without the option reports `Off`, Linux reports `NotObserved`.

Shape for consumers:

```rust
let cage = Cage::with_options(&policy, &CageOptions::default().with_violations())?;
let mut child = cage.spawn(&mut cmd, &grants)?;
child.wait()?;
for v in &child.violations() { eprintln!("{v}"); }
```

## Results (2026-11-01, macOS 26.6.2; Docker Linux 7.0.14 aarch64)

- `just ci`: all gates pass.
- macOS: spawn 58/58 (incl. 11 violation tests), escape 23/23 without and with
  reporting, lib 26/26, KF-M29 10/10 idle and 8/8 with every CPU busy.
- Linux T2 / T1: lib 32, spawn 36, escape 21, native 5, exec 9 / 18 — all pass;
  kernel facts 6 pass (T2), 13 pass (T1).
- Site: `zola check` and `zola build` pass (13 pages).
