# Quickstart: validating explain and diff

```sh
cargo test -p procage-policy explain     # evaluator, regex, remedy, diff soundness
cargo test -p procage --test oracle      # macOS: the oracle on this machine
just linux-t1 && just linux              # the oracle on Linux T1 and T2
```

Expected:

- `oracle` prints, per policy and target, the number of questions asked
  (at least 1,000 each) and the rule kinds reached, and passes. A
  disagreement fails with the question, the answer and the kernel's errno.
- Run inside another sandbox, the oracle fails with `AlreadySandboxed`.
- `explain` unit tests cover: every rule kind, `NotModelled`,
  non-canonical paths, remedies that flip, diff of v1→v2 and v2→v3 of every
  preset (base entries and the base setting, plus `build` v2's
  workspace sockets), and generated pairs
  whose differing answers are all covered by a diff entry with the right
  direction.

## Results (2026-11-02)

| Lane | Policies asked | Questions each | Result |
|---|---|---|---|
| macOS 26.6.2, Apple M4 Pro | 12 presets + rule kinds | 1,278 | all agree; every rule kind reached |
| Linux 7.0 aarch64 (Docker), T1 lane: T1 and T2 | 9 presets + rule kinds per tier (`build` needs loopback, which Linux cannot express) | 1,277 | all agree |
| Linux 7.0 aarch64 (Docker), T2 lane | 9 presets + rule kinds | 1,277 | all agree |

- Presets are fitted as a user would: approximations accepted by name,
  hard-deny classes a tier cannot express waived.
- An evaluator mapping exec to the wrong Seatbelt operation made the macOS
  suite fail with 21 disagreements, as did flipping any one rule kind's
  answers.
- `explain` in release: 0.61 ms per question for a 4,000-byte path under
  `agent_workspace` v3 on macOS (the spawn bench). `diff` of two
  10,000-rule policies: about 0.05 s in release.
- Gates: `just ci`, `just escape` (three variants), `just linux-t1`,
  `just linux`: green.
