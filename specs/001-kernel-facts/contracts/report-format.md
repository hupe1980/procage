# Contract: fact report

The runner prints the report to stdout and writes the same text to
`target/kernel-facts/report-<os>-<arch>.txt`.

```text
procage kernel facts
os: macos 26.6.2 (25G83) | arch: aarch64 | date: 2026-10-29 | sandboxed: no
tier: -                                   # Linux: "T2 (landlock abi 8 errata 7; userns no: EPERM; seccomp user_notif)"
KF-M01 PASS   0.04s  libsandbox symbols resolve by dynamic lookup
KF-M07 FAIL   0.11s  literal /etc/hosts does not block; /private spelling does
       expected errno=1 observed errno=0
KF-L03 N/A           tier T2: unprivileged user namespace unavailable (errno=1)
KF-M17 PASS  51.20s  20,000 deny-default allow rules abort the compiler [slow]
summary: 38 pass, 0 fail, 3 n/a, 0 setup-failed in 142.5s
```

- One line per fact, in catalog order. A FAIL or SETUP-FAILED line is followed
  by an indented `expected … observed …` line.
- `date` is UTC `YYYY-MM-DD` (SR-012).
- When the precheck finds `sandboxed: yes`, every enforcement fact is `FAIL`:

  ```text
  KF-M05 FAIL  already inside a Seatbelt sandbox: run `just test-outside` from a terminal that is not inside an agent sandbox
  ```

  (SR-001).
- Exit status 0 only if there are no FAIL or SETUP-FAILED lines and the tier
  matches `PROCAGE_KF_EXPECT_TIER` (when set).
- `cargo test … -- <filter>` runs only facts whose id starts with `<filter>`,
  e.g. `KF-M1`.
- The compile-abort bisection (`PROCAGE_KF_BISECT=1`) adds lines
  `bisect <shape>: ok<=N abort>=M (width P%) in Ts`.
