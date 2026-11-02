# Quickstart: validating the kernel matrix

```sh
just kernel                  # every kernel, locally under QEMU (slow without KVM)
just kernel v7.3.1=11        # one kernel
```

CI runs the same lane per kernel (`kernels` job) with KVM.

Expected: per kernel, the probe reports the expected ABI and tier T1, the
kernel facts pass, and every Linux suite passes on T1 and T2, with
violation reporting and through the async handle.

## Results (2026-11-02, local, arm64 under QEMU without KVM)

| Kernel | ABI | Result |
|---|---|---|
| 7.3.1 | 11 | facts and suites pass, except an R-09 canary fault (one socket path for both tiers: EADDRINUSE), fixed in the canary |
| 7.2 | 10 | the same |
| 7.1 | 9 | the same |
| 7.0 | 8 | all pass |
| 6.12 | 6 | suites pass; KF-L01 required the errata query, which exists from ABI 7: fixed in the fact |
| 6.6 | 3 | the same |
| 6.8 | 4 | hung at boot under emulation; left to CI |
| 5.15 | 1 | Landlock not in the default LSM list: the lane passes `lsm=…,landlock`; then T1 and ABI 1, KF-L01 passes, KF-L15 observes no hang-up of the seccomp listener after the child exits (open; CI decides) |

## Results (2026-11-02, CI, x86_64 with KVM)

Every kernel above passes the facts and all suites on commit `692982f`
(run 41503537476). The CI jobs boot the guest from QEMU running as root,
with the suites as the runner user, as `just kernel` does; QEMU as the
runner user failed every T1 mount and T2 spawn with `EACCES`.
