# Implementation Plan: Kernel matrix and newer Landlock ABIs

**Branch**: `044-kernel-matrix` (local planning; commits on `main`) | **Date**: 2026-11-02 | **Spec**: [spec.md](spec.md)

## Summary

Every Linux suite runs on real mainline kernels, one per Landlock ABI step,
each booted in a virtme-ng guest: in CI with KVM, locally under QEMU without
KVM inside the container image. The backend's maximum ABI rises to the
highest ABI whose kernel ran the suites green. Raising it makes two things
exact: Unix-socket paths on T2 (ABI 9) and UDP from a handed-over socket
with the network off (ABI 10).

## Technical Context

- **Kernels**: Ubuntu mainline builds (kernel.ubuntu.com), fetched by
  virtme-ng 1.42 by tag: v5.15, v6.6, v6.8, v6.12, v7.0, v7.1, v7.2, v7.3.
- **Guest**: the host's root file system (the container's locally, the
  runner's in CI), the build's target directory writable; the suites run as
  an unprivileged user, so the guest gives tier T1 and the suites also
  measure T2 cages.
- **Uapi**: the rights procage defines match `include/uapi/linux/landlock.h`
  (`RESOLVE_UNIX` bit 16, ABI 9; `BIND_UDP` and `CONNECT_SEND_UDP` bits 2
  and 3, ABI 10).

## Design

1. **Lane scripts.** `.github/kernel-lane.sh <tag>=<abi>…` builds the test
   binaries once, then boots each kernel and runs `.github/kernel-guest.sh`
   in it: the kernel facts with `PROCAGE_KF_EXPECT_ABI` (a probe that
   reports another ABI fails the lane), the spawn and escape suites, the
   escape suite with violation reporting and through tokio. The guest's
   exit code is the lane's. KVM is used when `/dev/kvm` is writable.
2. **CI.** A `kernels` job per kernel on `ubuntu-24.04`: a udev rule opens
   `/dev/kvm`, then QEMU, virtme-ng and the lane script.
3. **Local.** `just kernel [tag=abi …]` runs the same script in the
   container image as root with a `lane` user for the suites (QEMU without
   KVM on Apple silicon).
4. **Lowering.** With the network on, `RESOLVE_UNIX` is not handled, so
   every pathname socket stays reachable as below ABI 9.
5. **Maximum ABI.** `BACKEND_MAX_ABI` becomes the highest ABI with a green
   kernel (11 when 7.3 passes). Nothing in the child sequence changes:
   ABI 11's no-new-privileges flag is not used.
6. **Canaries.** R-09 checks exact Unix-socket paths from ABI 9 on both
   tiers and that a pathname socket stays reachable with the network on;
   a new canary checks that a handed-over UDP socket cannot send with the
   network off from ABI 10. Tests that encode the ABI 8 limits take the
   cage's ABI (`min(probe, BACKEND_MAX_ABI)`).
7. **Docs.** The backend's ABI table gains ABI 9 and 10; the Linux page
   lists each tested kernel with its date and where it ran.

## Constitution Check

| Principle | Check | Status |
|---|---|---|
| I | No weaker rule: what a newer ABI cannot do stays a gap; the network-on fix keeps the policy's meaning | PASS |
| III | The kernel is the oracle: every raised ABI has a green run of the full suites on that kernel | PASS |
| IV | The child sequence is unchanged | PASS |

## Project Structure

```text
.github/kernel-lane.sh, .github/kernel-guest.sh   # the lane
.github/workflows/ci.yml                          # kernels job
justfile                                          # kernel recipe
crates/procage-policy/src/lower/linux.rs          # RESOLVE_UNIX with the network on
crates/procage/src/linux/mod.rs                   # BACKEND_MAX_ABI, ABI table
crates/procage-kernel-facts/tests/kernel_facts.rs # PROCAGE_KF_EXPECT_ABI
crates/procage/tests/{escape,spawn}_linux.rs      # ABI-aware canaries
site/content/docs/linux.md                        # tested kernels
```
