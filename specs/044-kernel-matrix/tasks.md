# Tasks: Kernel matrix and newer Landlock ABIs

## Phase 1: Setup

- [X] T001 Lane scripts: `kernel-lane.sh <tag>=<abi>…` (build once, boot each kernel with virtme-ng, KVM when `/dev/kvm` is writable, as root the suites run as `PROCAGE_LANE_USER`, the guest's environment passed on, the guest's exit code per kernel) and `kernel-guest.sh` (facts with the expected ABI, spawn and escape suites, violation reporting, tokio) — .github/kernel-lane.sh, .github/kernel-guest.sh
- [X] T002 `just kernel [tag=abi …]` in the container image (QEMU, virtme-ng 1.42, udev, iproute2; the x86-64 guest init removed on arm64) — justfile
- [X] T003 CI `kernels` job, one per kernel, KVM opened by a udev rule — .github/workflows/ci.yml

## Phase 2: Foundational

- [X] T004 `PROCAGE_KF_EXPECT_ABI` fails the facts when the probe reports another ABI; KF-L13 applies where `/proc` is masked (measured from the mount table), not wherever a container marker file exists — crates/procage-kernel-facts/tests/kernel_facts.rs

## Phase 3: User Story 1 — Each ABI step on a real kernel (P1)

- [X] T005 [US1] Run the matrix (v5.15, v6.6, v6.8, v6.12, v7.0, v7.1, v7.2, v7.3) with `just kernel`; record kernel, probe and results in specs/044-kernel-matrix/quickstart.md

## Phase 4: User Story 2 — Newer kernels give exact results (P2)

- [X] T006 [US2] With the network on, `RESOLVE_UNIX` is not handled; lowering test at ABI 9 with and without the network — crates/procage-policy/src/lower/linux.rs, crates/procage-policy/tests/gaps.rs
- [X] T007 [US2] Canaries: R-09 exact on both tiers from ABI 9; a handed-over UDP socket cannot send with the network off from ABI 10 (`testing::udp_send_errno`); the fit test expects the Unix-socket relaxation only below ABI 9 — crates/procage/tests/escape_linux.rs, crates/procage/tests/spawn_linux.rs, crates/procage/src/linux/{mod,sys}.rs
- [X] T008 [US2] `BACKEND_MAX_ABI` to the highest ABI whose kernel passed T005 — crates/procage/src/linux/mod.rs

## Phase 5: Polish

- [X] T009 Docs: ABI table rows 9 and 10 and the Unix-socket paragraph (crate and site), the tested kernels with dates (site testing page), CHANGELOG — crates/procage/src/linux/mod.rs, site/content/docs/linux.md, site/content/docs/testing.md, CHANGELOG.md
- [X] T010 Gates: `just ci`, `just linux`, `just linux-t1`; spec status Implemented; commit on `main`
