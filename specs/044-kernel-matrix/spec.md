# Feature Specification: Kernel matrix and newer Landlock ABIs

**Feature Branch**: `044-kernel-matrix` (planning directory; commits land on `main`)

**Created**: 2026-11-01

**Status**: Draft

**Input**: procage supports Linux from Landlock ABI 1 (5.13) but CI runs one kernel (7.0, ABI 8). Older-kernel behaviour is tested by capping the ABI in-process, which proves the lowering but not the kernel. Newer ABIs (9 in 7.1: pathname Unix sockets; 10 in 7.2: UDP and quiet rules; 11 in 7.3: no-new-privileges on restrict) would make some approximations exact, but the backend stops at ABI 8.

## Context

The kernel is the oracle. A capped ABI on a 7.0 kernel is not the same as a
real 5.15 or 6.8 kernel (errata, missing system calls, different `/proc`).
Lightweight VMs (for example virtme-ng) boot a given kernel in seconds where
the runner exposes hardware virtualisation.

## Clarifications

### Session 2026-11-01

- Q: Which kernels? → A: One per ABI step procage behaves differently at:
  ABI 1 (5.15 LTS), 3 (6.2+), 4 (6.8, Ubuntu 24.04 GA), 6 (6.12 LTS, Debian
  13), 8 (7.0, already a lane), 11 (7.3).
- Q: Raise the backend's maximum ABI before a lane proves it? → A: No. The
  maximum rises only to an ABI a lane has run the full suite on.
- Q: No virtualisation on the runners? → A: Then the matrix runs locally on
  demand, results are recorded with kernel and date, and the docs say which
  kernels were tested where.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Each ABI step is tested on a real kernel (Priority: P1)

**Independent Test**: The kernel facts, spawn tests and escape suite run in a
VM per kernel of the matrix, tiers T1 and T2.

**Acceptance Scenarios**:

1. **Given** each kernel, **When** the suites run, **Then** they pass, and
   the probe reports the expected ABI and errata.

---

### User Story 2 - Newer kernels give exact results (Priority: P2)

**Acceptance Scenarios**:

1. **Given** ABI ≥ 9 on T2, **When** a policy names Unix-socket paths, **Then**
   it is enforced exactly (not a gap), proven by the canary.
2. **Given** ABI ≥ 11, **Then** no-new-privileges is set by Landlock as well,
   and the probe records it.

### Edge Cases

- Distribution kernels with backported ABIs (RHEL): the probe, not the
  version number, decides; documented.
- Errata that change behaviour within an ABI: probed and recorded in the
  lane header.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: The full Linux suites MUST run on one kernel per ABI step of
  the clarifications, in CI where virtualisation is available, otherwise as
  a recorded local run.
- **FR-002**: The backend's maximum ABI MUST be raised only to an ABI with a
  green run of the full suite.
- **FR-003**: Each newly exact construct MUST have a canary on that kernel.
- **FR-004**: The docs MUST list the tested kernels with their dates.

## Success Criteria *(mandatory)*

- **SC-001**: Six kernels green (or recorded), each with its probe output.
- **SC-002**: The platform table states, per ABI, which constructs are exact.

## Assumptions

- Prebuilt kernels for each version are available or buildable in CI time.

## Out of Scope

- Kernels below Landlock ABI 1 (unsupported).
