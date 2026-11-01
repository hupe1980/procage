# Feature Specification: Vanished snapshot covers and honest report loss

**Feature Branch**: `038-snapshot-covers-and-report-loss` (planning directory; commits land on `main`)

**Created**: 2026-11-01

**Status**: Draft

**Input**: Two defects found while a consumer harness adopted violation reporting: Linux tier T1 spawns failed when a file vanished during the spawn, and the macOS docs promised more completeness than the system delivers.

## Context

**Spawns on tier T1.** procage masks, at spawn, every pathname Unix socket
listed in `/proc/net/unix` outside the allowed trees, and every file of a
data class found in the writable trees (the spawn snapshot). The child then
mounts over each one. A file removed between the scan and the mount failed
the whole spawn with `ENOENT` (`the child failed at step mounts`). On a
developer machine sockets come and go all the time (test servers, language
servers, agents), so spawns failed at random. A churn test (a thread binding
and removing a socket while spawning) failed at the third spawn.

**Report loss on macOS.** The docs said an empty record that is complete and
`Observed` proves nothing was denied. Under heavy load macOS drops denial
reports before any reader sees them: with 16 runs in parallel, an
independent `log stream` saw 558 of 640 denials (research.md). A complete
record holds every denial that was *logged*.

## Clarifications

### Session 2026-11-01

- Q: Which mounts may be skipped? → A: Only covers from the spawn snapshot
  (data-class files, foreign sockets), only when the file no longer exists
  (`ENOENT`), and the remount of the same target with it. Mounts the policy
  declares stay strict.
- Q: Does skipping weaken the cage? → A: No more than the documented
  approximation already does: a file created after the spawn is never
  covered either, and these covers require `accept_spawn_snapshot`.
- Q: Can procage make macOS reports lossless? → A: No; the drop happens in
  the system before any reader. procage states it and never presents an
  empty record as proof.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Spawns survive file churn (Priority: P1)

A harness spawns cages on T1 while other programs create and remove Unix
sockets and files. Every spawn starts.

**Independent Test**: 300 T1 spawns while a thread binds and removes a
foreign socket the whole time; all succeed.

**Acceptance Scenarios**:

1. **Given** a socket removed between the scan and the mount, **Then** the
   spawn succeeds.
2. **Given** a socket that stays, **Then** it is still masked (existing mask
   tests).
3. **Given** a declared rule on a missing path, **Then** the cage still
   fails as before.

---

### User Story 2 - The docs say what an empty record means (Priority: P2)

A harness reads that an empty record never proves nothing was denied, and
why, with the measurement.

**Acceptance Scenarios**:

1. **Given** the crate docs and the site, **Then** neither presents a
   complete `Observed` record as proof, and both name the measured loss.

## Requirements *(mandatory)*

- **FR-001**: On T1, a cover from the spawn snapshot whose file is gone when
  the parent builds its mounts, or when the child mounts it (`ENOENT`), MUST
  be skipped together with the remount of the same target; every other mount
  failure MUST still fail the spawn.
- **FR-002**: The violation docs (module, `Coverage::Observed`,
  `Violations::complete`, the site page) MUST say that macOS drops reports
  under heavy load, with the measurement, and that an empty record never
  proves nothing was denied.

- **FR-003** (found in this row): The caged tests MUST remove the scratch
  directories they create.
- **FR-004** (found in this row): CI MUST fit free GitHub runners: one job
  per platform and tier, fuzzing bounded to minutes, no scheduled runs.

<!-- threatspec:begin -->
### Security Requirements *(managed by ThreatSpec — edit threat-model.yaml)*

- **SR-001** (P2): On Linux T1, only covers made from the file system at spawn MAY be skipped, and only when their file no longer exists; mounts the policy declares MUST stay strict, and a skipped cover MUST NOT leave a remount behind.
  - Mitigates: `threat.cover-skip-exposes` via `mitigation.optional-covers`
  - Given a thread binding and removing a foreign socket, when 300 T1 spawns run, then all succeed
  - Given the T1 escape suite and mask tests, when they run with the change, then they pass unchanged
- **SR-002** (P2): procage MUST NOT present a complete macOS record as proof that nothing was denied; its docs MUST state the measured report loss under load.
  - Mitigates: `threat.record-overclaim` via `mitigation.measured-docs`
  - Given the crate docs and the site page, when they describe Observed and complete, then neither calls an empty record proof, and both name the measured loss
<!-- threatspec:end -->

## Success Criteria *(mandatory)*

- **SC-001**: The churn test passes (300 of 300 spawns) and fails without
  the fix.
- **SC-002**: `just ci` and the Linux T1 lane pass (T2 has no mounts; CI runs every lane).

## Assumptions

- The child's mount sequence stays async-signal-safe (no allocation).
