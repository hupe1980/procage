# Threat Model: Path resolution that cannot be redirected or mis-spelled

**Feature**: `040-path-resolution` · **Generated**: 2026-11-03T08:37:52Z · **Profiles**: stride, llm, agent · **Canonical**: `threat-model.yaml`

> Rendered by ThreatSpec. Edit `threat-model.yaml`, not this file.

## Summary

| Threats | Critical | High | Medium | Low | Needs clarification | Not applicable | Mitigations | Requirements | Decisions |
|---|---|---|---|---|---|---|---|---|---|
| 12 | 0 | 6 | 5 | 1 | 0 | 28 | 10 | 10 | 0 |

## Actors

| ID | Name | Trust | Description |
|---|---|---|---|
| `actor.caged-code` | Arbitrary code in the caged child | untrusted |  |
| `actor.consumer` | Developer of a harness that builds and fits policies | trusted |  |
| `actor.contributor` | procage contributor who edits the backends, the data classes or the docs | semi-trusted |  |

## Trust Zones

| ID | Name | Trust rating | Description |
|---|---|---|---|
| `tz.cage` | The caged child and concurrent caged runs | 5 |  |
| `tz.harness` | The harness that builds cages | 90 |  |
| `tz.os` | The kernel (mounts, Landlock, Seatbelt) and the file systems | 95 |  |

## Assets

| ID | Name | Type | Classification | C / I / A | Source |
|---|---|---|---|---|---|
| `asset.claim` | The published canonicalisation claim and the escape-class evidence | configuration | public | 0 / 70 / 10 | spec.md#SC-004 |
| `asset.harness` | Spawns of concurrent runs on a shared workspace | capability | internal | 0 / 30 / 60 | spec.md#US1 |
| `asset.host` | The user's files, secrets and processes outside the policy | credential | secret | 100 / 90 / 50 | spec.md#Context |
| `asset.plan` | The T1 mount plan: each planned path and the object it resolved to | configuration | internal | 0 / 95 / 40 | spec.md#Key-Entities |

## Components

| ID | Name | Type | Trust zone | Source |
|---|---|---|---|---|
| `component.canaries` | Race canary and spelling matrix | test | `tz.harness` | spec.md#FR-001 |
| `component.canonicaliser` | macOS path canonicaliser and SBPL lowering of rule spellings | library | `tz.harness` | spec.md#FR-004 |
| `component.child-mounts` | Child mount sequence between fork and execve (T1) | library | `tz.harness` | spec.md#FR-003 |
| `component.docs` | Published canonicalisation claim and THREAT_MODEL escape class | document | `tz.harness` | spec.md#FR-007 |
| `component.resolver` | Parent-side mount plan: resolves policy paths and prepares targets | library | `tz.harness` | spec.md#Context |

## Data Flows

| ID | Name | From | To | Assets | Crosses |
|---|---|---|---|---|---|
| `flow.claims` | The docs tell the consumer which spellings are handled | `component.docs` | `actor.consumer` | `asset.claim` |  |
| `flow.lower` | The consumer's rule spellings are canonicalised and lowered to the profile | `actor.consumer` | `component.canonicaliser` | `asset.host` |  |
| `flow.mount` | The child mounts over a tree that other runs can write | `component.child-mounts` | `tz.os` | `asset.plan`, `asset.host` | `tz.harness`, `tz.os` |
| `flow.plan` | The parent hands the prepared mount plan to the child | `component.resolver` | `component.child-mounts` | `asset.plan` |  |
| `flow.plant` | A concurrent caged run changes the shared workspace | `tz.cage` | `tz.os` | `asset.plan` | `tz.cage`, `tz.os` |

```mermaid
flowchart LR
    actor_caged_code(["Arbitrary code in the caged child"])
    actor_consumer(["Developer of a harness that builds and fits policies"])
    actor_contributor(["procage contributor who edits the backends, the data classes or the docs"])
    subgraph tz_cage["The caged child and concurrent caged runs"]
    end
    subgraph tz_harness["The harness that builds cages"]
        component_canaries["Race canary and spelling matrix"]
        component_canonicaliser["macOS path canonicaliser and SBPL lowering of rule spellings"]
        component_child_mounts["Child mount sequence between fork and execve (T1)"]
        component_docs["Published canonicalisation claim and THREAT_MODEL escape class"]
        component_resolver["Parent-side mount plan: resolves policy paths and prepares targets"]
    end
    subgraph tz_os["The kernel (mounts, Landlock, Seatbelt) and the file systems"]
    end
    component_docs -->|"The docs tell the consumer which spellings are handled"| actor_consumer
    actor_consumer -->|"The consumer's rule spellings are canonicalised and lowered to the profile"| component_canonicaliser
    component_child_mounts -->|"The child mounts over a tree that other runs can write"| tz_os
    component_resolver -->|"The parent hands the prepared mount plan to the child"| component_child_mounts
    tz_cage -->|"A concurrent caged run changes the shared workspace"| tz_os
```

## Threats

| ID | Threat | Category | Technique | Severity | Status | Mitigations | Mappings | Source |
|---|---|---|---|---|---|---|---|---|
| `threat.case-miss` | On a case-insensitive macOS volume, a deny spelled in another case than on disk matches nothing in the profile, so the child reads the file through its on-disk spelling | Information Disclosure | sensitive-data-exposure | **high** | mitigated | `mitigation.exact-or-refuse`, `mitigation.spelling-matrix` |  | spec.md#US2 |
| `threat.hide-redirect` | A hidden file's parent directory becomes a link before the child mounts, so the empty file system or /dev/null cover lands on an unrelated path and the secret stays readable | Information Disclosure | sensitive-data-exposure | **high** | mitigated | `mitigation.mount-by-descriptor`, `mitigation.no-follow-resolution`, `mitigation.race-canary` |  | spec.md#US1 |
| `threat.mount-redirect` | A concurrent caged run on the same workspace replaces a component of a protected path with a symbolic link between the parent's plan and the child's mounts, so the read-only bind lands elsewhere and the protected path stays writable | Elevation of Privilege | broken-access-control | **high** | mitigated | `mitigation.mount-by-descriptor`, `mitigation.no-follow-resolution`, `mitigation.race-canary` |  | spec.md#US1 |
| `threat.source-redirect` | A bind source (a grant bind, the source of a protect bind) is redirected through a planted link, so the child sees content chosen by another run at a path it trusts | Tampering | injection | **high** | mitigated | `mitigation.no-follow-resolution`, `mitigation.race-canary` |  | spec.md#Edge-Cases |
| `threat.unicode-miss` | A rule in composed Unicode and a name in decomposed form on disk (or the reverse) do not match, so the rule silently misses the file | Information Disclosure | sensitive-data-exposure | **high** | mitigated | `mitigation.exact-or-refuse`, `mitigation.spelling-matrix` |  | spec.md#US2 |
| `threat.vacuous-canary` | The race canary never wins the race (timing, too few attempts), so zero redirected mounts after the change proves nothing, or the spelling matrix skips when a disk image or case-folding directory is missing | Repudiation | missing-audit-trail | **high** | mitigated | `mitigation.race-canary`, `mitigation.spelling-matrix` |  | spec.md#FR-001 |
| `threat.claim-overstates` | The published canonicalisation claim lists cases (case, Unicode, case-folding) that no caged test covers | Repudiation | missing-audit-trail | **medium** | mitigated | `mitigation.claim-from-matrix` |  | spec.md#Input |
| `threat.fold-overgrant` | Folding case or normalising a rule to make it match widens an allow: on a case-sensitive volume a grant for one name also grants a different file that differs only in case or form | Elevation of Privilege | broken-access-control | **medium** | mitigated | `mitigation.no-widening` |  | spec.md#US2 |
| `threat.kernel-fallback` | On a kernel without the system calls to resolve without following links or to mount by descriptor, the backend falls back to path mounts without an error | Elevation of Privilege | broken-access-control | **medium** | mitigated | `mitigation.no-fallback` |  | spec.md#Assumptions |
| `threat.resolve-then-remount` | The backend checks for links and then mounts by path name again, so a component replaced after the check still redirects the mount | Elevation of Privilege | broken-access-control | **medium** | mitigated | `mitigation.mount-by-descriptor` |  | spec.md#FR-002 |
| `threat.spawn-sabotage` | A caged run plants links in a shared workspace so that every sibling run's spawn fails, now that a link fails the spawn | Denial of Service | resource-exhaustion | **medium** | mitigated | `mitigation.named-failure` |  | spec.md#Clarifications |
| `threat.child-unsafe` | Resolution moved into the child allocates, takes locks or builds paths between fork and execve, so a multithreaded parent deadlocks or the child runs with corrupt state | Denial of Service | resource-exhaustion | **low** | mitigated | `mitigation.syscalls-only` |  | spec.md#FR-003 |

### Techniques evaluated without findings

| Technique | Disposition | Reason |
|---|---|---|
| credential-theft | not-applicable | no authentication surface |
| identity-spoofing | not-applicable | no authentication or network boundary |
| data-tampering-in-transit | not-applicable | no data in transit |
| data-tampering-at-rest | not-applicable | no store; the mount plan lives in memory for one spawn |
| cross-tenant-leak | not-applicable | single user |
| privilege-escalation-via-config | not-applicable | no configuration added; protected tool config is the asset of threat.mount-redirect |
| prompt-injection-direct | not-applicable | procage is a library that calls no model and runs no agent; LLM-written code is the adversary inside the child, modelled under STRIDE |
| prompt-injection-indirect | not-applicable | procage is a library that calls no model and runs no agent; LLM-written code is the adversary inside the child, modelled under STRIDE |
| sensitive-information-disclosure | not-applicable | procage is a library that calls no model and runs no agent; LLM-written code is the adversary inside the child, modelled under STRIDE |
| excessive-agency | not-applicable | procage is a library that calls no model and runs no agent; LLM-written code is the adversary inside the child, modelled under STRIDE |
| model-supply-chain | not-applicable | procage is a library that calls no model and runs no agent; LLM-written code is the adversary inside the child, modelled under STRIDE |
| training-data-poisoning | not-applicable | procage is a library that calls no model and runs no agent; LLM-written code is the adversary inside the child, modelled under STRIDE |
| unbounded-consumption | not-applicable | procage is a library that calls no model and runs no agent; LLM-written code is the adversary inside the child, modelled under STRIDE |
| misinformation | not-applicable | procage is a library that calls no model and runs no agent; LLM-written code is the adversary inside the child, modelled under STRIDE |
| hidden-context-exposure | not-applicable | procage is a library that calls no model and runs no agent; LLM-written code is the adversary inside the child, modelled under STRIDE |
| vector-embedding-weakness | not-applicable | procage is a library that calls no model and runs no agent; LLM-written code is the adversary inside the child, modelled under STRIDE |
| improper-output-handling | not-applicable | procage is a library that calls no model and runs no agent; LLM-written code is the adversary inside the child, modelled under STRIDE |
| model-extraction | not-applicable | procage is a library that calls no model and runs no agent; LLM-written code is the adversary inside the child, modelled under STRIDE |
| goal-hijack | not-applicable | procage is a library that calls no model and runs no agent; LLM-written code is the adversary inside the child, modelled under STRIDE |
| tool-misuse | not-applicable | procage is a library that calls no model and runs no agent; LLM-written code is the adversary inside the child, modelled under STRIDE |
| identity-privilege-abuse | not-applicable | procage is a library that calls no model and runs no agent; LLM-written code is the adversary inside the child, modelled under STRIDE |
| agentic-supply-chain | not-applicable | procage is a library that calls no model and runs no agent; LLM-written code is the adversary inside the child, modelled under STRIDE |
| unexpected-code-execution | not-applicable | procage is a library that calls no model and runs no agent; LLM-written code is the adversary inside the child, modelled under STRIDE |
| memory-context-poisoning | not-applicable | procage is a library that calls no model and runs no agent; LLM-written code is the adversary inside the child, modelled under STRIDE |
| insecure-inter-agent-communication | not-applicable | procage is a library that calls no model and runs no agent; LLM-written code is the adversary inside the child, modelled under STRIDE |
| cascading-failure | not-applicable | procage is a library that calls no model and runs no agent; LLM-written code is the adversary inside the child, modelled under STRIDE |
| human-agent-trust-exploitation | not-applicable | procage is a library that calls no model and runs no agent; LLM-written code is the adversary inside the child, modelled under STRIDE |
| rogue-agent | not-applicable | procage is a library that calls no model and runs no agent; LLM-written code is the adversary inside the child, modelled under STRIDE |

## Mitigations

| ID | Mitigation | Kind | Threats | Requirements | Touchpoints | Status |
|---|---|---|---|---|---|---|
| `mitigation.claim-from-matrix` | The published claim lists exactly the matrix cases, says Linux case-folding is untested where it is, and the threat model gains the escape class with its canary | detective | `threat.claim-overstates` | SR-010 | `site/content/docs/macos.md`, `crates/procage/THREAT_MODEL.md` | verified |
| `mitigation.exact-or-refuse` | The matrix measures what Seatbelt does per spelling; the canonicaliser emits the matching spelling or refuses the rule with a typed error | preventive | `threat.case-miss`, `threat.unicode-miss` | SR-007 | `crates/procage/src/macos/canon.rs`, `crates/procage/tests/spelling_macos.rs` | verified |
| `mitigation.mount-by-descriptor` | The mount applies to the descriptor of the resolved object, never to the path name again | preventive | `threat.resolve-then-remount`, `threat.mount-redirect`, `threat.hide-redirect` | SR-003 | `crates/procage/src/linux/sys.rs` | verified |
| `mitigation.named-failure` | The spawn error names the path, the component that is a link and the mount kind; vanished snapshot covers keep their skip, declared mounts stay strict | detective | `threat.spawn-sabotage` | SR-006 | `crates/procage/src/linux/spawn.rs`, `crates/procage/src/linux/mod.rs` | verified |
| `mitigation.no-fallback` | A kernel without the needed calls gives a typed error at cage build; there is no path-mount fallback | preventive | `threat.kernel-fallback` | SR-004 | `crates/procage/src/linux/sys.rs`, `crates/procage/src/linux/probe.rs` | verified |
| `mitigation.no-follow-resolution` | The parent prepares and the child resolves every source and target beneath its planned root without following links in any component; a link fails the spawn with a typed error naming the path | preventive | `threat.mount-redirect`, `threat.hide-redirect`, `threat.source-redirect` | SR-002 | `crates/procage/src/linux/sys.rs`, `crates/procage/src/linux/spawn.rs` | verified |
| `mitigation.no-widening` | No rule is folded or normalised into a broader match; on a case-sensitive volume a rule covers its exact name | preventive | `threat.fold-overgrant` | SR-008 | `crates/procage/src/macos/canon.rs`, `crates/procage/src/macos/spawn.rs` | verified |
| `mitigation.race-canary` | Escape canary per mount kind (protect, hide, data-class cover, socket cover, grant bind) with a deterministic link-planting hook as positive control and 10,000 racing attempts, run before and after the change | detective | `threat.vacuous-canary`, `threat.mount-redirect`, `threat.hide-redirect`, `threat.source-redirect` | SR-001 | `crates/procage/tests/escape_linux.rs` | verified |
| `mitigation.spelling-matrix` | Caged matrix on case-insensitive and case-sensitive APFS, composed and decomposed names, nested links, missing leaves and firmlinks, and a Linux case-folding directory where the lane has one; fails, never skips | detective | `threat.vacuous-canary`, `threat.case-miss`, `threat.unicode-miss` | SR-009 | `crates/procage/tests/spelling_macos.rs`, `.github/workflows/ci.yml` | verified |
| `mitigation.syscalls-only` | Every path and buffer is prepared in the parent; the child's sequence is listed in the plan and tested with a multithreaded parent | preventive | `threat.child-unsafe` | SR-005 | `crates/procage/src/linux/sys.rs`, `crates/procage/tests/spawn_linux.rs` | verified |

## Security Requirements

### SR-001 (P1) — verified

An escape canary MUST, for each T1 mount kind (protect, hide, data-class cover, socket cover, pin), replace a target component with a symbolic link or another directory between plan and mount, both at a deterministic hook and in racing attempts (10,000 in CI), and MUST record the outcome before and after the change.

- **Given** the build before the change and the deterministic hook, **when** the link is planted for each mount kind, **then** the canary records whether the mount was redirected
- **Given** the build after the change, **when** 10,000 racing attempts run per mount kind, **then** no spawn runs with a redirected mount
- Mitigations: `mitigation.race-canary`
- Tasks: T001 ✓, T005 ✓
- Verification `verification.sr-001.2026-11-03`: test → pass (verified) — `crates/procage/tests/escape_linux.rs::r33_a_planted_link_or_directory_cannot_move_a_mount, crates/procage/tests/escape_linux.rs::r33_racing_a_planted_link_never_moves_a_mount`
- Verification `verification.sr-001.2026-11-03-2`: test → pass (verified) — `crates/procage/tests/escape_linux.rs::r33_a_planted_link_or_directory_cannot_move_a_mount`

### SR-002 (P1) — verified

On T1 every mount source and target MUST be resolved beneath its planned root without following a symbolic link in any component; a link MUST fail the spawn with a typed error naming the path, even when the link points into a path the child may write.

- **Given** a protected directory replaced by a link to another directory before the child mounts, **when** the spawn runs, **then** it fails with an error naming the path and the link target is unchanged
- **Given** a hidden file whose parent directory became a link, **when** the spawn runs, **then** it fails the same way
- **Given** a pin whose path was replaced by a link into the writable workspace, **when** the spawn runs, **then** it fails the same way
- Mitigations: `mitigation.no-follow-resolution`
- Tasks: T002 ✓, T003 ✓
- Verification `verification.sr-002.2026-11-03`: test → pass (verified) — `crates/procage/tests/escape_linux.rs::r33_a_planted_link_or_directory_cannot_move_a_mount`
- Verification `verification.sr-002.2026-11-03-2`: test → pass (verified) — `crates/procage/tests/escape_linux.rs::r33_a_planted_link_or_directory_cannot_move_a_mount`

### SR-003 (P1) — verified

The mount MUST apply to exactly the object planned: the child MUST check the resolved object's device and inode against the plan and attach by descriptor, and no step MUST resolve the path name again afterwards.

- **Given** a hook that renames a planned directory away and moves another real directory into its place, **when** the child mounts, **then** the spawn fails and the moved-in directory is not covered
- Mitigations: `mitigation.mount-by-descriptor`
- Tasks: T002 ✓
- Verification `verification.sr-003.2026-11-03`: test → pass (verified) — `crates/procage/tests/escape_linux.rs::r33_a_planted_link_or_directory_cannot_move_a_mount`
- Verification `verification.sr-003.2026-11-03-2`: test → pass (verified) — `crates/procage/tests/escape_linux.rs::r33_racing_a_planted_link_never_moves_a_mount`

### SR-004 (P1) — verified

If the kernel lacks a call needed to resolve without following links or to mount by descriptor, T1 MUST be unavailable (the probe makes the same calls): the default is T2 with its typed gaps, a cage that asks for T1 MUST fail with Unsupported::Tier, and no mount MUST fall back to a path name.

- **Given** the T1 probe, **when** it runs, **then** it mounts its tmpfs with fsopen, fsmount, openat2 and move_mount, so a host without them reports no T1
- **Given** the child sequence, **when** it is reviewed, **then** no mount call takes a path name except the propagation change of the root
- Mitigations: `mitigation.no-fallback`
- Tasks: T004 ✓
- Verification `verification.sr-004.2026-11-03`: review → pass (verified) — `crates/procage/src/linux/sys.rs probe_userns (open_planned, bind_planned, tmpfs_planned); crates/procage/src/linux/sys.rs ChildPlan::run (only mount() call is MS_REC|MS_PRIVATE on /)`
- Verification `verification.sr-004.2026-11-03-2`: review → pass (verified) — `crates/procage/src/linux/sys.rs:1090`

### SR-005 (P2) — verified

The child's mount sequence MUST issue system calls only, with every path and buffer prepared in the parent, and MUST be covered by the multithreaded spawn test.

- **Given** a parent whose other threads allocate and lock continuously, **when** 1,000 T1 spawns run with the new sequence, **then** all complete and the child sequence contains no allocation (review of the sys module)
- Mitigations: `mitigation.syscalls-only`
- Tasks: T002 ✓, T010 ✓
- Verification `verification.sr-005.2026-11-03`: test → pass (verified) — `crates/procage/tests/spawn_linux.rs::t1_mounts_from_a_busy_multithreaded_parent`
- Verification `verification.sr-005.2026-11-03-2`: test → pass (verified) — `crates/procage/tests/spawn_linux.rs::t1_mounts_from_a_busy_multithreaded_parent`

### SR-006 (P2) — verified

A spawn refused for a moved mount MUST return SpawnError::MountMoved naming the planned path and, if there is one, the link; vanished snapshot covers MUST keep being skipped and declared mounts MUST stay strict.

- **Given** a planted link, **when** the spawn fails, **then** the error names the planned path and the link
- **Given** the existing spawn and escape suites, **when** they run, **then** they pass unchanged
- Mitigations: `mitigation.named-failure`
- Tasks: T003 ✓, T005 ✓
- Verification `verification.sr-006.2026-11-03`: test → pass (verified) — `crates/procage/tests/escape_linux.rs::r33_a_planted_link_or_directory_cannot_move_a_mount, crates/procage/tests/spawn_linux.rs::a_socket_removed_during_the_spawn_does_not_fail_it`
- Verification `verification.sr-006.2026-11-03-2`: test → pass (verified) — `crates/procage/tests/spawn_linux.rs::a_socket_removed_during_the_spawn_does_not_fail_it`

### SR-007 (P1) — verified

On macOS a rule whose spelling differs from the on-disk name (case on a case-insensitive volume, Unicode form) MUST enforce on the file under every spelling the volume treats as the same name, or the cage MUST be refused with a typed error naming the rule; it MUST NOT silently match nothing.

- **Given** a case-insensitive APFS volume and a read deny spelled in another case than on disk, **when** the child reads the file by its on-disk spelling, **then** it is denied, or the cage was refused
- **Given** a name decomposed on disk and composed in the rule, **when** the child accesses it, **then** the result equals that of the on-disk spelling, or the cage was refused
- Mitigations: `mitigation.exact-or-refuse`
- Tasks: T007 ✓
- Verification `verification.sr-007.2026-11-03`: test → pass (verified) — `crates/procage/tests/spelling_macos.rs::every_spelling_enforces_on_the_default_volume`
- Verification `verification.sr-007.2026-11-03-2`: test → pass (verified) — `crates/procage/tests/spelling_macos.rs::every_spelling_enforces_on_the_default_volume`

### SR-008 (P1) — verified

No allow MUST be widened by case folding or normalisation: an allow rule, an allowed Unix socket or a grant on a case-sensitive volume MUST refuse the cage with SpawnError::CaseSensitive naming the path, since Seatbelt would also allow its case variants.

- **Given** a case-sensitive APFS disk image with a write rule for a, **when** the cage is built, **then** it fails with CaseSensitive naming the path
- **Given** a grant bound to a path on that image, **when** the spawn runs, **then** it fails the same way
- **Given** a deny for a on that image, **when** the child reads A, **then** it is denied
- Mitigations: `mitigation.no-widening`
- Tasks: T006 ✓, T007 ✓
- Verification `verification.sr-008.2026-11-03`: test → pass (verified) — `crates/procage/tests/spelling_macos.rs::a_case_sensitive_volume_refuses_allows_and_keeps_denies, crates/procage/tests/escape_macos.rs::r37_an_allow_on_a_case_sensitive_volume_is_refused`
- Verification `verification.sr-008.2026-11-03-2`: test → pass (verified) — `crates/procage/tests/spelling_macos.rs::a_case_sensitive_volume_refuses_allows_and_keeps_denies`

### SR-009 (P1) — verified

The spelling matrix MUST run as caged tests on the default volume and on a case-sensitive APFS image with case and Unicode variants, nested links, missing leaves and firmlinks; a macOS lane that cannot create the image MUST fail, not skip. Linux case-folding directories are untested and the docs MUST say so.

- **Given** each macOS lane, **when** the matrix runs, **then** every case enforces as intended or is refused
- **Given** a macOS lane where the disk image cannot be created, **when** the matrix runs, **then** it fails
- Mitigations: `mitigation.spelling-matrix`
- Tasks: T007 ✓, T011
- Verification `verification.sr-009.2026-11-03`: review → inconclusive (implemented-unverified) — `.github/workflows/ci.yml (Spelling matrix step in the macOS job); crates/procage/tests/spelling_macos.rs Image::new asserts`
- Verification `verification.sr-009.2026-11-03-2`: test → pass (verified) — `crates/procage/tests/spelling_macos.rs::a_case_sensitive_volume_refuses_allows_and_keeps_denies`

### SR-010 (P2) — verified

The published canonicalisation claim MUST list exactly the cases the matrix covers and say where Linux case-folding is untested, and the threat model MUST carry the escape class for setup that follows a planted link with the race canary as evidence.

- **Given** the claim and the matrix, **when** they are compared, **then** every claimed case has a test and every test a claim
- **Given** the threat model, **when** it is read, **then** it lists the class with the race canary
- Mitigations: `mitigation.claim-from-matrix`
- Tasks: T008 ✓
- Verification `verification.sr-010.2026-11-03`: test → pass (verified) — `crates/procage/tests/threat_model.rs::gate`
- Verification `verification.sr-010.2026-11-03-2`: review → pass (verified) — `site/content/docs/macos.md:28`
