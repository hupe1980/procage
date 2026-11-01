# Tasks: Base V3 and quiet records

## Phase 1: Foundational (policy crate)

- [X] T001 [SR-001] [SR-003] `Base::V3` in crates/procage-policy/src/policy.rs (serde `v3`, construct `base-v3`); `sbpl::Rule::quiet` rendered `(with no-report)` in crates/procage-policy/src/sbpl.rs; `base::macos_v3_quiet(tty)` in crates/procage-policy/src/base.rs; macOS lowering emits the quiet block before the allows in crates/procage-policy/src/lower/macos.rs; Linux lowers V3 as V2 in crates/procage-policy/src/lower/linux.rs; lowering.md row
- [X] T002 [SR-001] Presets v3 (minimal, agent_readonly, agent_workspace, build) in crates/procage-policy/src/presets.rs and fixtures crates/procage-policy/tests/fixtures/presets/*-v3.sb
- [X] T003 [P] [SR-001] [SR-002] Policy tests: every reference policy on V3 minus no-report lines equals its V2 profile; V1/V2 fixtures unchanged; v3 fixtures; quiet targets share none with hard-deny or data-class rules; on every Linux target the V3 plan equals the V2 plan (crates/procage-policy/tests/base.rs, presets.rs)
- [X] T004 [P] KF-M30 in crates/procage-kernel-facts: a no-report deny refuses without a log line; a later allow overrides it

## Phase 2: User Stories 1–2 (P1)

- [X] T005 [US2] [SR-004] `Violation::repeats` and merging in `Record::push` (exact key, saturating) with unit tests in crates/procage/src/violation.rs, including the cap (a kept entry keeps counting, a new key past the cap is dropped); `Display` appends the count
- [X] T006 [US1] [SR-003] crates/procage/tests/spawn_macos.rs: under V3 `/bin/ls` reports nothing; a logd lookup and the dtracehelper ioctl stay refused and unreported; `Tty::Inherit` still opens /dev/tty; the commands of the measured set that are installed succeed, with ≥ 95 % fewer entries than V2 and no quiet probe
- [X] T007 [US2] [SR-004] crates/procage/tests/spawn_macos.rs: a repeated denial (same path read 50 times) is one entry with repeats 50; crates/procage/tests/spawn_linux.rs: the 20,000-call flood is one entry with repeats 20,000 (both tiers)
- [X] T008 [SR-001] crates/procage/tests/escape_macos.rs: escape canaries also on Base V3 (with `PROCAGE_ESCAPE_BASE=v3`, in `just escape` and CI)

## Phase 3: User Story 3 (P2) and polish

- [X] T009 [US3] Docs: base versions table and what V3 silences in crates/procage/src/lib.rs, README.md, site/content/docs/{presets,macos,violations}.md
- [X] T010 Gates: `just ci`, the four Linux lanes, `just site`; results in specs/036-base-v3/quickstart.md
- [X] T011 Record the decision; commit on `main`
