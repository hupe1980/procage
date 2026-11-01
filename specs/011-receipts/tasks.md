# Tasks: Receipts — evidence of how a run was caged

## Phase 1: Setup

- [X] T001 [SR-011] Dependencies in Cargo.toml (workspace: `serde` 1 with `derive`, `sha2` 0.11 without default features beyond what hashing needs; `serde_json` moved to both systems) and crates/procage/Cargo.toml (`procage-policy` with `serde`); `cargo deny check` passes

## Phase 2: Foundational

- [X] T002 [SR-001] `policy_digest(&Policy) -> String` in crates/procage/src/receipt.rs: a canonical copy (sort `fs`, `grants`, `ipc.unix_sockets`, the environment allowlist and the Linux layer's lists; keep the Seatbelt layer's rule order, which changes meaning), serialised with the policy's own serde form, SHA-256, `sha256:<hex>`
- [X] T003 [SR-002] [SR-003] [SR-004] [SR-008] [SR-010] `Receipt`, `ReceiptBackend`, `ReceiptExit`, `ReceiptViolations`, `ReceiptRelaxation`, `ReceiptApproximation` (`#[non_exhaustive]`, serde, `deny_unknown_fields` on every map, `"version": 1` refused otherwise), `Receipt::{to_json, from_json}`, `ReceiptError`; `CageFacts` (crate-private) with `enforced_as_written` computed from the three lists; re-exports in crates/procage/src/lib.rs

## Phase 3: User Story 1 — proof of caging (P1)

- [X] T004 [US1] [SR-006] [SR-007] macOS: `kern.osproductversion` next to `os_build` in crates/procage/src/macos/sys.rs; `CageFacts` built in `Cage::with_options` (crates/procage/src/macos/mod.rs); `Child` holds the facts, the bound grant names and a `killed` flag set by `kill_all` (crates/procage/src/macos/child.rs); `Child::receipt`
- [X] T005 [US1] [SR-006] [SR-007] Linux: kernel release from `/proc/sys/kernel/osrelease`, tier, ABI and errata from the plan and the probe; the same wiring in crates/procage/src/linux/mod.rs and crates/procage/src/linux/child.rs
- [X] T006 [US1] [SR-005] `CageOptions::with_policy_in_receipt` on both backends: the receipt then holds the policy and the relaxation subjects
- [X] T007 [US1] [SR-001] [SR-004] [SR-008] [SR-010] crates/procage/tests/receipts.rs (new, both systems): fields per backend (and tier on Linux), `None` while running, exit code and signal, `ended_by_caller` after `kill_all`, coverage off/observed, grant names sorted, equal digests for equal policies (rules in another order) and different ones for any change, a fixed digest for a reference policy

## Phase 4: User Story 2 — a relaxed run says so (P1)

- [X] T008 [US2] [SR-002] Both `Cage::fit` store the relaxations in the facts; tests in crates/procage/tests/receipts.rs: `enforced_as_written` false with an approximation, a relaxation, a waiver; true for a preset with nothing accepted

## Phase 5: User Story 3 — stable format (P2)

- [X] T009 [US3] [SR-003] [SR-005] Round trip; refusal of version 2, of an unknown field at the top and in a nested map; canary strings in the environment, the arguments and the policy paths never appear in the JSON unless the policy is requested

## Phase 6: Polish

- [X] T010 [SR-009] Docs: "Receipts" in crates/procage/src/lib.rs (what a receipt proves and what not: unsigned, the caller's record, keep it outside paths a later run may write; macOS coverage is best effort; `Cage::exec` gives none), site/content/docs/receipts.md (new) and the site index, README feature line, CHANGELOG Added; the `PresetTag` doc line and the presets page now hold
- [X] T011 [SR-007] Gates: `just ci`, `just linux`, `just linux-t1`; the ignored `latency` probes (spawn_macos, spawn_linux) before and after, within noise (SC-003); results in specs/011-receipts/quickstart.md
- [X] T012 Record the decision; commit on `main`

## Dependencies

T001 → T002 → T003 → (T004, T005) → T006 → (T007, T008, T009) → T010 → T011 → T012.

## Phase 7: Security Convergence

**Purpose**: Close security gaps found by ThreatSpec converge on 2026-11-01 (commit 917721e).

- [X] T013 [SR-001] Add a test for SR-001 (The policy digest MUST be SHA-256 over one canonical encoding of the policy, its versioned serialised form (fixed field order, order-insensitive lists sorted, order kept only where it changes meaning, every path by its bytes, no omitted defaults), written sha256:<hex>; equal policies MUST have equal digests however they were built, and policies that differ in any rule, waiver, base or preset tag MUST have different digests) — touchpoints: crates/procage-policy/src/format.rs, crates/procage/src/receipt.rs, crates/procage/tests/receipts.rs [converge: implemented-unverified; The canonical copy (sorted fs, grants, sockets, env lists, Linux layer; Seatbelt order kept) is hashed over the versioned policy form, and the_digest_is_canonical covers fs-rule order, one waiver, one access and the pinned default digest, but no test reorders grants or sets, changes one path byte, the base or the preset tag, or digests after a round trip through the serialised form.]
- [X] T014 [SR-002] Add a test for SR-002 (The receipt MUST list every accepted approximation by construct, every fit relaxation with its lift and every waived hard-deny class held by the cage's plan, and MUST carry one field that says enforced as written only when all three lists are empty) — touchpoints: crates/procage/src/linux/mod.rs, crates/procage/src/macos/mod.rs, crates/procage/src/receipt.rs [converge: implemented-unverified; Both Cage::fit rebuild the facts with the relaxations and enforced_as_written is computed from the three lists; tests cover a waiver (exact), an approximation (only "any" match, not exactly the plan's entries) and a relaxation on Linux only, so the macOS fit path and exactness of the lists are untested.]
- [X] T015 [SR-003] Complete SR-003 (A receipt reader MUST refuse, with a typed error, a receipt of any version other than the ones it knows and a receipt holding any field or value it does not know, in any nested map; it MUST NOT present a receipt it only partly understood; older format versions MUST stay readable) — touchpoints: crates/procage/src/receipt.rs, crates/procage/tests/receipts.rs [converge: partial; deny_unknown_fields and the version check exist and tests refuse version 2, a top-level and an exit-level unknown field, but coverage and the relaxation fields are free strings so an unknown coverage value or relaxation kind is accepted, ReceiptError has no distinct unsupported-version variant, and unknown fields in backend, violations and a relaxation are untested.]
- [X] T016 [SR-004] Add a test for SR-004 (The violation summary MUST carry the record's coverage, completeness and dropped count; with coverage off or unavailable it MUST NOT carry a violation count) — touchpoints: crates/procage/src/receipt.rs, crates/procage/tests/receipts.rs [converge: implemented-unverified; count is set only for observed or system-calls coverage and dropped and complete come from the record; a test covers coverage off with no count, but none covers coverage unavailable or an observed macOS run whose record dropped reports.]
- [X] T017 [SR-005] Add a test for SR-005 (Without with_policy_in_receipt, the receipt MUST NOT contain environment values, command arguments, file contents, policy paths, grant paths, relaxation subjects, violation paths or process names; with it, the receipt MUST add only the policy and the relaxation subjects) — touchpoints: crates/procage/src/linux/mod.rs, crates/procage/src/macos/mod.rs, crates/procage/src/receipt.rs, crates/procage/tests/receipts.rs [converge: implemented-unverified; The receipt has no field for environment, arguments, file contents or process names and subjects are gated on the option; tests cover environment, argument, policy-path and grant-path canaries and subject absence on Linux, but not a file the child reads or a denied path, and the with-option run does not assert the canaries appear only inside the policy and subject fields.]
- [X] T018 [SR-006] Add a test for SR-006 (Every receipt field MUST come from the parent's cage and plan, the parent's own host fact reads, the kernel's reports and the reaped exit status; strings the caged code controls MUST NOT appear in a receipt) — touchpoints: crates/procage/src/linux/child.rs, crates/procage/src/macos/child.rs, crates/procage/src/macos/sys.rs, crates/procage/src/receipt.rs [converge: implemented-unverified; Facts come from the cage, plan, parent sysctl and /proc reads, the record's counts and the reaped status, so no child string reaches a receipt by inspection; no test runs a child with format-breaking names and paths and compares every field to the cage's values.]
- [X] T019 [SR-007] Add a test for SR-007 (The child's call sequence between fork and exec MUST be identical with and without receipts; the receipt MUST be built in the parent only) — touchpoints: crates/procage/src/linux/child.rs, crates/procage/src/macos/child.rs, crates/procage/src/macos/sys.rs, crates/procage/src/receipt.rs [converge: implemented-unverified; The diff adds receipt state only after spawn returns in the parent on both backends and leaves the pre-exec code unchanged; the spawn suites and a macOS latency probe are reported in quickstart.md, but no Linux latency comparison is recorded and no security review record covers the requirement.]
- [X] T020 [SR-008] Add a test for SR-008 (Child::receipt MUST return None until the child was reaped, and a receipt MUST carry the violation record's own completeness (never complete while the record is open); the exit MUST hold exactly one of code and signal, and ended_by_caller MUST be true only when kill_all or dropping the handle signalled the child while it was still running) — touchpoints: crates/procage/src/linux/child.rs, crates/procage/src/macos/child.rs, crates/procage/src/receipt.rs [converge: implemented-unverified; receipt returns None until try_wait sees an exit and killed is set only when kill_all found the child running; tests cover None while running, a normal exit and a kill_all run, but not a run ended by a signal the caller did not send, nor kill_all on an already-exited child yielding ended_by_caller false.]
- [X] T021 [SR-009] Complete SR-009 (The receipt docs MUST state that a receipt is the caller's own unsigned record and not an attestation, that whoever can write where it is kept can change it (so keep it outside every path a later run may write), that an empty complete record does not prove nothing was denied, that Cage::exec produces no receipt, that Child::receipt is None until the run exits, that it names the OS release and build or kernel release, and that with_policy_in_receipt adds every policy path and relaxation subject to each receipt of the cage) — touchpoints: crates/procage/src/lib.rs, crates/procage/src/receipt.rs, site/content/docs/receipts.md [converge: partial; Both docs say unsigned, not an attestation, keep it outside writable paths, and Cage::exec gives none, but neither states that an empty complete record does not prove nothing was denied, the crate docs name only the OS build or kernel (not the release), and neither says with_policy_in_receipt adds every policy path to each receipt of the cage.]

> 2026-11-01, remediation: coverage, construct and lift are typed, so a reader
> refuses unknown values; an unsupported version has its own error; tests for
> every nested map, every part of the digest (grants and variables reordered,
> round trip, base, preset, a rule, one path byte), a signal the child sent
> itself, `kill_all` after the exit, an observed run (count, no denied path or
> content), requested paths only inside the policy, output that looks like
> JSON; docs: an empty record proves nothing, host facts, every policy path
> with the option. Linux latency recorded.

## Phase 8: Security Convergence

**Purpose**: Close security gaps found by ThreatSpec converge on 2026-11-01 (commit 917721e).

- [X] T022 [SR-003] Add a test for SR-003 (A receipt reader MUST refuse, with a typed error, a receipt of any version other than the ones it knows and a receipt holding any field or value it does not know, in any nested map; it MUST NOT present a receipt it only partly understood; older format versions MUST stay readable) — touchpoints: crates/procage/src/receipt.rs, crates/procage/tests/receipts.rs [converge: implemented-unverified; Tests refuse version 2 with ReceiptError::UnsupportedVersion, unknown fields at the top level and in backend, violations and exit, an unknown coverage and base value, and round-trip the current version; ReceiptRelaxation has deny_unknown_fields and Construct refuses unknown names (crates/procage-policy/src/lower/mod.rs:196), but no test reads a receipt holding a relaxation with an added field or an unknown construct, although one is easy to build from the JSON on any lane.]
