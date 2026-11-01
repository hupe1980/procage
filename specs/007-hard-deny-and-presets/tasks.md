---

description: "Task list for 007-hard-deny-and-presets"
---

# Tasks: Data-driven hard denies and frozen presets

## Phase 1: Foundational

- [X] T001 [SR-004] Add `Glob::to_sbpl_regex_folded()` in `crates/procage-policy/src/glob.rs` (ASCII letters become `[xX]`, everything else as in `to_sbpl_regex`), with unit tests.
- [X] T002 [SR-005] Add `HardDenyClass::{Secrets, TrustHandoff, Persistence}` (appended to `ALL`, kebab names) and `PresetTag` with `Policy.preset` in `policy.rs`/`format.rs`, and `Construct::{HdSecrets, HdTrustHandoff, HdPersistence}`.
- [X] T003 [SR-001] [SR-002] [SR-003] Create `crates/procage-policy/src/presets.rs`: the frozen pattern lists of FR-002 to FR-004 and `patterns(class)`.

## Phase 2: US1/US2 - classes (P1)

- [X] T004 [US1] [SR-001] [SR-002] [SR-003] [SR-006] Emit the three classes in `lower/macos.rs` (secrets: read and write deny; handoff: write deny plus `.git` unlink deny; persistence: write deny) in the hard-deny block, as `n/a` on Linux. Add the three rows to `lowering.md` with the "pending on Linux (008)" note.
- [X] T005 [US1] [SR-001] [SR-004] Add caged tests:
  - `hard_deny_secrets`: with a `$HOME` read grant, listing `$HOME` works, while `~/.ssh`, `~/.aws`, `~/.gnupg` and `~/.SSH` are refused;
  - with `secrets` waived, listing `~/.ssh` works.
- [X] T006 [US2] [SR-002] [SR-003] [SR-004] Add caged tests:
  - `hard_deny_trust_handoff`: in a temp workspace with `.git/{hooks,objects}`, `.git/hooks/pre-commit`, `.git/config`, `.zshrc`, `.ZSHRC`, `.envrc`, `.vscode/settings.json` and `.GIT/HOOKS/x` are refused, `mv .git z` is refused, and `src/x` and `.git/objects/x` succeed;
  - with the class waived, the hook write works;
  - `hard_deny_persistence`: with a write grant on `~/Library/LaunchAgents`, creating a file there is refused and nothing is created.

## Phase 3: US3 - presets (P2)

- [X] T007 [US3] [SR-005] Add the presets `minimal`, `agent_readonly`, `agent_workspace` and `build` (v1) in `presets.rs`, per FR-007, tagged.
- [X] T008 [US3] [SR-005] Write `crates/procage-policy/tests/presets.rs`: the lowered macOS profile of each preset (workspace `/work`) equals `tests/fixtures/presets/<name>-v1.sb`; the class lines are pinned; the tags are correct; the data form round-trips. Add the four presets to `reference_policies()` in `tests/common/mod.rs`, so the libsandbox compile check covers them (FR-009).
- [X] T009 [US3] Add caged tests `preset_*`: `agent_workspace` (writes `W/src/x`, refused `W/.git/hooks/x` and `~/.ssh` reads, no network); `agent_readonly` (`W` write refused, read OK); `build` (a script written to `W` runs); `minimal` (`echo` runs).

## Phase 4: Polish

- [X] T010 [SR-006] Docs: the `presets` module (lists, presets, the Linux pending note, the git init/clone waiver note); the macos module docs; the README; the THREAT_MODEL release status; the 008 spec carries the Linux requirement.
- [X] T011 Inject the four defects and record the results.
- [X] T012 Run `just ci`, record the decision (Linux data classes pending until 008), record the outcomes, and commit on `main`.

---

## Phase 5: Convergence

- [X] T013 Extend `hard_deny_trust_handoff` so the child also writes `.git/index`, `.git/HEAD` and `.git/refs/heads/main` (allowed), per SC-003 (partial)
