# Tasks: Explain and diff, checked against the kernel

## Phase 1: Foundational (policy crate)

- [X] T001 [SR-009] SBPL regex subset as a Thompson NFA over bytes (`^ $ . \ [..] [^..] ( | ) * + ? {m,n}`; anything else is a parse error), with unit tests over every regex the lowering emits and a long-path linear-time case — crates/procage-policy/src/explain/regex.rs
- [X] T002 macOS lowering emits its blocks (quiet, allow, within, hard, marker) as rules tagged with their origin (`Decider`) before reasons are stripped and rules merged; `lower` keeps its output byte-identical (preset fixtures unchanged) — crates/procage-policy/src/lower/macos.rs
- [X] T003 [SR-006] [SR-007] Types `Op` (`MODELLED` = read, write, exec; `Other(String)` answers not modelled), `Question` (`mode` default `0o644`), `Context`, `Decision`, `Decider`, `Answer`, `Change`, `Remedy`, `ExplainError::NotCanonical { canonical: Option<AbsPath> }`; the canonical check (lexical form; macOS `/etc`, `/tmp`, `/var` → `/private/…`) — crates/procage-policy/src/explain/mod.rs, crates/procage-policy/src/lib.rs

## Phase 2: User Story 1 — Why was this denied? (P1)

- [X] T004 [US1] [SR-007] macOS evaluator: last matching rule in profile order; read `file-read-data`, write `file-write-data`, exec `process-exec`; ops by name or `*` prefix; `literal`, `subpath`, `regex`, `path-ancestors`, grant `extension`, `file-mode`; any other filter on a modelled op makes the answer `NotModelled` — crates/procage-policy/src/explain/macos.rs
- [X] T005 [US1] [SR-004] Linux evaluator: rights per op, unhandled rights allowed, union of covering Landlock rules (grants from the context), attribution to the policy rule, grant, layer entry or base; T1 masks and read-only binds; classes with the context's homes, system paths and `anywhere` names under writable trees, with the spawn caveat; T2 piecewise hides with the piecewise caveat — crates/procage-policy/src/explain/linux.rs
- [X] T006 [US1] [SR-005] Remedy: up to three narrowest changes for the deciding rule (literal rule of the asked access, waiver of the deciding class, removal of the deciding protect or hide rule), each re-lowered (approximations it needs accepted and listed) and re-asked; carries the diff of the change; none if nothing flips — crates/procage-policy/src/explain/mod.rs
- [X] T007 [US1] [SR-005] [SR-006] [SR-007] Unit tests: each rule kind on each target, `.git/hooks/x` → trust-handoff with that waiver, non-canonical paths name their canonical form, pattern characters literal, `Op::Other` not modelled under every preset, every remedy of generated denied questions flips — crates/procage-policy/tests/explain.rs
- [X] T008 [US1] [SR-006] `Cage::explain(op, path, &Grants)` on both backends: resolve the path (or its parent for a missing file), bind grants as a spawn would, homes on Linux; `SpawnError::Explain` — crates/procage/src/macos/mod.rs, crates/procage/src/linux/mod.rs

## Phase 3: User Story 3 — The oracle guards the semantics (P1)

- [X] T009 [US3] [SR-001] [SR-002] [SR-003] Oracle: per lane, every preset v1–v3 and a rule-kinds policy (+ exec of the test binary); a generated tree with at least 1,000 read/write questions per policy and target answered by one caged child (`O_RDONLY`, `O_WRONLY` without truncation, errno printed), exec questions as caged spawns of copies of `true` (one set-user-ID on macOS); classification allowed/denied/unresolved; fail on any disagreement or unresolved question naming it; every rule kind reached; flipping the answers of one kind is detected; covered ops equal `MODELLED` — crates/procage/tests/oracle.rs
- [X] T010 [US3] [SR-001] Run the oracle on macOS (`cargo test -p procage --test oracle`), Linux T1 and T2 (`just linux-t1`, `just linux`); fix every disagreement in the evaluator, never in the oracle's classification — crates/procage-policy/src/explain/

## Phase 4: User Story 2 — What does this change allow? (P2)

- [X] T011 [US2] [SR-008] [SR-009] `diff(a, b, targets, options)`: multiset difference of tagged rules (macOS) or Landlock rules, mounts, classes and seccomp rules (Linux); added allow or removed deny loosens, the opposite tightens; every other differing plan field, base, preset tag and waivers as settings; `PathSet::contains` and `DiffEntry::covers` — crates/procage-policy/src/explain/diff.rs
- [X] T012 [US2] [SR-008] [SR-009] Diff tests: generated pairs × generated questions (every differing answer covered with the right direction), one more writable path or waiver, a T2-only change tagged T2, preset vN→vN+1 entries all from the base with the base setting, 10,000-rule pairs under a second — crates/procage-policy/tests/explain.rs

## Phase 5: Polish

- [X] T013 [SR-009] Explain timing: the spawn bench prints the release time per question for the largest preset and a maximum-length path; a debug test bounds it loosely — crates/procage/benches/spawn.rs, crates/procage-policy/tests/explain.rs
- [X] T014 [SR-003] [SR-010] Docs: site page `explain.md` (proven operations per target, answer fields, caveats, relay guidance), crate docs, README feature line, CHANGELOG Added; a test compares the page's proven list with `MODELLED` — site/content/docs/explain.md, crates/procage-policy/src/explain/mod.rs, README.md, CHANGELOG.md
- [X] T015 Gates: `just ci`, `just escape`, `just linux`, `just linux-t1`; results in specs/042-explain/quickstart.md; spec status Implemented; commit on `main`

## Phase 6: Convergence

- [X] T016 Assert that diffing every preset's v2 and v3 yields no loosening entry on any target, in crates/procage-policy/tests/explain.rs, per US2/AC1 (partial)
