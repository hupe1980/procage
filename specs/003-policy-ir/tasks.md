---

description: "Task list for 003-policy-ir"
---

# Tasks: Portable policy IR and its lowering to each backend

**Input**: Design documents from `specs/003-policy-ir/`

**Prerequisites**: plan.md, spec.md, research.md, data-model.md, contracts/, quickstart.md

**Tests**: The spec requires them. SC-001 to SC-007 and FR-016, FR-023 and FR-024 make tests and fuzz targets deliverables.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: can run in parallel (different files, no dependencies)
- **[Story]**: US1 lower or gap, US2 untrusted paths, US3 limits, US4 data format
- `[SR-###]` tags sit on the first line of each security task
- `P/` = `crates/procage-policy/`

---

## Phase 1: Setup

- [X] T001 Update `P/Cargo.toml`:
  - features `serde = ["dep:serde"]` and `unstable-operations = []`;
  - optional `serde = { version = "1", default-features = false, features = ["derive", "alloc"] }`;
  - dev-dependency `serde_json = "1"`;
  - description "Portable sandbox policy and its lowering for procage (unpublished)".

  Add `exclude = ["crates/procage-policy/fuzz"]` to the root `Cargo.toml`
  workspace. Run `cargo deny --workspace check`.
- [X] T002 [P] Create `P/tests/common/mod.rs` with:
  - a deterministic xorshift64* generator (`Rng::new(seed)`, `u64`, `below(n)`, `bytes(len)`, `pick`);
  - `decode_sbpl_string(&str) -> Option<Vec<u8>>`, a strict reader of `"…"` that knows only `\\` and `\"` and returns `None` on anything else, including an unbalanced quote.

---

## Phase 2: Foundational (value types and skeleton)

- [X] T003 [P] Implement `P/src/name.rs`: `GrantName [a-z0-9_-]{1,32}`, `Tag [A-Za-z0-9._-]{1,64}`, `Name [A-Za-z0-9._-]{1,128}`, `OperationName [a-z0-9*-]{1,64}`, `Port` (1–65535), and `NameError { kind, value }` with `Display`/`Error`. Each type has `TryFrom<&str>`, `as_str`, and unit tests [SR-004]
- [X] T004 [P] Implement `AbsPath(Vec<u8>)` in `P/src/path.rs`. Rules: "starts with `/`; no NUL; no empty, `.` or `..` component; no trailing `/` except `/`". Errors `PathError::{Empty, Relative, Nul{at}, EmptyComponent{at}, DotComponent{at}, DotDotComponent{at}, TrailingSlash}`. Methods: `TryFrom<&[u8]>`/`<&str>`, `as_bytes`, `components`, `parent`, `starts_with_path` (component-wise), `ancestors`, and `Display` (lossy, for messages only) [SR-003]
- [X] T005 [P] Implement `Glob` in `P/src/glob.rs`. It is absolute UTF-8 with no control characters. Tokens `*`, `**` (whole component only), `?`, `\x`; `[ ] { }` unescaped are refused. Errors `GlobError::{Empty, Relative, ControlCharacter{at}, UnsupportedSyntax{at, ch}, MisplacedDoubleStar{at}, TrailingEscape}`. `to_sbpl_regex()` produces `^…$` with `**/` → `(.*/)?`, a trailing `/**` → `(/.*)?`, `*` → `[^/]*`, `?` → `[^/]`, and every literal character in `\ . ^ $ | ? * + ( ) [ ] { }` escaped with a backslash [SR-002]
- [X] T006 [P] Implement `sbpl::quote(&[u8]) -> Result<String, EscapeError>` in `P/src/sbpl.rs`. It escapes `\` and `"`, and refuses invalid UTF-8 (`NotUtf8{at}`) and U+0000–U+001F and U+007F (`ControlCharacter{at, byte}`). Add `pub const INLINE_LIMIT: usize = 1016`. This is the only function in the crate that writes a `"` into SBPL [SR-001]
- [X] T007 Add the SBPL rule model to `P/src/sbpl.rs`: `Rule { effect, ops: Vec<&'static str or Operation>, filters: Vec<SbplFilter> }` and `SbplFilter`, whose string-bearing variants hold raw values. `render(rule, &mut Params)` quotes every value through `quote`, switches to `(param "P<n>")` above `INLINE_LIMIT`, and renders more than one filter as `(require-any …)`. Also add `Profile::write(tag, blocks) -> (String, params)` [SR-001]
- [X] T008 Implement the intent layer in `P/src/policy.rs`, per data-model.md, with its defaults: `Policy` (`#[non_exhaustive]`, `Default` = deny everything), `FsRule`, `Access`, `FsTarget`, `Network`, `Ports`, `Process`, `Exec`, `Signals`, `Ipc`, `EnvPolicy`, `Rlimits` (`core_bytes = 0`), `Tty` (default `None`), `HardDenyClass` (`#[non_exhaustive]`, nine classes, `Ord`, `ALL`, kebab names), `Grant`. `validate()` returns `PolicyError::{ExecConflict, EmptyProxy, GrantAccess, EmptyOperations}`
- [X] T009 [P] Implement the raw layer in `P/src/seatbelt.rs`: `Operation`, with exactly the 112 names of research R6 (`ALL`, `as_str`) and `Other(OperationName)` under `cfg(feature = "unstable-operations")`; `Effect`; `Filter` (data-model.md); `Rule`; `Layer`. There is no modifier type [SR-004]
- [X] T010 [P] Implement `P/src/linux.rs`:
  - `AccessFs`/`AccessNet`/`Scopes` bit constants;
  - `handled_fs(abi)`, `handled_net(abi)`, `scopes(abi)` (the ABI table of research R7, clamped at 12);
  - `Syscall` (named variants used by the plans, plus `Other(SyscallName)`), `SeccompRule { syscall, condition: Condition::{Always, SocketFamily(u32 list), IoctlCommand(list), CloneWithoutThread, CloneNewNamespace} }`;
  - `Mount`, `Namespaces`, `LinuxNetwork`, `LandlockRule { target: RuleTarget::{Path(AbsPath), Grant(GrantName), ExpandGlob(Glob)}, access }`, `LinuxPlan`, `Layer`.
- [X] T011 Implement the skeleton in `P/src/lower/mod.rs`: [SR-005]
  - `Target`, `Tier`, `LowerOptions` (`max_rules` default 2000);
  - `Construct` (data-model list, kebab `Display`/`FromStr`, `ALL`), `Outcome`;
  - `CapabilityGap`, `GapKind`, `Degradation`, `TargetError`, `LowerError` (`Display`/`Error`);
  - `Hygiene`, `Plan`, `SeatbeltPlan`;
  - `lower()`: validate, then check the target (`LandlockTooOld` for T1 < 1, T2 < 4), then dispatch, then sort and return gaps.

  A gap collector `Gaps` records `(construct, outcome)`. An `Approximated`
  outcome becomes a degradation only when the construct is allowed, and an
  `Unsupported` outcome is always a gap.

**Checkpoint**: `cargo build -p procage-policy --target thumbv7em-none-eabihf` succeeds, and the unit tests pass.

---

## Phase 3: User Story 1 - one policy, an exact plan or typed gaps (Priority: P1) 🎯 MVP

**Goal**: lowering for macOS, T1 and T2 matches the published lowering table, with degradations recorded and the hard-deny tier last.

**Independent Test**: `cargo test -p procage-policy --test lowering_table --test gaps --test precedence`.

- [X] T012 [US1] Implement `P/src/lower/macos.rs`: [SR-001] [SR-005] [SR-007]
  - the allow block: fs Read/Write/Exec for literal, subpath and glob (`(regex …)` from `Glob::to_sbpl_regex`); grants (`(extension "procage.<name>")` plus a `GrantSlot`); network; `exec: Any`; fork; signals; IPC; raw allows;
  - the deny-within-allow block: protect, hide, raw denies;
  - the hard-deny block: the nine classes in enum order, minus waivers, with the R8 forms; rename anchors from Write roots and protect/hide paths; n/a classes emit nothing;
  - each block rendered, sorted bytewise and deduplicated;
  - `(deny default)`, or `(deny default (with message …))` from `options.tag`;
  - an `Unrepresentable` gap (construct of the rule, subject path) for each value `quote` refuses;
  - a `linux` layer present: an `Approximated` gap for `linux-layer`, which is ignored when allowed.
- [X] T013 [US1] Implement `P/src/lower/linux.rs`, per research R7: [SR-005]
  - namespaces and mounts for T1;
  - Landlock `handled_*` for the ABI, with REFER never granted and EXECUTE unhandled only for `exec: Any`;
  - path rules for subpath (exact), literal and glob (Approximated, glob as `ExpandGlob`), protect (T1 `ReadOnlyBind`, T2 Unsupported) and hide (T1 `Mask`, T2 Approximated);
  - grants as `RuleTarget::Grant`;
  - network modes and socket seccomp rules (None: deny all `socket`; UnixSockets by ABI ≥ 9; Loopback T1 Approximated / T2 Unsupported; Proxy T1 exact / T2 Unsupported);
  - fork and signal seccomp rules, with T2 signals needing ABI ≥ 6; IPC per R7;
  - the hard-deny seccomp rules, minus waivers;
  - `no_new_privs`;
  - a `seatbelt` layer: an `Approximated` gap for `seatbelt-layer`;
  - `linux` layer entries checked against `handled_fs(abi)` (`PolicyError` or `Unsupported` gap).

  The output is deterministic (sorted rules).
- [X] T014 [US1] Write `P/src/lowering.md` in the format of `contracts/lowering-table.md`: one row per `Construct` (32 rows), with outcomes from research R5, R7 and R8, and notes (errno for hide on T1; "expanded at spawn"; "compiles on 26.6.2 — enforcement verified by later features"). Include it as the doc of `pub mod lower` via `#![doc = include_str!("../lowering.md")]` in `P/src/lower/mod.rs`. The intro states what lowering produces and makes no enforcement claim [SR-006] [SR-011]
- [X] T015 [US1] Add to `P/tests/common/mod.rs` `reference_policy(Construct) -> Policy`: the smallest policy that exercises each construct. Hard-deny rows use a policy with a Write subpath and a protected child, so that rename anchors have input. Also add `reference_policies()`, which yields all of them plus three composite policies (agent workspace, build, read-only).
- [X] T016 [US1] Write `P/tests/lowering_table.rs`. It parses `P/src/lowering.md`: [SR-006]
  - the exact header, unique construct names, every `Construct::ALL` present once, and a cell grammar that includes `(ABI ≥ N) /`;
  - for every row × target × ABI set (`contracts/lowering-table.md`), it asserts the outcome semantics with and without `allow_degrade`;
  - failure messages name the construct, the target and the ABI.
- [X] T017 [P] [US1] Write `P/tests/gaps.rs`: [SR-005]
  - a policy with protect, glob and loopback on T2 returns all three gaps (complete and sorted) and no plan;
  - a literal with `fs-literal` allowed returns a plan with exactly one `Degradation`;
  - T2 at ABI 3 and T1 at ABI 0 return `TargetError::LandlockTooOld`;
  - `Exec::Never` with an Exec rule is `ExecConflict`;
  - `Proxy{None, None}` is `EmptyProxy`;
  - a grant with access Protect is `GrantAccess`;
  - an empty policy lowers on every target to deny-by-default plus the hard-deny tier.
- [X] T018 [P] [US1] Write `P/tests/precedence.rs`: [SR-007]
  - for every reference policy and 50 shuffles each (generator), the macOS profile is byte-identical and the Linux plan is equal;
  - block order: every allow comes before every deny-within-allow, and the hard-deny block is last;
  - a protect inside a write root yields `(deny file-write* (subpath P))` after the allow;
  - waiving one class removes exactly its rules and lists the waiver;
  - no waiver means all applicable classes are present;
  - duplicate rules collapse;
  - FR-018: the allow block of each composite policy equals the union of the allow blocks of its single-element policies, so no allow appears without a source. The empty policy has no allow rule.

**Checkpoint**: US1 passes its independent test.

---

## Phase 4: User Story 2 - untrusted path data never changes meaning (Priority: P1)

**Goal**: adversarial names stay data; relative paths, bad globs, operation names and identifiers are refused.

**Independent Test**: `cargo test -p procage-policy --test paths --test escaping`; `cargo test -p procage-kernel-facts --test policy_compiles`.

- [X] T019 [P] [US2] Write `P/tests/paths.rs`: [SR-003]
  - each `PathError` variant comes from its input (`relative/dir`, `~/dir`, `/a/../b`, `/a/./b`, `/a//b`, `/a/`, `/a\0b`, empty);
  - `/` is valid;
  - non-UTF-8 bytes round-trip through `as_bytes`;
  - `starts_with_path` is component-wise (`/ab` does not start with `/a`);
  - `ancestors` of `/a/b/c` is `[/a/b, /a, /]`;
  - 10,000 generated byte strings: accepted ⇔ the rules hold (an independent oracle in the test).
- [X] T020 [P] [US2] Write `P/tests/escaping.rs`: [SR-001] [SR-002] [SR-004]
  - quote: 10,000 generated byte strings (biased toward `" \ ( ) * ? [ ] { } . ^ $ |`, control bytes and invalid UTF-8) either decode back exactly with `decode_sbpl_string` or are refused with the right error;
  - the subpath `/tmp/a"b(c)*?[d]` lowers to exactly one `(subpath …)` that decodes to it, and is never emitted as a regex;
  - `/work/**/*.rs` lowers to `^/work/(.*/)?[^/]*\.rs$`;
  - for 10,000 generated globs, every literal character of the source shows up escaped in the regex (an independent oracle);
  - `[` and `{` are refused, and a misplaced `**` is refused;
  - a glob with no wildcard (`/work/a.txt`) still lowers to an anchored `(regex …)`, never to a literal;
  - a newline or non-UTF-8 path on macOS gives an `Unrepresentable` gap;
  - `OperationName` refuses `a(b`, `a b`, `a"b` and `no-sandbox)`;
  - `GrantName` refuses `a"b`, `a b` and `a/b`;
  - no rendered reference profile contains `(with` other than the tag form, or `no-sandbox`, or `no-profile`.
- [X] T021 [US2] Add `tests/kernel_facts/tests/policy_compiles.rs` (`#![cfg(target_os = "macos")]`) and a `[dev-dependencies] procage-policy = { path = "../../crates/procage-policy" }` in `tests/kernel_facts/Cargo.toml`. Using `procage_kernel_facts::sys::macos::Sandbox` it compiles: [SR-004] [SR-011]
  - every reference policy's macOS profile with its params;
  - a profile with a parameter-backed long path;
  - `(version 1)(deny default)(allow <op>)` for each `Operation::ALL`.

  Each failure prints the libsandbox message. The module doc states that compiling shows well-formedness only and is not evidence of enforcement.

**Checkpoint**: US2 passes its independent test.

---

## Phase 5: User Story 3 - large policies fail closed (Priority: P2)

**Goal**: a rule limit, the exact merge only, and parameters for long values.

**Independent Test**: `cargo test -p procage-policy --test limits`.

- [X] T022 [US3] In `P/src/sbpl.rs`, implement `merge_adjacent(rules, max_filters = 64)`. It merges neighbours only when they have the same effect and identical ops; an unfiltered rule absorbs its neighbours; filters are concatenated in order, in groups of at most 64. In `P/src/lower/macos.rs`, run the guard when `rule_count > max_rules`: merge, recount, then either set `merged = true` or return `LowerError::LimitExceeded { limit, rules }` [SR-008] [SR-009]
- [X] T023 [US3] Add `eval(rules, op, path) -> Effect` to `P/tests/common/mod.rs`: default deny; last match wins; literal, subtree (component boundary), extension and require-any matching; wildcard ops (`file-read*` matches `file-read-data`). Then write `P/tests/limits.rs`: [SR-008] [SR-009]
  - 10,000 generated rule lists (mixed effects and ops, literal and subpath filters) and requests: `eval(merge(r)) == eval(r)`;
  - merged rules never mix effects;
  - a 2,001-rule policy that cannot merge, at the default limit, gives `LimitExceeded { 2000, n }`;
  - a mergeable 5,000-literal policy lowers with `merged = true` and passes the limit;
  - a path whose quoted form is 1,017 bytes or more yields `(param "P0")`, and `params` holds the exact path, while 1,016 bytes stays inline.

---

## Phase 6: User Story 4 - policies as data (Priority: P2)

**Goal**: a versioned, strict, round-tripping format.

**Independent Test**: `cargo test -p procage-policy --features serde --test format`.

- [X] T024 [US4] Implement `P/src/format.rs` (`cfg(feature = "serde")`), per `contracts/data-format.md`: [SR-010]
  - derives with `deny_unknown_fields` and kebab-case enums;
  - `try_from`/`into` for `AbsPath` (string or byte array), `Glob`, the names and `Port`;
  - `Policy` through a `PolicyRepr` with `version: 1`;
  - `HardDenyClass` and `Construct` as kebab strings; the seatbelt and linux layers.
- [X] T025 [US4] Write `P/tests/format.rs` (feature `serde`, serde_json): [SR-010]
  - every reference policy, plus one with a non-UTF-8 path (`[47, 255]`), round-trips equal;
  - the example in `contracts/data-format.md` parses;
  - an unknown field at the top level and inside `FsRule` is refused, naming the field;
  - version 2 and a missing version are refused;
  - a relative path, a malformed glob, an unknown hard-deny class, an unknown operation and an operation name containing `(` are each refused with the constructor's message;
  - 10,000 generated JSON mutations of reference documents never panic, and every accepted one round-trips.

---

## Phase 7: Polish and cross-cutting

- [X] T026 Create the cargo-fuzz package `P/fuzz/`: `Cargo.toml` with its own `[workspace]`, `libfuzzer-sys` 0.4 and `procage-policy` with `serde`; `serde_json`; `publish = false`. It has four targets in `P/fuzz/fuzz_targets/`: [SR-001] [SR-010]
  - `quote.rs`: decode equals the input, or refused;
  - `glob.rs`: parse; every literal escaped;
  - `format.rs`: read JSON; accepted documents round-trip;
  - `lower.rs`: build a `Policy` from bytes, lower it for all targets, never panic.

  Add the recipes `fuzz target="quote" secs="60"` and `fuzz-all secs="60"` to `justfile`, using `cargo +nightly fuzz run … -- -max_total_time=…`.
- [X] T027 [P] Extend the `no-std` recipe in `justfile` to also build `--features serde`. Add a `fuzz` job to `.github/workflows/ci.yml` (ubuntu, nightly, cargo-fuzz, `just fuzz-all 30`).
- [X] T028 Write the crate docs in `P/src/lib.rs`: the purpose (the portable policy and its lowering), the layers, a minimal example (a doctest that lowers for macOS and Linux T2), a link to the [`lower`] lowering table, and an explicit sentence that the crate applies nothing and that a plan says nothing about enforcement until procage applies and tests it. Re-export the main types. Review all rustdoc for enforcement wording [SR-011]
- [X] T029 Run `just fuzz-all 60`, all four targets. Record the executions and the result in `specs/003-policy-ir/quickstart.md` [SR-001] [SR-010]
- [X] T030 Inject the seven defects of `quickstart.md` one at a time (from backups in the scratchpad). Confirm that each fails its named test, restore byte for byte, and record the outcome in `quickstart.md`.
- [X] T031 Run `just ci` and `cargo test -p procage-policy --all-features`. Record scenarios 1–11 in `quickstart.md`.
- [X] T032 Record the decisions:
  - `Exec::{Granted, Any, Never}` replaces `Paths[..]`; Linux `Network::None` denies `socket()` outright; `UnixSockets` below ABI 9 is approximated on T1 and unsupported on T2;
  - the closed list of 112 operations measured on 26.6.2 (`default` and `*-message-send` excluded); nine fixed hard-deny classes; adjacent merge in groups of 64; `INLINE_LIMIT` 1016 measured on the quoted form.

---

## Dependencies & Execution Order

- Setup (T001–T002) → Foundational (T003–T011). T003–T006, T009 and T010 run
  in parallel; T007 needs T006; T008 needs T003–T005; T011 needs T008–T010.
- US1: T012 and T013 after T011; T014 after both; T015 → T016. T017 and T018
  run in parallel after T015.
- US2: T019 and T020 run in parallel after Phase 2; T021 after T015 and T012.
- US3: T022 after T012; T023 after T022 and T015.
- US4: T024 after Phase 2; T025 after T024 and T015.
- Polish: T026 after T024 and T013; T027 in parallel; T028 after T014;
  T029–T031 last; T032 last.

## Parallel Opportunities

- T003 ∥ T004 ∥ T005 ∥ T006 ∥ T009 ∥ T010.
- T017 ∥ T018 ∥ T019 ∥ T020.
- T024 ∥ US1 tests.

## Implementation Strategy

The MVP is US1: types, lowering for all targets, the table and its test. US2
hardens the inputs and proves well-formedness through libsandbox. US3 and US4
complete the safety properties. Polish adds fuzzing, the docs and the recorded decisions.
Everything lands as one change; nothing is committed without authorization.

---

## Phase 8: Convergence

- [X] T033 Add a test in `crates/procage-policy/tests/gaps.rs` that a raw Seatbelt rule without operations gives `PolicyError::EmptyOperations { index }` and that a Linux-layer path rule with protect or hide access gives `PolicyError::LandlockExtraAccess`, both through `lower()` on every target, per FR-012 and data-model `validate()` (partial)
