---

description: "Task list for 006-base-profile"
---

# Tasks: A base profile that lets ordinary programs start

## Phase 1: Foundational

- [X] T001 [SR-002] Add `Base::{None, V1}` (`#[non_exhaustive]`, default `None`, serde kebab) and `Policy.base` in `crates/procage-policy/src/policy.rs`, the serde field in `format.rs`, `Construct::BaseV1` (`base-v1`) in `lower/mod.rs`, `sbpl::Filter::IpcPosixName` and `linux::RuleTarget::PathIfExists`.
- [X] T002 [SR-001] [SR-004] [SR-005] Create `crates/procage-policy/src/base.rs` with the documented V1 content constants (macOS: system code dirs, data dirs, metadata literals, devices, sysctl, services, shared memory; Linux: system dirs, `/etc`, devices), plus `macos_v1(tty) -> Vec<sbpl::Rule>` (terminal devices only with `Tty::Inherit`) and `linux_v1(tty, handled) -> Vec<LandlockRule>`.

## Phase 2: US1/US2 - lowering and kernel evidence (P1)

- [X] T003 [US1] [SR-003] Lower `Base::V1` into the allow block in `lower/macos.rs` and into Landlock rules in `lower/linux.rs` (exact on all targets), then add the `base-v1` row to `src/lowering.md` with the note "Linux content verified with Linux spawning (008)".
- [X] T004 [US1] [SR-002] [SR-003] [SR-004] [SR-005] Write `crates/procage-policy/tests/base.rs`:
  - pinned macOS lines (None and Inherit) and pinned Linux rules at ABI 6;
  - base allows precede the protect deny and the hard-deny tier;
  - no `/dev/tty` rule with `Tty::None`, and the terminal allows before the TIOCSTI deny with `Inherit`;
  - base services disjoint from the hard-deny service names;
  - no `/Users`, `/private/var/folders`, `/private/tmp` or `/Volumes` path in the base;
  - the empty policy still has no allow.

  Add a `BaseV1` reference policy in `tests/common/mod.rs`, plus a round-trip.
- [X] T005 [US1] [SR-006] Add caged tests `base_runs_ordinary_programs` to `tests/spawn_macos.rs`: `id -un` equals the user name outside, `date +%Z` equals outside, `uname -a`, `sh`/`zsh`/`bash -c` in a granted working directory, `cat`/`sort`/`sed`/`awk`, `xxd` on `/dev/urandom`, `perl -e 1`, `tar --version`, `gzip -V`; a Rust child (the test binary) without an extra sysctl rule; a child with `Stdio::null()` for all three streams.
- [X] T006 [US2] [SR-001] Add the caged test `base_grants_nothing_personal`: under base V1 alone, `ls $HOME` and `stat $HOME/.zshrc` (or of `$HOME` itself) are refused; reading a temp-dir file, creating a `/tmp` file and `nc` to loopback are refused.

## Phase 3: Polish

- [X] T007 [SR-006] Docs: `base.rs` module docs (content with a reason per entry, verified programs, release, Xcode shims not covered); `macos` module docs (point to `Base::V1`); crate example uses the base; README and THREAT_MODEL release status ("ships base profile V1 for macOS").
- [X] T008 Inject the three quickstart defects, confirm each is caught, and record the results.
- [X] T009 Run `just ci`, record the outcomes, record the decision (a curated base list, not `system.sb`; macOS 27 still untested), and commit on `main`.
