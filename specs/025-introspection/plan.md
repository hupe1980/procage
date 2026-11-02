# Implementation Plan: Other processes stay opaque

**Branch**: `025-introspection` (local planning; commits on `main`) | **Date**: 2026-11-02 | **Spec**: [spec.md](spec.md)

## Summary

The fix goes in place into the `process-access` hard-deny class (spec,
Session 2026-11-02, no release users yet): no new base, no new presets, no
sysctl allowlist.

- **Policy crate, macOS**:
  - `crates/procage-policy/src/lower/macos.rs`: the `ProcessAccess` class's
    hard denies gain `(deny sysctl-read (sysctl-name-prefix
    "kern.procargs"))` (covers `kern.procargs` and `kern.procargs2`); for the
    class only, the lowering adds a quiet early `(deny process-info-pidinfo
    (with no-report))` and `(allow process-info-pidinfo (target
    same-sandbox))`. It applies to every policy, every base (V1–V3) and every
    preset version (v1–v3); waiving `HardDenyClass::ProcessAccess` lifts all
    three.
  - `crates/procage-policy/src/sbpl.rs`: Seatbelt filters
    `Filter::SysctlName` and `Filter::SysctlNamePrefix`.
  - Preset fixtures v1–v3 regenerated, three lines longer each
    (`crates/procage-policy/tests/fixtures/presets/*.sb`).
- **Policy crate, Linux**:
  - `Construct::ProcOtherProcesses` (`proc-other-processes`), an
    approximation on both tiers.
  - `procage_policy::linux::reaches_other_processes` (shared predicate: `/`,
    `/proc` or a path below it other than `/proc/self` and
    `/proc/thread-self`) and `PROC_OTHER_PROCESSES_NOTE`
    (`crates/procage-policy/src/linux.rs`).
  - `proc_reach` in `crates/procage-policy/src/lower/linux.rs` counts literal
    file rules, raw Landlock rules and globs.
- **procage, Linux backend** (`crates/procage/src/linux/mod.rs`):
  - `proc_links` at cage creation: a rule whose canonicalised path reaches
    `/proc` (a symbolic link to `/proc` or `/`) is refused unless accepted,
    then listed in `plan.degradations`.
  - `bind` at spawn: a grant's resolved path that reaches `/proc` is refused
    with a `proc-other-processes` gap unless accepted; when accepted the run's
    receipt lists the approximation (`RunFacts::with_approximation`,
    `crates/procage/src/receipt.rs`) and `enforced_as_written` is false.
- **procage, macOS**: test helpers `procargs1_errno` and `pidinfo_errno`
  (`crates/procage/src/macos/sys.rs`, `macos::testing`); the stale module
  note that the sandbox does not mediate `KERN_PROCARGS2` is removed.
- **Tests**:
  - `escape_macos::r25_other_processes_arguments_are_unreadable` on the
    default policy: the caller's `KERN_PROCARGS2`, `KERN_PROCARGS` and pidinfo
    EPERM; own and own child's readable; with `ProcessAccess` waived the
    caller readable (control). Not ignored.
  - `escape_linux::r25_other_processes_are_opaque` and
    `r25_proc_through_a_link_or_a_grant_is_an_approximation`.
  - Policy: `tests/base.rs`, `tests/precedence.rs`
    (`every_allow_has_a_source`: the pidinfo allow is the only allow without a
    policy rule), `tests/gaps.rs`, `tests/presets.rs`
    (`presets_do_not_reach_other_processes_on_linux`), `src/linux.rs`
    (`what_reaches_other_processes`); `tests/fit.rs`, `tests/gaps.rs`,
    `spawn_linux::t2_reading_everything_except_secrets` accept the construct.
- **Docs**: THREAT_MODEL R-25 `mitigated`; site `macos.md`, `linux.md`,
  `threat-model.md`; CHANGELOG (Security: the macOS refusal, migration =
  waive `ProcessAccess`; Added: the construct and the filters; Changed: the
  Linux approximation, migration = allow `ProcOtherProcesses`).

## Technical Context

macOS 26.6.2 (25G83) for the measurement and the program set; the `xcode-27`
lane re-measures once it exists (spec 039); Docker Linux 7.0.14 aarch64,
tiers T1 and T2.

## Constitution Check

| Principle | Check | Status |
|---|---|---|
| I. Fail closed | Linux `/proc` reach (rules, links, grants) is an approximation by name; the macOS class refuses unless waived | PASS |
| II. Types | One new construct; two Seatbelt filter variants | PASS |
| III. Kernel oracle | Measured rule (research.md); canaries on macOS and both Linux tiers, with a waived control | PASS |
| IV. fork/exec | No child change | PASS |
| V. Hygiene | Strengthens the hard-deny tier | PASS |
| VI. Private interfaces | SBPL semantics measured, documented as such | PASS |
| VII. Library | Frozen presets only tighten (three lines each, pinned by fixtures); migration notes in the CHANGELOG | PASS |

## Complexity Tracking

| Item | Why | Simpler alternative rejected |
|---|---|---|
| An early unfiltered pidinfo deny plus a same-sandbox allow | The default deny does not hold the query; only an explicit rule does | `(deny process-info* (target others))`: measured not to hold |
| A prefix deny of `kern.procargs` | A prefix matches the numeric call | An exact `kern.procargs2` name: measured not to match; a base V4 with a sysctl allowlist: more surface, a new base and presets for no user |
| No PID namespace | PID 1 semantics (ignored signals, orphan reaping) need an init process | A PID namespace now: three processes per run and new lifetime risks, for a case the default already avoids |
