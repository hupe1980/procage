# Implementation Plan: Audit of the writable trees, before and after a run

**Branch**: `023-tree-audit` (local planning; commits on `main`) | **Date**: 2026-11-01 | **Spec**: [spec.md](spec.md)

## Summary

- **procage, shared** (`src/audit.rs`, new, both systems):
  - `LinkAudit::{Refuse (default), Report, Off}`.
  - `Targets` (built once per cage from the resolved policy): the literal
    protect and hide targets, the protect and hide subpath roots, the fixed
    prefixes of protect and hide globs (with the glob, matched by
    `may_overlap`), and the existing class paths in every home (secrets,
    home trust-handoff paths, persistence; system persistence paths).
  - `links(&Targets, limit) -> LinkResult { findings: Vec<LinkFinding {
    path, links }>, complete, visited }`: walks each target without following
    links and without leaving its device; a regular file with `st_nlink > 1`
    is a finding. Past the limit (or on an unreadable entry) the result is
    incomplete.
  - `Snapshot` and `handoff(&before, &after) -> HandoffResult { findings:
    Vec<HandoffFinding { path, kind: Created | Modified | Link { target } |
    Repository }>, complete }`: the walk of the writable trees records
    trust-handoff names (`HANDOFF_ANYWHERE`, home handoff paths) with inode,
    size, ctime and mtime, every symbolic link with its target, and every
    `.git` directory.
- **Backends**: `CageOptions::with_link_audit(LinkAudit)` and
  `with_handoff_audit()` (both); macOS gains `with_walk_limit` (default
  200,000, as Linux). In `prepare` (each spawn, in the parent): the link
  audit; `Refuse` with findings → `SpawnError::HardLinks(Vec<LinkFinding>)`;
  `Report` keeps them on the `Child`. With the handoff audit, a snapshot is
  taken before the fork. `Child::audit(&mut self) -> Option<Audit>` gives
  `None` while the run is alive (SR-006); after exit it walks again and
  returns `Audit { links, handoff }`. The receipt carries an `audit`
  summary (counts and completeness; paths only with the policy included).
- **`SpawnError` becomes `#[non_exhaustive]`** on both backends (0.2.0 is
  already a breaking release; later variants are then not).
- **Tests**: `escape_*::r08_*` un-ignored: a hard link to a hidden file and
  to a protected file refuse the spawn on macOS, T1, T2; report mode runs and
  lists; the in-run link attempt is refused (both systems). `tests/audit.rs`
  (new, both systems): every handoff kind detected once (created, modified,
  link, repository), an empty complete audit for a quiet run, incomplete at
  a small walk limit, `None` before exit, paths as bytes round-trip.
- **Docs**: THREAT_MODEL R-08 → mitigated (refuse) with the canaries; R-07
  description gains detection; crate docs "Audits"; site page; CHANGELOG.

## Technical Context

Rust 1.99.1; no new dependencies. Lanes: macOS 26.6.2, Docker Linux 7.0.14
T1/T2.

## Constitution Check

| Principle | Check | Status |
|---|---|---|
| I. Fail closed | Refuse by default; an incomplete audit is never reported as clean | PASS |
| II. Types | Typed modes, findings and kinds; paths as bytes | PASS |
| III. Kernel oracle | R-08 canaries on every lane; the in-run link refusal asserted | PASS |
| IV. fork/exec | Audits run in the parent before the fork and after the exit | PASS |
| V. Hygiene | — | PASS |
| VI. Private interfaces | None | PASS |
| VII. Library | No global state; the handoff audit is opt-in (its walk costs time); the harness decides what to do with findings | PASS |

## Project Structure

```text
crates/procage/src/{lib.rs, audit.rs (new), receipt.rs}
crates/procage/src/macos/{mod.rs, child.rs}
crates/procage/src/linux/{mod.rs, child.rs}
crates/procage/tests/{escape_macos.rs, escape_linux.rs, audit.rs (new), threat_model.rs}
crates/procage/THREAT_MODEL.md, CHANGELOG.md, site/content/docs/audits.md (new)
```

## Complexity Tracking

| Item | Why | Simpler alternative rejected |
|---|---|---|
| Link check on the protected side | An alias shows as a link count on the protected file; no workspace walk is needed, so the check is cheap enough to be on by default | Walking every reachable tree for aliases: unbounded for policies that read `/` |
| Handoff audit opt-in | It walks the writable trees twice per run | On by default: a cost every spawn pays for a detection most callers do not read |
