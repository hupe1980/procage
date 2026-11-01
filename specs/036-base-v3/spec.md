# Feature Specification: Base V3 and quiet records

**Feature Branch**: `036-base-v3` (planning directory; commits land on `main`)

**Created**: 2026-11-01

**Status**: Shipped in 0.1.0 (2026-11-01)

**Input**: User description: "Keep going. Run the full spec kit workflow, include analyze. We want best-in-class/state-of-the-art." Follows a finding of 010-violations.

## Context

010 made every macOS denial visible. Measured with that reporting
(`research.md`), 22 everyday commands under base V2 all succeed, yet their
records are flooded:

- every process asks for the logging services (`com.apple.logd`,
  `com.apple.diagnosticd`) and registers with the DTrace helper
  (`/dev/dtracehelper` ioctl); shells probe `/dev/tty`; developer tools look
  up `com.apple.bsd.dirhelper` (left out of V2 on purpose) and group
  membership (`opendirectoryd.membership`). All are refused and none is
  needed: 5,208 `diagnosticd` reports in one run of the set;
- the Xcode shim (`xcrun` → `xcodebuild`) retries a refused LaunchServices
  lookup (`com.apple.lsd.modifydb`, hard-deny service handoff) 4,920 times
  per run, so one `clang` gives ~1,800 records.

A harness that shows "what was denied" drowns in this. Two measured
mechanisms fix it without allowing anything new:

- SBPL's `(with no-report)` on a deny rule refuses without logging, and an
  allow later in the profile still overrides it (verified on 26.6.2).
- Identical denials (same process, operation, target and rule) can be
  merged in the record with a repeat count.

## Clarifications

### Session 2026-11-01

- Q: Allow the probes, or deny them quietly? → A: Deny quietly. They are
  not needed (every command works under V2); allowing logd or the DTrace
  helper would widen what caged code reaches. V3 adds only `no-report`
  denies.
- Q: Where do the quiet denies go? → A: First, right after `(deny default)`,
  so every allow of the policy (a granted `/dev/tty` with `Tty::Inherit`)
  still wins.
- Q: Is the LaunchServices lookup silenced too? → A: No: it is a hard-deny
  class and a real escape route when malicious. It stays reported; record
  merging makes it one entry per process with a count.
- Q: What about V1, V2 and the presets? → A: V1 and V2 stay byte-identical
  (frozen). V3 is new; presets gain v3 (each preset's v2 on Base V3).
  Linux: V3 lowers as V2 (no such probes there).
- Q: Does merging apply to Linux too? → A: Yes, the record is shared; a
  flood of one refused call becomes one entry with a count.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - A record shows only what matters (Priority: P1)

A harness runs `clang`, `git`, `make` and shells under base V3 with
violations on. Their records contain no logging, DTrace, dirhelper,
membership or tty probes; what remains is denials worth showing.

**Independent Test**: the measured command set under V3 has none of the
quiet probes in any record, every command still succeeds, and the
quiet-probe targets are still refused.

**Acceptance Scenarios**:

1. **Given** base V3, **When** `/bin/ls` runs, **Then** its record is empty.
2. **Given** base V3 and `Tty::Inherit`, **Then** `/dev/tty` is still
   reachable (the policy's allow wins).
3. **Given** base V3, **When** the child looks up `com.apple.logd`, **Then**
   the lookup fails and nothing is reported.

---

### User Story 2 - A flood becomes one line (Priority: P1)

Identical denials merge: one entry per process, operation, target and rule,
with how often it happened.

**Acceptance Scenarios**:

1. **Given** `clang` under V3, **Then** `com.apple.lsd.modifydb` appears once
   per process with a repeat count above 1, still as service handoff.
2. **Given** Linux and 20,000 refused calls of one kind, **Then** the record
   has one entry with a count of 20,000.

---

### User Story 3 - Upgrading is explicit (Priority: P2)

V1, V2 and existing presets are unchanged; V3 and presets v3 are new names,
documented with what V3 silences.

### Edge Cases

- A policy that allows a quiet target (`Tty::Inherit`, a raw layer allow of
  `com.apple.logd`): the allow wins.
- The record's cap counts distinct entries; repeats keep counting past it
  only for entries already kept (others are counted as dropped).
- The display of a merged violation names the count ("… ×4,920").

## Requirements *(mandatory)*

- **FR-001**: `Base::V3` MUST lower on macOS to V2's rules plus `no-report`
  denies of the quiet probes, emitted directly after `(deny default)`; on
  Linux as V2.
- **FR-002**: V1 and V2 profiles MUST stay byte-identical; presets v3 MUST
  be each preset's v2 on Base V3, frozen as fixtures.
- **FR-003**: The record MUST merge violations with the same pid,
  operation, target and rule into one entry with a `repeats` count, on both
  backends.
- **FR-004**: Caged tests MUST show the stories on macOS (and the Linux merge
  on both tiers); the escape suite MUST pass with presets v3.
- **FR-005**: Docs (crate, site, README) MUST list what V3 silences and that
  it allows nothing more than V2.

<!-- threatspec:begin -->
### Security Requirements *(managed by ThreatSpec — edit threat-model.yaml)*

- **SR-001** (P1): Every V3 profile with its no-report rules removed MUST equal the V2 profile of the same policy, and V1, V2 and presets v1/v2 MUST stay byte-identical; the escape suite MUST pass with presets v3.
  - Mitigates: `threat.v3-loosens` via `mitigation.strip-equals-v2`
  - Given every reference policy on V3, when its profile is rendered, then removing the no-report lines gives its V2 profile
  - Given the frozen fixtures, when the tests run, then V1, V2 and presets v1/v2 match unchanged
- **SR-002** (P2): The quiet probes MUST be a fixed list, none of which is a target of a hard-deny rule or a data class.
  - Mitigates: `threat.quiet-hides-attack` via `mitigation.quiet-list`
  - Given the quiet list, when compared with every hard-deny and data-class rule, then no target is shared
- **SR-003** (P2): Quiet denies MUST come before every allow, so access a policy grants is never refused by them.
  - Mitigates: `threat.quiet-overrides-allow` via `mitigation.first`
  - Given base V3 with Tty::Inherit, when the child opens /dev/tty, then it succeeds
- **SR-004** (P2): Violations MUST merge only when pid, process, operation, target and rule are all equal; the repeat count MUST saturate.
  - Mitigates: `threat.merge-misreports` via `mitigation.exact-key`
  - Given violations differing in any one field, when pushed, then they stay separate
  - Given the same violation pushed repeatedly, when read, then one entry with that count
<!-- threatspec:end -->

## Success Criteria *(mandatory)*

- **SC-001**: For the measured set, reports under V3 fall by at least 90 %
  against V2 (measured 94.6 %), no quiet probe is left, and commands that do
  not go through Apple's Xcode shim leave an empty record. The shim's reads
  of the user's preferences and caches stay reported (they name user files).
- **SC-002**: Every command of the set still succeeds under V3.
- **SC-003**: `just ci` and the four Linux lanes pass.

## Assumptions

- `(with no-report)` keeps its measured meaning; a kernel fact pins it on
  every macOS lane.
