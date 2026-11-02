# Threat Model: Other processes stay opaque

**Feature**: `025-introspection` · **Generated**: 2026-11-02T00:56:52Z · **Profiles**: stride, llm, agent · **Canonical**: `threat-model.yaml`

> Rendered by ThreatSpec. Edit `threat-model.yaml`, not this file.

## Summary

| Threats | Critical | High | Medium | Low | Needs clarification | Not applicable | Mitigations | Requirements | Decisions |
|---|---|---|---|---|---|---|---|---|---|
| 10 | 0 | 2 | 8 | 0 | 0 | 28 | 9 | 7 | 0 |

## Actors

| ID | Name | Trust | Description |
|---|---|---|---|
| `actor.caged-code` | Arbitrary code in the caged child | untrusted |  |
| `actor.consumer` | Developer of a harness that picks a base or preset, waives classes, accepts approximations and grants paths | trusted |  |
| `actor.contributor` | procage contributor who edits the hard-deny classes, the Seatbelt filters, the Linux lowering or the docs | semi-trusted |  |

## Trust Zones

| ID | Name | Trust rating | Description |
|---|---|---|---|
| `tz.cage` | The caged child and the run's descendants | 5 |  |
| `tz.harness` | The harness that builds cages | 90 |  |
| `tz.os` | The kernel (Seatbelt and sysctl on macOS; /proc and Landlock on Linux) | 95 |  |
| `tz.others` | The user's other processes (editor, agent, shell, the calling program) | 70 |  |

## Assets

| ID | Name | Type | Classification | C / I / A | Source |
|---|---|---|---|---|---|
| `asset.base` | The process-access hard-deny class and the frozen macOS base profiles (V1 to V3) and presets (v1 to v3) it applies to, with their fixtures | capability | internal | 0 / 90 / 50 | spec.md#Key-Entities |
| `asset.compat` | Existing policies: Linux rules or grants on / or /proc, macOS runs that read other processes, and the programs of the base program set | capability | internal | 0 / 30 / 70 | plan.md#Summary |
| `asset.lifetime` | The run-lifetime guarantee: no process of the run outlives it (unchanged; no PID namespace in this change) | capability | internal | 0 / 90 / 50 | spec.md#FR-003 |
| `asset.process-secrets` | Command lines and environments of the user's other processes, which routinely hold tokens | credential | secret | 100 / 0 / 0 | spec.md#Input |

## Components

| ID | Name | Type | Trust zone | Source |
|---|---|---|---|---|
| `component.canaries` | R-25 canaries on the default policy in every just escape variant and on Linux T1/T2, and the base program set | test | `tz.harness` | plan.md#Summary |
| `component.docs` | THREAT_MODEL, crate docs, site and CHANGELOG on R-25 | document | `tz.harness` | spec.md#FR-005 |
| `component.lifetime` | Run-lifetime enforcement (the whole run is killed when it ends); unchanged by this change | library | `tz.harness` | spec.md#Clarifications |
| `component.preset-fixtures` | Frozen preset fixtures v1 to v3 (each three lines longer) and the policy tests that pin the class's rules | test | `tz.harness` | spec.md#Key-Entities |
| `component.proc-reach` | Linux proc-other-processes approximation on T1 and T2: the shared predicate reaches_other_processes, the lowering's proc_reach (file rules, raw Landlock rules, globs), proc_links at cage creation (rules that resolve to /proc) and the grant check in bind at spawn | library | `tz.harness` | spec.md#FR-003 |
| `component.process-access-class` | macOS process-access hard-deny class: (deny sysctl-read (sysctl-name-prefix "kern.procargs")), a quiet early unfiltered (deny process-info-pidinfo) and (allow process-info-pidinfo (target same-sandbox)), in every policy on every base, lifted only by waiving the class | library | `tz.harness` | spec.md#Clarifications |
| `component.receipt` | Cage plan (degradations) and run receipt (RunFacts::with_approximation) that list accepted approximations | library | `tz.harness` | spec.md#User-Story-2 |

## Data Flows

| ID | Name | From | To | Assets | Crosses |
|---|---|---|---|---|---|
| `flow.approximation` | An accepted proc-other-processes approximation is listed in the plan and the receipt | `component.proc-reach` | `component.receipt` | `asset.process-secrets` |  |
| `flow.claims` | The docs tell the consumer that the class closes R-25 on macOS unless waived, the Linux default, and what the approximation leaves open | `component.docs` | `actor.consumer` | `asset.process-secrets` |  |
| `flow.confine` | The process-access class confines the child on macOS on every base and preset | `component.process-access-class` | `tz.cage` | `asset.base`, `asset.process-secrets` | `tz.harness`, `tz.cage` |
| `flow.exposure` | The kernel hands other processes' arguments and environment to the child | `tz.others` | `tz.cage` | `asset.process-secrets` | `tz.others`, `tz.cage` |
| `flow.kill` | The harness kills every process of the run when it ends | `component.lifetime` | `tz.cage` | `asset.lifetime` | `tz.harness`, `tz.cage` |
| `flow.measure` | The canaries and the program set measure the class's rule and the Linux refusal on each lane | `component.canaries` | `component.process-access-class` | `asset.base`, `asset.compat` |  |
| `flow.policy-in` | The consumer's Linux policy (file rules, raw Landlock rules, grants) and accepted approximations enter the lowering | `actor.consumer` | `component.proc-reach` | `asset.process-secrets`, `asset.compat` |  |
| `flow.presets` | The preset fixtures pin the class's rules in every preset version | `component.preset-fixtures` | `component.process-access-class` | `asset.base` |  |
| `flow.procfs` | The child lists /proc and reads cmdline and environ of other processes | `tz.cage` | `tz.os` | `asset.process-secrets` | `tz.cage`, `tz.os` |
| `flow.sysctl` | The child queries sysctls by name or numeric MIB and process information of other processes (KERN_PROCARGS2, pidinfo) | `tz.cage` | `tz.os` | `asset.process-secrets`, `asset.compat` | `tz.cage`, `tz.os` |

```mermaid
flowchart LR
    actor_caged_code(["Arbitrary code in the caged child"])
    actor_consumer(["Developer of a harness that picks a base or preset, waives classes, accepts approximations and grants paths"])
    actor_contributor(["procage contributor who edits the hard-deny classes, the Seatbelt filters, the Linux lowering or the docs"])
    subgraph tz_cage["The caged child and the run's descendants"]
    end
    subgraph tz_harness["The harness that builds cages"]
        component_canaries["R-25 canaries on the default policy in every just escape variant and on Linux T1/T2, and the base program set"]
        component_docs["THREAT_MODEL, crate docs, site and CHANGELOG on R-25"]
        component_lifetime["Run-lifetime enforcement (the whole run is killed when it ends); unchanged by this change"]
        component_preset_fixtures["Frozen preset fixtures v1 to v3 (each three lines longer) and the policy tests that pin the class's rules"]
        component_proc_reach["Linux proc-other-processes approximation on T1 and T2: the shared predicate reaches_other_processes, the lowering's proc_reach (file rules, raw Landlock rules, globs), proc_links at cage creation (rules that resolve to /proc) and the grant check in bind at spawn"]
        component_process_access_class["macOS process-access hard-deny class: (deny sysctl-read (sysctl-name-prefix "kern.procargs")), a quiet early unfiltered (deny process-info-pidinfo) and (allow process-info-pidinfo (target same-sandbox)), in every policy on every base, lifted only by waiving the class"]
        component_receipt["Cage plan (degradations) and run receipt (RunFacts::with_approximation) that list accepted approximations"]
    end
    subgraph tz_os["The kernel (Seatbelt and sysctl on macOS; /proc and Landlock on Linux)"]
    end
    subgraph tz_others["The user's other processes (editor, agent, shell, the calling program)"]
    end
    component_proc_reach -->|"An accepted proc-other-processes approximation is listed in the plan and the receipt"| component_receipt
    component_docs -->|"The docs tell the consumer that the class closes R-25 on macOS unless waived, the Linux default, and what the approximation leaves open"| actor_consumer
    component_process_access_class -->|"The process-access class confines the child on macOS on every base and preset"| tz_cage
    tz_others -->|"The kernel hands other processes' arguments and environment to the child"| tz_cage
    component_lifetime -->|"The harness kills every process of the run when it ends"| tz_cage
    component_canaries -->|"The canaries and the program set measure the class's rule and the Linux refusal on each lane"| component_process_access_class
    actor_consumer -->|"The consumer's Linux policy (file rules, raw Landlock rules, grants) and accepted approximations enter the lowering"| component_proc_reach
    component_preset_fixtures -->|"The preset fixtures pin the class's rules in every preset version"| component_process_access_class
    tz_cage -->|"The child lists /proc and reads cmdline and environ of other processes"| tz_os
    tz_cage -->|"The child queries sysctls by name or numeric MIB and process information of other processes (KERN_PROCARGS2, pidinfo)"| tz_os
```

## Threats

| ID | Threat | Category | Technique | Severity | Status | Mitigations | Mappings | Source |
|---|---|---|---|---|---|---|---|---|
| `threat.procargs-variant` | On any base the child reads another process's arguments or environment through a query the class's rule does not cover (KERN_PROCARGS by numeric MIB, a pidinfo flavour, a pidinfo of a process outside the sandbox), stealing tokens | Information Disclosure | sensitive-data-exposure | **high** | mitigated | `mitigation.deny-then-name` |  | research.md |
| `threat.t2-silent-proc` | On Linux T1 or T2 a policy whose rules or grants reach /proc (literally, through an ancestor such as /, a symbolic link, a raw Landlock rule or a glob) runs without the caller accepting proc-other-processes, so other processes' command lines are readable silently | Information Disclosure, Elevation of Privilege | privilege-escalation-via-config | **high** | mitigated | `mitigation.no-default-proc`, `mitigation.proc-gap` |  | spec.md#FR-003 |
| `threat.linux-root-refused` | Existing policies change behaviour after the upgrade (on Linux a rule or grant on / or /proc is refused; on macOS a run that reads other processes is refused on every base and preset), so consumers break, or accept proc-other-processes or waive process-access reflexively without seeing the exposure | Denial of Service, Information Disclosure | privilege-escalation-via-config | **medium** | mitigated | `mitigation.per-platform-status`, `mitigation.proc-gap` |  | plan.md#Summary |
| `threat.numeric-unnamed-sysctl` | A query the child makes by numeric MIB is matched differently from its name (an exact sysctl-name filter does not match KERN_PROCARGS2 by number), so a rule that reads right lets other processes' arguments through | Information Disclosure | sensitive-data-exposure | **medium** | mitigated | `mitigation.deny-then-name` |  | research.md |
| `threat.prefix-future-name` | Every base still allows sysctl-read outside the kern.procargs prefix, so a sysctl a later macOS release adds (or one not yet known) that returns other processes' arguments or environment is admitted | Information Disclosure | sensitive-data-exposure | **medium** | mitigated | `mitigation.measure-before-freeze` |  | research.md |
| `threat.proc-reach-bypass` | The /proc reach check misses a rule or grant that reaches other processes (a symbolic link or bind mount to /proc, a raw Landlock rule, a glob, a grant bound at spawn), or the /proc/self carve-out resolves to a process other than the child, so the read is silent | Information Disclosure, Elevation of Privilege | privilege-escalation-via-config | **medium** | mitigated | `mitigation.proc-gap` |  | plan.md#Summary |
| `threat.program-set-gap` | The class's new rules break a program of the base program set or a frozen preset (a tool that reads its own or a sibling's process information, ps of the run), pushing consumers to waive process-access | Denial of Service | broken-access-control | **medium** | mitigated | `mitigation.program-set-v4` |  | spec.md#User-Story-1 |
| `threat.rule-weakened` | A contributor weakens the process-access class's rule to make a program work (an exact sysctl-name instead of the kern.procargs prefix, which the numeric call does not match; a filtered or dropped early pidinfo deny; a pidinfo allow beyond same-sandbox; a new unfiltered allow), re-admitting KERN_PROCARGS2 on every base and preset | Elevation of Privilege, Information Disclosure | privilege-escalation-via-config | **medium** | mitigated | `mitigation.literal-allowlist` |  | research.md |
| `threat.status-overclaim` | The docs or the threat model present R-25 as closed for a run with process-access waived or a Linux cage with proc-other-processes accepted, or omit the documented limits, so a consumer passes secrets in arguments it believes hidden | Repudiation | missing-audit-trail | **medium** | mitigated | `mitigation.per-platform-status` |  | spec.md#FR-004 |
| `threat.unmeasured-release` | The rule measured on macOS 26.6.2 (a prefix matches the numeric call; an explicit unfiltered pidinfo deny is needed) does not hold on macOS 27 or a later release, and a release ships with the read open there | Information Disclosure | sensitive-data-exposure | **medium** | mitigated | `mitigation.measure-before-freeze` |  | spec.md#Assumptions |

### Techniques evaluated without findings

| Technique | Disposition | Reason |
|---|---|---|
| credential-theft | not-applicable | no authentication surface |
| identity-spoofing | not-applicable | no authentication or network boundary |
| data-tampering-in-transit | not-applicable | no data in transit; the feature changes profile rules of a hard-deny class and a Linux lowering check |
| data-tampering-at-rest | no-threat-detected | checked the stored profiles and presets: presets v1 to v3 change only by the process-access class's three rules, pinned by the fixtures (SR-002); weakening those rules is threat.rule-weakened |
| injection | not-applicable | no external-input surface; the feature parses no data the child provides |
| resource-exhaustion | not-applicable | no external-input surface and no new process or namespace; the run's lifetime handling is unchanged (no PID namespace in this change) |
| cross-tenant-leak | not-applicable | single user; other users' processes are already refused by the kernel (out of scope); the kern.proc process list (pids, names) stays readable and carries no arguments or environment |
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
| `mitigation.deny-then-name` | The process-access class denies sysctl-read of the kern.procargs prefix and, first in the profile, process-info-pidinfo unfiltered, then allows pidinfo for the same sandbox; the canary reads another process's KERN_PROCARGS2, KERN_PROCARGS and pidinfo by numeric call, with positive controls on self and an own child and a control with the class waived | preventive | `threat.procargs-variant`, `threat.numeric-unnamed-sysctl` | SR-001 | `crates/procage-policy/src/lower/macos.rs`, `crates/procage-policy/src/sbpl.rs`, `crates/procage/src/macos/sys.rs`, `crates/procage/tests/escape_macos.rs` | required |
| `mitigation.fresh-proc` | The target runs inside the new PID namespace and /proc is mounted fresh from inside it, over the old one; the T1 canary checks /proc, a known outside pid and every proc mount in mountinfo | preventive | `threat.stale-proc-view` |  | `no PID namespace in this change (clarification 2026-11-02)` | rejected |
| `mitigation.lifetime-suite` | The R-23 escape suite runs unchanged on T1 with the PID namespace, and a test checks that orphans are reaped and that no process of the run survives its end | preventive | `threat.pidns-lifetime` |  | `no PID namespace in this change (clarification 2026-11-02)` | rejected |
| `mitigation.literal-allowlist` | The class adds exactly the prefix deny, the early pidinfo deny and the same-sandbox pidinfo allow and allows nothing else (the pidinfo allow is the only allow without a policy rule); the policy tests pin the lines and the preset fixtures v1 to v3 pin every preset | preventive | `threat.rule-weakened` | SR-002 | `crates/procage-policy/src/lower/macos.rs`, `crates/procage-policy/tests/base.rs`, `crates/procage-policy/tests/precedence.rs`, `crates/procage-policy/tests/gaps.rs`, `crates/procage-policy/tests/presets.rs`, `crates/procage-policy/tests/fixtures/presets` | required |
| `mitigation.measure-before-freeze` | The R-25 canaries fail, never skip, in every just escape variant (default, with reporting, base V3 with reporting) and on every macOS lane; the macOS 27 lane re-measures the rule when it exists | detective | `threat.unmeasured-release`, `threat.prefix-future-name` | SR-003 | `crates/procage/tests/escape_macos.rs`, `.github/workflows/ci.yml`, `justfile` | required |
| `mitigation.no-default-proc` | The Linux base and every preset grant nothing under /proc beyond /proc/self and /proc/thread-self; a canary reads another process's cmdline on the default policy and expects a denial | preventive | `threat.t2-silent-proc` | SR-004 | `crates/procage-policy/src/base.rs`, `crates/procage-policy/src/presets.rs`, `crates/procage-policy/tests/presets.rs`, `crates/procage/tests/escape_linux.rs` | required |
| `mitigation.per-platform-status` | THREAT_MODEL marks R-25 mitigated with per-platform text, the site pages state the Linux residual with the approximation accepted and the macOS waiver, and the CHANGELOG carries both migration notes (macOS: waive ProcessAccess; Linux: allow ProcOtherProcesses) | preventive | `threat.status-overclaim`, `threat.linux-root-refused` | SR-007 | `crates/procage/THREAT_MODEL.md`, `site/content/docs/macos.md`, `site/content/docs/linux.md`, `site/content/docs/threat-model.md`, `CHANGELOG.md` | required |
| `mitigation.proc-gap` | On Linux T1 and T2 a file rule, raw Landlock rule or glob that reaches /proc other than /proc/self and /proc/thread-self is an approximation in the lowering; at cage creation a rule whose canonicalised path reaches /proc (a symbolic link) is refused unless accepted, then listed in the plan; at spawn a grant's resolved path is checked the same way and, when accepted, listed in the run's receipt | preventive | `threat.t2-silent-proc`, `threat.proc-reach-bypass`, `threat.linux-root-refused` | SR-006 | `crates/procage-policy/src/linux.rs`, `crates/procage-policy/src/lower/linux.rs`, `crates/procage/src/linux/mod.rs`, `crates/procage/src/receipt.rs`, `crates/procage/tests/escape_linux.rs` | required |
| `mitigation.program-set-v4` | The base program set and the escape suite run with the class in force; the run's own and its children's arguments and process information stay readable (same-sandbox allow); ps (setuid, refused in any cage) and pgrep (needs sysmond) are documented limits | preventive | `threat.program-set-gap` | SR-005 | `crates/procage/tests/spawn_macos.rs`, `crates/procage/tests/escape_macos.rs`, `site/content/docs/macos.md` | required |

## Security Requirements

### SR-001 (P1) — verified

On macOS, on every base, the process-access class MUST refuse with EPERM the child's reads of the arguments, environment and process information of any process outside the run (KERN_PROCARGS2 and KERN_PROCARGS by numeric MIB, pidinfo), while its reads of its own and its children's MUST succeed; waiving the class MUST lift the refusal.

- **Given** a same-user process outside the run and a child on the default policy, **when** the child reads that process's KERN_PROCARGS2, KERN_PROCARGS and pidinfo by numeric call, **then** each read fails with EPERM
- **Given** the same child with a child of its own, **when** it reads its own and its child's KERN_PROCARGS2 and pidinfo, **then** every read succeeds
- **Given** the same policy with HardDenyClass::ProcessAccess waived, **when** the child reads the other process's KERN_PROCARGS2, **then** it succeeds
- Mitigations: `mitigation.deny-then-name`
- Tasks: T001 ✓, T004 ✓, T011 ✓
- Verification `verification.sr-001.2026-11-01`: test → partial (partial) — `crates/procage/tests/escape_macos.rs::r25_other_processes_arguments_are_unreadable`
- Verification `verification.sr-001.2026-11-02`: test → pass (verified) — `crates/procage/tests/escape_macos.rs::r25_other_processes_arguments_are_unreadable`

### SR-002 (P1) — verified

The process-access class MUST add exactly (deny sysctl-read (sysctl-name-prefix "kern.procargs")), the quiet early unfiltered (deny process-info-pidinfo) and (allow process-info-pidinfo (target same-sandbox)) and MUST allow nothing else; the preset profiles v1 to v3 MUST change only by these three lines, pinned by their fixtures.

- **Given** the empty policy, **when** it is lowered for macOS, **then** the only allow is (allow process-info-pidinfo (target same-sandbox))
- **Given** the reference policies, **when** every allow is traced to its source, **then** the same-sandbox pidinfo allow is the only allow without a policy rule
- **Given** every preset version v1 to v3, **when** it is lowered, **then** it equals its fixture, which contains the prefix deny, the early pidinfo deny and the same-sandbox allow
- Mitigations: `mitigation.literal-allowlist`
- Tasks: T001 ✓, T002 ✓, T012 ✓
- Verification `verification.sr-002.2026-11-01`: test → partial (partial) — `crates/procage-policy/tests/base_v4.rs::the_allowlist_leaves_out_the_argument_queries`
- Verification `verification.sr-002.2026-11-02`: test → pass (verified) — `crates/procage-policy/tests/precedence.rs::every_allow_has_a_source`

### SR-003 (P1) — verified

The R-25 canaries MUST run on the default policy and MUST fail, never skip, when another process's arguments are readable, in every just escape variant and on every macOS lane; the macOS 27 lane MUST re-measure the rule when it exists.

- **Given** every just escape variant (default, with reporting, base V3 with reporting), **when** r25_other_processes_arguments_are_unreadable runs, **then** it passes, and it is not ignored
- **Given** a lane where the read succeeds, **when** the canary runs, **then** it fails the lane
- Mitigations: `mitigation.measure-before-freeze`
- Tasks: T004 ✓, T013 ✓
- Verification `verification.sr-003.2026-11-01`: review → inconclusive (implemented-unverified) — `.github/workflows/ci.yml:81`
- Verification `verification.sr-003.2026-11-02`: test → pass (verified) — `crates/procage/tests/escape_macos.rs::r25_other_processes_arguments_are_unreadable`

### SR-004 (P1) — verified

On Linux (T1 and T2) the base and every preset MUST grant nothing under /proc beyond /proc/self and /proc/thread-self, so on the default policy a child's read of another process's cmdline or environ MUST be denied.

- **Given** Linux T1 or T2, the base policy and a same-user process outside the run, **when** the child reads that process's cmdline and environ, **then** both reads are denied
- **Given** every preset version v1 to v3 on T1 and T2, **when** its rules are lowered, **then** none names proc-other-processes
- Mitigations: `mitigation.no-default-proc`
- Tasks: T003 ✓, T007 ✓, T014 ✓
- Verification `verification.sr-004.2026-11-01`: review → inconclusive (implemented-unverified) — `crates/procage/tests/escape_linux.rs::r25_other_processes_are_opaque`
- Verification `verification.sr-004.2026-11-02`: test → pass (verified) — `crates/procage/tests/escape_linux.rs::r25_other_processes_are_opaque`

### SR-005 (P2) — verified

With the class in force the run's own processes MUST stay readable (the pidinfo allow is same-sandbox, not self and children) and the base program set MUST work as before; ps (setuid, refused in any cage) and pgrep (needs sysmond) MUST be documented as limits.

- **Given** a child on the default policy with a child of its own, **when** it reads its own and its child's arguments and pidinfo, **then** every read succeeds
- **Given** the base program set, **when** it runs with the class in force, **then** every program works as before
- **Given** the macOS docs, **when** they describe R-25, **then** they state what of ps of the run works and the ps and pgrep limits
- Mitigations: `mitigation.program-set-v4`
- Tasks: T004 ✓, T005 ✓, T015 ✓, T018 ✓
- Verification `verification.sr-005.2026-11-01`: test → partial (partial) — `crates/procage/tests/escape_macos.rs::r25_other_processes_arguments_are_unreadable`
- Verification `verification.sr-005.2026-11-02`: test → partial (partial) — `crates/procage/tests/escape_macos.rs::r25_other_processes_arguments_are_unreadable`
- Verification `verification.sr-005.2026-11-02-2`: test → pass (verified) — `crates/procage/tests/escape_macos.rs::r25_other_processes_arguments_are_unreadable`

### SR-006 (P1) — verified

On Linux T1 and T2 a policy whose file rule, raw Landlock rule or glob reaches /proc other than /proc/self and /proc/thread-self (literally, through an ancestor such as /, or through a symbolic link resolved at cage creation), or a grant whose resolved path does at spawn, MUST be refused naming proc-other-processes unless the caller accepts it by name; an accepted rule MUST be listed in the plan and an accepted grant in the run's receipt, which is then not enforced as written; other processes' environ MUST stay unreadable.

- **Given** T1 or T2 and a rule on /proc, **when** the cage is made without the approximation, **then** it is refused naming proc-other-processes
- **Given** the approximation accepted by name, **when** the child reads another process's environ and cmdline and its own environ, **then** environ is refused, cmdline is readable (the residual), its own environ is readable, and the plan lists the approximation
- **Given** a rule on a symbolic link to /proc, **when** the cage is made without, then with the approximation, **then** it is refused naming the construct, then made with the approximation in the plan
- **Given** a grant bound at spawn to a symbolic link to /proc, **when** the run is spawned without, then with the approximation, **then** the spawn is refused naming the construct, then the receipt lists the approximation and enforced_as_written is false
- Mitigations: `mitigation.proc-gap`
- Tasks: T003 ✓, T006 ✓, T007 ✓, T016 ✓
- Verification `verification.sr-006.2026-11-01`: test → partial (partial) — `crates/procage/tests/escape_linux.rs::r25_other_processes_are_opaque`
- Verification `verification.sr-006.2026-11-02`: test → pass (verified) — `crates/procage/tests/escape_linux.rs::r25_proc_through_a_link_or_a_grant_is_an_approximation`

### SR-007 (P2) — verified

THREAT_MODEL MUST mark R-25 mitigated with per-platform text (macOS: the class on every base, lifted by waiving it; Linux: no /proc by default, the approximation by name with its residual), the site docs MUST say the same, and the CHANGELOG MUST carry the migration notes (macOS: waive ProcessAccess; Linux: allow ProcOtherProcesses).

- **Given** THREAT_MODEL, the crate docs and the site, **when** they describe R-25, **then** they give the macOS class and its waiver, the Linux default and the residual with the approximation, and no base or preset that does not exist
- **Given** the CHANGELOG, **when** the release is cut, **then** it lists the macOS refusal under Security and the Linux approximation under Changed, each with its migration
- Mitigations: `mitigation.per-platform-status`
- Tasks: T008 ✓, T017 ✓
- Verification `verification.sr-007.2026-11-01`: review → partial (partial) — `crates/procage/THREAT_MODEL.md:208`
- Verification `verification.sr-007.2026-11-02`: review → pass (verified) — `crates/procage/THREAT_MODEL.md:204`
