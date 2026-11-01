# Threat Model: CI lanes for the releases people run

**Feature**: `039-ci-lanes` · **Generated**: 2026-11-01T21:15:52Z · **Profiles**: stride, llm, agent · **Canonical**: `threat-model.yaml`

> Rendered by ThreatSpec. Edit `threat-model.yaml`, not this file.

## Summary

| Threats | Critical | High | Medium | Low | Needs clarification | Not applicable | Mitigations | Requirements | Decisions |
|---|---|---|---|---|---|---|---|---|---|
| 11 | 0 | 5 | 4 | 2 | 2 | 23 | 7 | 8 | 0 |

### Needs clarification

- `threat.t1-step-scope` — [NEEDS CLARIFICATION: does a documented host change made as root (the sysctl used on 24.04, an AppArmor profile) count as the documented, user-level way for a 26.04 T1 job, or only a step that needs no host change?] (spec.md#Clarifications)
- `threat.unavailable-lane-status` — [NEEDS CLARIFICATION: while a lane is marked temporarily unavailable, is its release still listed as supported on the last measured result, and for how long, given that supported means exactly the green lanes?] (spec.md#Edge-Cases)

## Actors

| ID | Name | Trust | Description |
|---|---|---|---|
| `actor.action-author` | Maintainer of a third-party action the workflow uses, or whoever compromises that action's repository | untrusted |  |
| `actor.consumer` | Developer of a harness who reads the supported releases and tiers and relies on them | trusted |  |
| `actor.contributor` | procage contributor who edits the workflow, the lane assertions, the base profiles or the platform docs | semi-trusted |  |
| `actor.image-provider` | The provider of the hosted runner images, which updates and remaps image labels on its own schedule | semi-trusted |  |
| `actor.pr-author` | Author of a pull request, possibly from a fork, whose code the lanes build and run | untrusted |  |

## Trust Zones

| ID | Name | Trust rating | Description |
|---|---|---|---|
| `tz.readers` | People who read the README, SECURITY and the platform table | 50 |  |
| `tz.repo` | The public repository, its workflow files, tags and releases | 90 |  |
| `tz.runner` | A hosted runner image (OS release, build, architecture, host security defaults) | 60 |  |
| `tz.third-party` | Third-party action repositories and tool downloads | 30 |  |

## Assets

| ID | Name | Type | Classification | C / I / A | Source |
|---|---|---|---|---|---|
| `asset.claims` | The supported-release list and platform table: which releases, which Linux tier, measured when | capability | public | 0 / 90 / 30 | spec.md#FR-005 |
| `asset.evidence` | The lane report and test results that back each claim (OS, build, arch, sandboxed, tier, ABI, errata) | log | public | 0 / 85 / 60 | spec.md#Key-Entities |
| `asset.frozen-bases` | The frozen base profiles V1 to V3 and their fixtures | source-code | internal | 0 / 95 / 20 | spec.md#FR-006 |
| `asset.repo` | Integrity of the repository, its branches, tags, releases and published pages | source-code | internal | 0 / 100 / 50 | spec.md#FR-007 |
| `asset.token` | The job token and any secret a job could see | credential | secret | 90 / 90 / 10 | spec.md#FR-007 |

## Components

| ID | Name | Type | Trust zone | Source |
|---|---|---|---|---|
| `component.actions` | Third-party actions the workflow uses (checkout, tool installers) | library | `tz.third-party` | spec.md#FR-007 |
| `component.bases` | Frozen base profiles, their fixtures and any new base version a newer macOS needs | library | `tz.repo` | spec.md#FR-006 |
| `component.docs` | README and SECURITY release lists and the platform table | document | `tz.repo` | spec.md#FR-005 |
| `component.lane` | A lane: one job with an image label, architecture, expected tier or macOS major version, and its suites | pipeline | `tz.runner` | spec.md#Key-Entities |
| `component.lane-report` | Kernel facts and the lane report header, with the expected-version and expected-tier assertions | library | `tz.runner` | spec.md#FR-004 |
| `component.suites` | Spawn tests, base program-set tests, escape suite (plain and with reporting, newest base) and the profile-compile check | library | `tz.runner` | spec.md#FR-001 |
| `component.t1-step` | The step that lifts the user-namespace restriction for a T1 job | pipeline | `tz.runner` | spec.md#Clarifications |
| `component.workflow` | The CI workflow file (triggers, permissions, jobs, steps) | pipeline | `tz.repo` | spec.md#FR-007 |

## Data Flows

| ID | Name | From | To | Assets | Crosses |
|---|---|---|---|---|---|
| `flow.actions` | The runner fetches the actions and tools a lane uses | `component.actions` | `component.lane` | `asset.token`, `asset.repo` | `tz.third-party`, `tz.runner` |
| `flow.claims` | The docs tell readers which releases are supported and at which tier | `component.docs` | `actor.consumer` | `asset.claims` | `tz.repo`, `tz.readers` |
| `flow.image` | An image label resolves to an OS release, build and architecture chosen by the image provider | `actor.image-provider` | `component.lane` | `asset.evidence` | `tz.runner` |
| `flow.pr` | A pull request's code is checked out and run by the lanes | `actor.pr-author` | `component.workflow` | `asset.repo`, `asset.token` | `tz.repo` |
| `flow.report` | The lane report and suite results go to the job log as evidence | `component.lane-report` | `component.workflow` | `asset.evidence` | `tz.runner`, `tz.repo` |
| `flow.token` | The workflow hands the job token (and nothing else) to each lane | `component.workflow` | `component.lane` | `asset.token` | `tz.repo`, `tz.runner` |

```mermaid
flowchart LR
    actor_action_author(["Maintainer of a third-party action the workflow uses, or whoever compromises that action's repository"])
    actor_consumer(["Developer of a harness who reads the supported releases and tiers and relies on them"])
    actor_contributor(["procage contributor who edits the workflow, the lane assertions, the base profiles or the platform docs"])
    actor_image_provider(["The provider of the hosted runner images, which updates and remaps image labels on its own schedule"])
    actor_pr_author(["Author of a pull request, possibly from a fork, whose code the lanes build and run"])
    subgraph tz_readers["People who read the README, SECURITY and the platform table"]
    end
    subgraph tz_repo["The public repository, its workflow files, tags and releases"]
        component_bases["Frozen base profiles, their fixtures and any new base version a newer macOS needs"]
        component_docs["README and SECURITY release lists and the platform table"]
        component_workflow["The CI workflow file (triggers, permissions, jobs, steps)"]
    end
    subgraph tz_runner["A hosted runner image (OS release, build, architecture, host security defaults)"]
        component_lane["A lane: one job with an image label, architecture, expected tier or macOS major version, and its suites"]
        component_lane_report["Kernel facts and the lane report header, with the expected-version and expected-tier assertions"]
        component_suites["Spawn tests, base program-set tests, escape suite (plain and with reporting, newest base) and the profile-compile check"]
        component_t1_step["The step that lifts the user-namespace restriction for a T1 job"]
    end
    subgraph tz_third_party["Third-party action repositories and tool downloads"]
        component_actions["Third-party actions the workflow uses (checkout, tool installers)"]
    end
    component_actions -->|"The runner fetches the actions and tools a lane uses"| component_lane
    component_docs -->|"The docs tell readers which releases are supported and at which tier"| actor_consumer
    actor_image_provider -->|"An image label resolves to an OS release, build and architecture chosen by the image provider"| component_lane
    actor_pr_author -->|"A pull request's code is checked out and run by the lanes"| component_workflow
    component_lane_report -->|"The lane report and suite results go to the job log as evidence"| component_workflow
    component_workflow -->|"The workflow hands the job token (and nothing else) to each lane"| component_lane
```

## Threats

| ID | Threat | Category | Technique | Severity | Status | Mitigations | Mappings | Source |
|---|---|---|---|---|---|---|---|---|
| `threat.action-supply-chain` | A third-party action referenced by a tag or branch, or re-pinned to a malicious commit, runs attacker code in a lane with the job token | Tampering, Elevation of Privilege | privilege-escalation-via-config | **high** | open | `mitigation.sha-pins` |  | spec.md#FR-007 |
| `threat.pass-without-evidence` | A lane is green without evidence because enforcement tests skip (AlreadySandboxed, no administrator, a feature missing) or the job is marked continue-on-error or unavailable | Repudiation | missing-audit-trail | **high** | open | `mitigation.no-skip-green` |  | spec.md#FR-001 |
| `threat.silent-image-change` | An image label moves to another OS release, build or architecture (ubuntu-latest to 26.04, xcode-27 to a later macOS, an arm label on x86_64) and the lane stays green while the docs name the old release | Repudiation, Spoofing | missing-audit-trail | **high** | open | `mitigation.assert-expected` |  | spec.md#Edge-Cases |
| `threat.silent-tier-change` | A Linux lane gets a different tier than it states (T1 expected, T2 observed after an AppArmor default change, or the reverse) and the tier-specific tests pass vacuously | Repudiation | missing-audit-trail | **high** | open | `mitigation.assert-expected` |  | spec.md#Clarifications |
| `threat.token-overreach` | A lane gets a writable token or a secret, so pull-request code, a caged test program or a compromised action writes to the repository, releases or pages | Elevation of Privilege, Information Disclosure | credential-theft | **high** | open | `mitigation.least-privilege-workflow` |  | spec.md#FR-007 |
| `threat.expression-injection` | A run step interpolates pull-request text (title, branch name, commit message) into a shell script, which then runs as the workflow | Tampering | injection | **medium** | open | `mitigation.least-privilege-workflow` |  | spec.md#FR-007 |
| `threat.frozen-base-drift` | An allowance macOS 27 needs is edited into a frozen base V1 to V3 instead of a new base version, silently loosening every cage built on it | Elevation of Privilege, Tampering | privilege-escalation-via-config | **medium** | open | `mitigation.new-base-version` |  | spec.md#FR-006 |
| `threat.stale-claims` | README or SECURITY still name a release supported after its lane was removed, turned red or its image retired (macOS 14 on 2026-11-02), or state a tier that was not measured, without a date | Repudiation | missing-audit-trail | **medium** | open | `mitigation.docs-from-lanes` |  | spec.md#FR-005 |
| `threat.t1-unrepresentative` | A T1 job reaches T1 by weakening the host beyond what users would do (AppArmor off, tests as root), so the T1 claim and the docs' advice overstate what users get | Repudiation, Elevation of Privilege | missing-audit-trail | **medium** | open | `mitigation.representative-t1` |  | spec.md#Clarifications |
| `threat.cache-poisoning` | A pull-request job saves a build cache that a main-branch lane restores, so pull-request code alters what main measures | Tampering | data-tampering-at-rest | **low** | open | `mitigation.least-privilege-workflow` |  | spec.md#Context |
| `threat.evidence-expiry` | The lane report lives only in job logs that expire, so a dated claim later cites evidence nobody can see | Repudiation | missing-audit-trail | **low** | open | `mitigation.docs-from-lanes` |  | spec.md#Key-Entities |

### Techniques evaluated without findings

| Technique | Disposition | Reason |
|---|---|---|
| identity-spoofing | no-threat-detected | checked flow.image: the identity that matters is which OS a lane really runs, covered by threat.silent-image-change |
| data-tampering-in-transit | no-threat-detected | checked flow.actions: actions and toolchains are fetched over TLS by the runner; integrity of what is fetched is threat.action-supply-chain |
| cross-tenant-leak | not-applicable | no shared-tenant surface; hosted runners are ephemeral per job and the repository is the only tenant |
| resource-exhaustion | no-threat-detected | checked component.lane: a hung caged test turns the lane red at the job timeout; it delays the signal and grants nothing |
| sensitive-data-exposure | no-threat-detected | checked flow.report: the lane report prints OS, build, architecture, tier, Landlock ABI and errata, all public; tokens are threat.token-overreach |
| prompt-injection-direct | not-applicable | the CI lanes call no model and run no agent; programs run in caged tests are the adversary inside the child, modelled under STRIDE |
| prompt-injection-indirect | not-applicable | the CI lanes call no model and run no agent; programs run in caged tests are the adversary inside the child, modelled under STRIDE |
| sensitive-information-disclosure | not-applicable | the CI lanes call no model and run no agent; programs run in caged tests are the adversary inside the child, modelled under STRIDE |
| excessive-agency | not-applicable | the CI lanes call no model and run no agent; programs run in caged tests are the adversary inside the child, modelled under STRIDE |
| model-supply-chain | not-applicable | the CI lanes call no model and run no agent; programs run in caged tests are the adversary inside the child, modelled under STRIDE |
| training-data-poisoning | not-applicable | the CI lanes call no model and run no agent; programs run in caged tests are the adversary inside the child, modelled under STRIDE |
| unbounded-consumption | not-applicable | the CI lanes call no model and run no agent; programs run in caged tests are the adversary inside the child, modelled under STRIDE |
| misinformation | not-applicable | the CI lanes call no model and run no agent; programs run in caged tests are the adversary inside the child, modelled under STRIDE |
| hidden-context-exposure | not-applicable | the CI lanes call no model and run no agent; programs run in caged tests are the adversary inside the child, modelled under STRIDE |
| vector-embedding-weakness | not-applicable | the CI lanes call no model and run no agent; programs run in caged tests are the adversary inside the child, modelled under STRIDE |
| improper-output-handling | not-applicable | the CI lanes call no model and run no agent; programs run in caged tests are the adversary inside the child, modelled under STRIDE |
| model-extraction | not-applicable | the CI lanes call no model and run no agent; programs run in caged tests are the adversary inside the child, modelled under STRIDE |
| goal-hijack | not-applicable | the CI lanes call no model and run no agent; programs run in caged tests are the adversary inside the child, modelled under STRIDE |
| tool-misuse | not-applicable | the CI lanes call no model and run no agent; programs run in caged tests are the adversary inside the child, modelled under STRIDE |
| identity-privilege-abuse | not-applicable | the CI lanes call no model and run no agent; programs run in caged tests are the adversary inside the child, modelled under STRIDE |
| agentic-supply-chain | not-applicable | the CI lanes call no model and run no agent; programs run in caged tests are the adversary inside the child, modelled under STRIDE |
| unexpected-code-execution | not-applicable | the CI lanes call no model and run no agent; programs run in caged tests are the adversary inside the child, modelled under STRIDE |
| memory-context-poisoning | not-applicable | the CI lanes call no model and run no agent; programs run in caged tests are the adversary inside the child, modelled under STRIDE |
| insecure-inter-agent-communication | not-applicable | the CI lanes call no model and run no agent; programs run in caged tests are the adversary inside the child, modelled under STRIDE |
| cascading-failure | not-applicable | the CI lanes call no model and run no agent; programs run in caged tests are the adversary inside the child, modelled under STRIDE |
| human-agent-trust-exploitation | not-applicable | the CI lanes call no model and run no agent; programs run in caged tests are the adversary inside the child, modelled under STRIDE |
| rogue-agent | not-applicable | the CI lanes call no model and run no agent; programs run in caged tests are the adversary inside the child, modelled under STRIDE |

## Mitigations

| ID | Mitigation | Kind | Threats | Requirements | Touchpoints | Status |
|---|---|---|---|---|---|---|
| `mitigation.assert-expected` | Each lane prints its report header and asserts the expected macOS major version and architecture or Linux tier; any mismatch fails the lane | detective | `threat.silent-image-change`, `threat.silent-tier-change` | SR-004 | `component.lane-report`, `component.lane` | required |
| `mitigation.docs-from-lanes` | The supported list equals the workflow's green lanes, with tier, build and measurement date copied from the lane report; a gate compares docs and workflow | detective | `threat.stale-claims`, `threat.evidence-expiry` | SR-006 | `component.docs`, `component.workflow` | required |
| `mitigation.least-privilege-workflow` | Read-only token at workflow level, no job-level widening in test lanes, no secrets, pull_request trigger only (no pull_request_target or workflow_run running PR code), no PR-saved cache restored on main, untrusted context passed through env only | preventive | `threat.token-overreach`, `threat.expression-injection`, `threat.cache-poisoning` | SR-002, SR-003 | `component.workflow` | required |
| `mitigation.new-base-version` | A newer macOS's allowance lands as a new frozen base version with its program-set measurement; fixtures of V1 to V3 stay byte-identical in CI | preventive | `threat.frozen-base-drift` | SR-007 | `component.bases`, `component.suites` | required |
| `mitigation.no-skip-green` | Enforcement tests fail instead of skipping; no lane whose release is named supported is continue-on-error | preventive | `threat.pass-without-evidence` | SR-005 | `component.suites`, `component.workflow` | required |
| `mitigation.representative-t1` | A T1 job applies only the documented step, logs it, runs the tests unprivileged; without such a step T1 is recorded unavailable | preventive | `threat.t1-unrepresentative` | SR-008 | `component.t1-step`, `component.docs` | required |
| `mitigation.sha-pins` | Every action reference is a full commit SHA with its version as a comment; a lint gate rejects tags, branches and short SHAs | preventive | `threat.action-supply-chain` | SR-001 | `component.workflow`, `component.actions` | required |

## Security Requirements

### SR-001 (P1) — unverified

Every action a workflow uses MUST be referenced by a full 40-character commit SHA; a gate MUST fail on any tag, branch or short-SHA reference.

- **Given** a workflow step using an action at a tag such as v4, **when** the pin gate runs, **then** it fails naming the file and line
- **Given** the workflows on main, **when** the pin gate runs, **then** it passes and every reference carries its version as a comment
- Mitigations: `mitigation.sha-pins`
- Tasks: — none —

### SR-002 (P1) — unverified

Every workflow MUST default to a read-only token; test lanes MUST NOT widen permissions or reference secrets, and no workflow MAY run pull-request code under pull_request_target or workflow_run.

- **Given** the CI workflow, **when** a gate parses it, **then** the top-level permissions are contents read, no test job sets permissions, and no step references secrets
- **Given** a pull request from a fork, **when** its lanes run, **then** the token cannot push, and the job has no secrets
- Mitigations: `mitigation.least-privilege-workflow`
- Tasks: — none —

### SR-003 (P2) — unverified

Run steps MUST NOT interpolate pull-request or commit text into scripts (pass it through environment variables), and a main-branch lane MUST NOT restore a cache saved by a pull-request job.

- **Given** the workflows, **when** a gate searches run steps for github.event and github.head_ref expressions, **then** none appear inside a run script
- **Given** any cache step, **when** its keys are reviewed, **then** main-branch lanes restore only caches saved on main
- Mitigations: `mitigation.least-privilege-workflow`
- Tasks: — none —

### SR-004 (P1) — unverified

Every lane MUST print its OS release and build (or kernel release), architecture, sandbox status, observed tier, Landlock ABI and errata, and MUST fail when the macOS major version, architecture or Linux tier differs from what it expects.

- **Given** the macOS 27 lane expecting major version 27 on arm64, **when** the image reports another major version or architecture, **then** the lane fails naming expected and observed
- **Given** a Linux lane with PROCAGE_EXPECT_TIER=T1, **when** the probe observes T2, or a T2 lane observes T1, **then** the lane fails
- **Given** any green lane, **when** its log is read, **then** the report header shows release, build, architecture, sandboxed no and tier
- Mitigations: `mitigation.assert-expected`
- Tasks: — none —

### SR-005 (P1) — unverified

In CI an enforcement test MUST fail, never skip, when it cannot run (AlreadySandboxed, missing administrator rights, a missing feature), and a lane whose release is named supported MUST NOT be continue-on-error.

- **Given** a lane run inside an outer sandbox, **when** the enforcement tests run, **then** they fail with AlreadySandboxed
- **Given** the workflow, **when** a gate reads it, **then** no lane of a supported release has continue-on-error
- Mitigations: `mitigation.no-skip-green`
- Tasks: — none —

### SR-006 (P2) — unverified

README and SECURITY MUST list as supported exactly the releases with a green lane, each with its build or kernel, measured Linux tier and measurement date, and MUST name every other release untested.

- **Given** a lane removed from the workflow while its release stays listed, **when** the docs gate runs, **then** it fails naming the release
- **Given** macOS 14 retired and macOS 15 without a green lane, **when** the docs are read, **then** both are named untested
- **Given** the platform table, **when** it is read, **then** every Linux lane has its measured tier and date
- Mitigations: `mitigation.docs-from-lanes`
- Tasks: — none —

### SR-007 (P1) — unverified

Existing base profile versions MUST stay byte-identical; an entry a newer macOS needs MUST be a new frozen base version with its own program-set measurement on that release.

- **Given** the fixtures of base V1 to V3, **when** CI compiles each base, **then** the output equals the fixture byte for byte
- **Given** a base entry added for macOS 27, **when** it is reviewed, **then** it is in a new base version whose program-set test passed on the 27.x lane with the build recorded
- Mitigations: `mitigation.new-base-version`
- Tasks: — none —

### SR-008 (P2) — unverified

A T1 job MUST apply only the documented step that lifts the user-namespace restriction, MUST log that step and run the tests unprivileged; where no such step exists, the docs MUST record T1 as unavailable without host changes.

- **Given** a T1 job, **when** its log is read, **then** it shows the exact step applied and the tests ran as a non-root user
- **Given** Ubuntu 26.04 with no documented step, **when** the docs are read, **then** they state T1 is unavailable there without host changes
- Mitigations: `mitigation.representative-t1`
- Tasks: — none —
