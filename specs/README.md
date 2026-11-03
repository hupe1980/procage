# Design records

Every change to procage is specified, threat-modelled and verified before it
ships. This directory holds the record of each change, one numbered folder
per change, written with [Spec Kit](https://github.com/github/spec-kit) and
its [ThreatSpec](https://github.com/hupe1980/spec-kit-threatspec) extension.

These are **records of each change as it was made**: the state, the numbers
and the open items are those of that day. What procage promises today is in
the [README](../README.md), the [threat model](../crates/procage/THREAT_MODEL.md)
and the [documentation](https://hupe1980.github.io/procage/). Where a record
and those documents differ, the documents are right.

## What a record holds

| File | What it is |
|---|---|
| `spec.md` | What the change must do and why: user stories, acceptance scenarios, requirements (`FR-…`), success criteria (`SC-…`), the decisions taken during clarification, and the security requirements (`SR-…`) derived from the threat model |
| `research.md` | Measurements and experiments behind the design, on real kernels |
| `plan.md` | How it is built, checked against the [constitution](../.specify/memory/constitution.md) |
| `tasks.md` | The work, in order, each task tied to a story and its security requirements; later phases record what implementation found |
| `threat-model.yaml`, `threat-model.md` | The threat model ([Open Threat Model](https://github.com/iriusrisk/OpenThreatModel)-compatible), rendered for reading |
| `security/` | Verdicts and the convergence report: how each security requirement was verified |
| `quickstart.md` | How to run the checks, and the results on the day |
| `contracts/`, `data-model.md`, `checklists/` | Interfaces, types and the spec quality checklist, where a change has them |

## How a change is made

```text
specify ─▶ threat model ─▶ clarify ─▶ plan ─▶ threat model (from the plan)
        ─▶ tasks ─▶ check ─▶ analyze ─▶ implement ─▶ converge (security, then core)
```

ThreatSpec turns each threat into a chain that must close before a change is
done:

```text
asset ─▶ threat ─▶ mitigation ─▶ security requirement (SR-…)
                                    ├──▶ task in tasks.md
                                    └──▶ verification: a test, a review or evidence
```

`check` finds any broken link (a threat without a mitigation, a requirement
without a task); `converge` records how each requirement was verified and is
clean only when every one is. A claim procage makes about enforcement is
backed by a caged test on a real kernel, never by the profile text alone.

## Index

### Shipped in 0.1.0

| Record | Change |
|---|---|
| [001-kernel-facts](001-kernel-facts/spec.md) | Kernel facts as regression tests |
| [002-threat-model](002-threat-model/spec.md) | Published threat model and escape-class contract |
| [003-policy-ir](003-policy-ir/spec.md) | Portable policy IR and its lowering to each backend |
| [004-spawn-macos](004-spawn-macos/spec.md) | Spawn a caged child on macOS |
| [005-hygiene](005-hygiene/spec.md) | Process hygiene for caged children |
| [006-base-profile](006-base-profile/spec.md) | A base profile that lets ordinary programs start |
| [007-hard-deny-and-presets](007-hard-deny-and-presets/spec.md) | Data-driven hard denies and frozen presets |
| [008-spawn-linux](008-spawn-linux/spec.md) | Spawning a caged child on Linux |
| [009-escape-suite](009-escape-suite/spec.md) | The escape suite |
| [010-violations](010-violations/spec.md) | Violations — what the sandbox denied, and why |
| [024-lifetime](024-lifetime/spec.md) | Lifetime — nothing a run starts outlives it |
| [026-consumer-api](026-consumer-api/spec.md) | Consumer API before the freeze |
| [027-base-v2](027-base-v2/spec.md) | Base profile V2 — developer tools work in a cage |
| [028-linux-gaps](028-linux-gaps/spec.md) | Unix sockets under trees, and hiding on Linux T2 |
| [029-exec-entry](029-exec-entry/spec.md) | Exec entry — a helper becomes the caged command |
| [030-older-kernels](030-older-kernels/spec.md) | Older Linux kernels — honest confinement from Landlock ABI 1 |
| [032-fit](032-fit/spec.md) | Fitting a policy to the host |
| [034-linux-violations](034-linux-violations/spec.md) | Linux violations — exact reports of refused system calls |
| [036-base-v3](036-base-v3/spec.md) | Base V3 and quiet records |
| [037-public-design-records](037-public-design-records/spec.md) | Public design records |
| [038-snapshot-covers-and-report-loss](038-snapshot-covers-and-report-loss/spec.md) | Vanished snapshot covers and honest report loss |

### Shipped since 0.1.0

| Record | Change | Release |
|---|---|---|
| [041-service-sockets](041-service-sockets/spec.md) | No service handoff over Unix sockets | 0.2.0 |
| [011-receipts](011-receipts/spec.md) | Receipts — evidence of how a run was caged | 0.2.0 |
| [042-explain](042-explain/spec.md) | Explain and diff, checked against the kernel | 0.2.0 |
| [023-tree-audit](023-tree-audit/spec.md) | Audit of the writable trees, before and after a run | 0.2.0 |
| [025-introspection](025-introspection/spec.md) | Other processes stay opaque | 0.2.0 |
| [043-benchmarks](043-benchmarks/spec.md) | Published spawn benchmarks | 0.2.0 |
| [013-tokio](013-tokio/spec.md) | Async integration (tokio) | 0.3.0 |
| [016-proxy](016-proxy/spec.md) | Egress proxy with a domain allowlist | 0.3.0 |
| [044-kernel-matrix](044-kernel-matrix/spec.md) | Kernel matrix and newer Landlock ABIs | 0.3.0 |
| [045-moves-and-link-exemptions](045-moves-and-link-exemptions/spec.md) | Moves between writable directories, and link-check exemptions | 0.3.0 |
| [046-process-groups](046-process-groups/spec.md) | Process groups under `Lifetime::Run` on Linux | 0.3.1 |
| [047-exec-session](047-exec-session/spec.md) | A helper's command in a session of its own | 0.3.2 |
| [048-ip-network](048-ip-network/spec.md) | An IP network without Unix sockets | 0.4.0 |
| [039-ci-lanes](039-ci-lanes/spec.md) | CI lanes for the releases people run | 0.4.1 |
| [040-path-resolution](040-path-resolution/spec.md) | Path resolution that cannot be redirected or mis-spelled | 0.4.1 |
| [022-pty](022-pty/spec.md) | A fresh pseudo-terminal for interactive runs | 0.5.0 |
| [017-grant-on-denial](017-grant-on-denial/spec.md) | Grant on denial | 0.5.0 |
| [020-python](020-python/spec.md) | Python bindings | 0.6.0 |
| [049-nodejs](049-nodejs/spec.md) | Node.js bindings | 0.7.1 |

## Reading order

Start with [001-kernel-facts](001-kernel-facts/spec.md) (what the kernels
really do) and [002-threat-model](002-threat-model/spec.md) (what procage
defends against), then any change that interests you. Numbers are
allocation order; gaps belong to changes that are not public, not started,
or waiting for a trigger (a helper binary for macOS, importing existing
Seatbelt profiles).
