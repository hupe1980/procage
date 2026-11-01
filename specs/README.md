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

## Reading order

Start with [001-kernel-facts](001-kernel-facts/spec.md) (what the kernels
really do) and [002-threat-model](002-threat-model/spec.md) (what procage
defends against), then any change that interests you. Numbers are
allocation order; gaps belong to changes that are not public or not started.
