## ThreatSpec Check Report

Feature: `020-python` · Model: `threat-model.yaml` · Enforcement: `warn`

| ID | Check | Severity | Location | Summary | Recommendation |
|---|---|---|---|---|---|
| F1 | C6 | LOW | `threat-model.yaml#requirements` | 7 requirements have no verification entry yet (implementation not started): SR-001, SR-002, SR-003, SR-004, SR-005, SR-006, SR-007 | Expected before implementation; run the converge command afterwards |
| F2 | C9 | LOW | `plan.md` | plan.md was not hashed when the model was generated | Re-run the model command |

**Metrics**

- threats: 7
- mitigations: 7
- requirements: 7
- requirements with tasks: 7
- requirements verified: 0
- decisions: 0
- threats by severity: high 2, low 1, medium 4
- findings: low 2

**Next actions**

- Proceed.
