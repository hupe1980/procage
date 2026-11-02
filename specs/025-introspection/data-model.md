# Data model

- `HardDenyClass::ProcessAccess` (existing) — on macOS gains three Seatbelt
  rules: `(deny sysctl-read (sysctl-name-prefix "kern.procargs"))` among its
  hard denies, a quiet early `(deny process-info-pidinfo (with no-report))`
  and `(allow process-info-pidinfo (target same-sandbox))`. Waiving the class
  removes all three. No new base, no new preset version.
- `sbpl::Filter::SysctlName`, `sbpl::Filter::SysctlNamePrefix` — Seatbelt
  filters `(sysctl-name …)` and `(sysctl-name-prefix …)`.
- `Construct::ProcOtherProcesses` — `proc-other-processes`, Linux
  approximation on both tiers.
- `procage_policy::linux::reaches_other_processes(path)` — whether a path
  reaches other processes' `/proc` entries; `PROC_OTHER_PROCESSES_NOTE` — the
  approximation's note, shared by the plan and the receipt.
- `RunFacts::with_approximation` (procage, internal) — a run's receipt lists
  an approximation only its grants made.
