## Security Convergence — 036-base-v3

Commit `2e3e490` · 2026-11-01T07:09:33Z

| Metric | Value |
|---|---|
| Threats (active) | 4 |
| Open blocking threats | 0  |
| Security requirements | 4 |
| verified | 4 |
| implemented, unverified | 0  |
| partial | 0  |
| missing | 0  |
| Expired decisions | 0  |
| Source drift | none |

**Status: CONVERGED**

| Requirement | Verdict | Method | Evidence | Justification |
|---|---|---|---|---|
| SR-001 | verified | test | `crates/procage-policy/tests/base.rs::v3_is_v2_plus_quiet_denies; crates/procage-policy/tests/presets.rs::every_v3_preset_is_pinned; crates/procage/tests/escape_macos.rs (PROCAGE_ESCAPE_BASE=v3)` | For every reference policy, the V3 profile minus its three no-report lines equals the V2 profile; V1/V2 and presets v1/v2 fixtures pass unchanged; presets v3 are pinned and equal v2 apart from the base; the macOS escape suite passes 23/23 on base V3 with reporting. |
| SR-002 | verified | test | `crates/procage-policy/tests/base.rs::quiet_targets_are_not_hard_deny_targets` | No quiet service name or path appears in any hard-deny or data-class rule of the full hard-deny policy, and V3 adds exactly three quiet lines from the fixed list (base::MACOS_V3_QUIET_SERVICES, dtracehelper, /dev/tty). |
| SR-003 | verified | test | `crates/procage/tests/spawn_macos.rs::v3_keeps_a_granted_terminal; crates/procage-policy/tests/precedence.rs::blocks_are_in_fixed_order_and_the_tier_is_last` | Every quiet deny precedes every allow in every reference profile; with Tty::Inherit the caged open of /dev/tty is not refused by the sandbox (ENXIO from the kernel, no EPERM). KF-M30 pins that a later allow overrides a no-report deny. |
| SR-004 | verified | test | `crates/procage/src/violation.rs::only_equal_denials_merge; crates/procage/src/violation.rs::the_record_keeps_the_cap_and_counts_the_rest` | Violations differing in pid, process, operation, target or kind stay separate; equal ones merge and the count saturates at u32::MAX; past the cap a kept entry keeps counting and a new key is dropped. Caged tests show a repeated read as one entry (macOS) and a 20,000-call flood as one entry with 20,000 repeats (Linux T1/T2). |
