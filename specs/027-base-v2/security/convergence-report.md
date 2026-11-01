## Security Convergence — 027-base-v2

Commit `407f2e0` · 2026-10-31T20:17:57Z

| Metric | Value |
|---|---|
| Threats (active) | 4 |
| Open blocking threats | 0  |
| Security requirements | 3 |
| verified | 3 |
| implemented, unverified | 0  |
| partial | 0  |
| missing | 0  |
| Expired decisions | 0  |
| Source drift | none |

**Status: CONVERGED**

| Requirement | Verdict | Method | Evidence | Justification |
|---|---|---|---|---|
| SR-001 | verified | test | `tests/spawn_macos.rs::base_v2_runs_developer_tools, crates/procage-policy/tests/base.rs::v2_adds_no_service` | Under base V2 with the tmpdir grant, getconf DARWIN_USER_TEMP_DIR and mktemp both land in the child's private TMPDIR (the caged test prints "private"); the policy test asserts V2's mach-lookup rules equal V1's and name neither dirhelper nor membership. |
| SR-002 | verified | test | `tests/spawn_macos.rs::base_v2_grants_nothing_personal` | Under base V2 the child cannot list the home, read ~/Library/Preferences or ~/.ssh, read a Homebrew etc file that is not OpenSSL's, write /opt/homebrew or /usr/local, or connect to a loopback port; stat of $HOME succeeds as documented. |
| SR-003 | verified | test | `crates/procage-policy/tests/base.rs::macos_v2_is_v1_plus_its_pinned_additions, crates/procage-policy/tests/base.rs::every_base_rule_has_a_filter, crates/procage-policy/tests/presets.rs::every_v2_preset_is_pinned, crates/procage-policy/tests/presets.rs::every_preset_is_pinned` | V1's rendered allows are pinned and unchanged; V2 is V1 plus three pinned rules; every base rule except V1's sysctl-read carries a filter (rendered and structural check); the v1 and v2 preset profiles are pinned fixtures. |
