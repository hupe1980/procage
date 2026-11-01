# Quickstart

1. `cargo test -p procage-policy` (pins, filters, presets).
2. `cargo test -p procage --test spawn_macos base_v2` (installed tools; refusals).
3. `just linux`, `just linux-t1` (Base::V2 lowers like V1).
4. `just ci`.

## Recorded outcomes (2026-10-31)

- Research (research.md): V1 failed or could not run 11 of 27 workloads;
  the final V2 runs every installed one (`cargo` not on PATH). dirhelper and
  membership are left out on evidence (they redirect tools to the shared
  per-user temporary directory). The first measurement of a `git` workspace
  showed a second gap: `git` needs metadata of the workspace's parents;
  V2 allows metadata of the directories on the way to the policy's paths
  and of the per-user `/private/var/folders` chain.
- Policy crate: 83 passed (V2 pinned as V1 + 3 rules, V1 unchanged, no
  unfiltered base rule, no service beyond V1, Linux V2 = V1, ancestor
  metadata only under V2, v2 presets pinned: each v1 fixture + 3 base rules,
  `build` + the workspace socket rule).
- macOS 26.6.2: `base_v2_runs_developer_tools` (clang build, git commit,
  make, python3 with ssl/sqlite3, ruby, perl, node, jq, xcrun SDK path equal
  to uncaged, per-user temp dir = private TMPDIR, warm shim < 200 ms, V1
  shim fails), `base_v2_grants_nothing_personal` (home listing, home
  preferences, ~/.ssh, other /opt/homebrew/etc file, writes to /opt/homebrew
  and /usr/local, network refused; stat of $HOME allowed),
  `agent_workspace_v2_builds_with_clang`; spawn suite 47, escape 23, exec 6,
  native 3.
- Linux T2 and T1: `base_v2_runs_programs_on_linux` and all suites pass;
  Linux clippy and rustdoc clean.
- `just ci`: all 10 gates.
