# Tasks: Unix sockets under trees, and hiding on Linux T2

## Phase 1: Foundational (policy crate)

- [X] T001 [SR-004] `Ipc.unix_sockets` in crates/procage-policy/src/policy.rs; remove `Network::UnixSockets` and `PolicyError::EmptyUnixSockets`; construct `ipc-unix-sockets`; `Construct::SPAWN_SNAPSHOT`; rename `accept_spawn_masks` → `accept_spawn_snapshot`; gap Display names the option for snapshot constructs (crates/procage-policy/src/lower/mod.rs); update callers (src/linux/mod.rs docs, tests/exec.rs, tests/native.rs, crates/procage-policy/tests)
- [X] T002 [SR-001] macOS lowering in crates/procage-policy/src/lower/macos.rs (system-socket + network ops with subpath filters; hidden paths deny them); src/macos/canon.rs resolves `ipc.unix_sockets`
- [X] T003 [SR-001] [SR-002] Linux lowering in crates/procage-policy/src/lower/linux.rs: AF_UNIX-only socket filter, ABI 9 / T1 approximated (mask flag + paths + abstract scope) / T2 unsupported; `LinuxPlan.unix_socket_paths` in crates/procage-policy/src/linux.rs
- [X] T004 [SR-003] Linux lowering: T2 `Hide` approximated unless a write rule reaches it; secrets class on T2 approximated when reached only by read rules
- [X] T005 [SR-004] Policy tests: lowering table rows (crates/procage-policy/src/lowering.md, tests/common reference policy), gaps tests (snapshot set pinned, message names the option, T2 hide with/without write, secrets T2 read/write, sockets per tier/ABI), serde (`ipc.unix_sockets`, removed variant refused), preset fixtures unchanged

## Phase 2: User Story 1 — sockets (P1)

- [X] T006 [US1] [SR-001] [SR-002] Linux backend: socket masks from `/proc/net/unix` on T1 (src/linux/spawn.rs + prepare in src/linux/mod.rs), skipping relative, missing, non-socket, allowed and already-masked paths
- [X] T007 [US1] [SR-001] [SR-002] Canaries: `r09_unix_sockets_reach_only_their_paths` in tests/escape_macos.rs and tests/escape_linux.rs (bind+connect inside, outside daemon refused, TCP refused; Linux: host abstract socket refused; T2 refused naming the construct; T1 needs the option); replace the old `Network::UnixSockets` controls

## Phase 3: User Story 2 — T2 hiding (P2)

- [X] T008 [US2] [SR-003] Linux backend: hidden set on T2 and piecewise expansion in src/linux/spawn.rs (skip symlinks, drop rules at/under hidden, walk limit), `GrantError::Covers` in src/linux/mod.rs
- [X] T009 [US2] [SR-003] Tests in tests/spawn_linux.rs (T2): sibling readable, hidden unreadable directly and through a symlink sibling, entry created later on the way unreadable, write rule refused, write grant around refused, secrets class with read `/` and a test home; update existing T2-hide expectations (tests/spawn_linux.rs, tests/escape_linux.rs)

## Phase 4: DX, docs, polish

- [X] T010 [P] Docs: lowering table notes, linux module docs ("reading everything except secrets" on T1 and T2, Unix sockets), THREAT_MODEL (R-09 note, release status), README line
- [X] T011 Docker T1/T2, macOS suites; record in quickstart.md
- [X] T012 `just ci`; record the decision (it renames the option of 026 to `accept_spawn_snapshot`); commit on `main`
