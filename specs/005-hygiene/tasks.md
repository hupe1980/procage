---

description: "Task list for 005-hygiene"
---

# Tasks: Process hygiene for caged children

**Tests**: Required (FR-010).

---

## Phase 1: Foundational

- [X] T001 [SR-005] Create `src/hygiene.rs` (all OSes, exported as `pub mod hygiene`). It holds the denylist constants (prefixes `DYLD_`, `AWS_`; names `LD_PRELOAD`, `LD_LIBRARY_PATH`, `SSH_AUTH_SOCK`; suffixes `_TOKEN`, `_SECRET`, `_PASSWORD`, `_API_KEY`), `EnvDecision`, and the pure `environment(caller, policy, explicit)`, plus unit tests: allowlist as written; passthrough drops each pattern and reports it; explicit variables win; explicit removals remove.
- [X] T002 [SR-001] [SR-003] Extend `src/macos/sys.rs`:
  - a `Group::{Session, ProcessGroup}` step (`setsid` / `setpgid(0, 0)`);
  - a descriptor step `Fds` (6): `proc_pidinfo` into a parent buffer, mark close-on-exec everything ≥ 3 not kept, clear close-on-exec on kept fds, falling back to an `fcntl` sweep up to `getdtablesize()` when the buffer is full or listing fails;
  - `fd_count_estimate()` for buffer sizing;
  - `fd_is_open(fd)`;
  - `killpg`, `kill`, `descendants(pid)` via `proc_listchildpids` (repeat until stable, at most 8 rounds);
  - testing helpers `clear_cloexec(fd)`, `alive(pid)`, `spawn_sleeper(setsid) -> u32`.

  Every `unsafe` block gets a SAFETY comment.

## Phase 2: US1 - descriptors (P1) 🎯 MVP

- [X] T003 [US1] [SR-001] [SR-002] Add `Step::Fds`, `SpawnError::Fd { fd }`, and `Cage::spawn_with_fds(cmd, grants, &[BorrowedFd])` in `src/macos/mod.rs`, with named fds validated by `fd_is_open`. Size the buffer in the parent and pass the keep list into `ChildPlan`.
- [X] T004 [US1] [SR-001] [SR-002] [SR-003] Add tests to `tests/spawn_macos.rs`:
  - a denied file's fd with close-on-exec cleared is absent in the child (`fd:N` → `open=false`);
  - the same fd named is readable;
  - 1,000 extra fds open give `fdcount=0`;
  - a named fd that is not open gives `SpawnError::Fd`;
  - a failed rlimit step after the sweep is still `Apply { Rlimit }`;
  - naming fd 1 is accepted as a no-op.

## Phase 3: US2 - lifetime (P1)

- [X] T005 [US2] [SR-004] Create `src/macos/child.rs`: `Child` (Deref/DerefMut to `std::process::Child`) with `kill_all()` (descendant walk, SIGKILL, `killpg`, wait), `detach()`, `dropped_env()`, `tmpdir()`, and `Drop`. `Cage::spawn` returns `Child`; `Tty::Inherit` uses `Group::ProcessGroup`.
- [X] T006 [US2] [SR-004] Add tests:
  - `sleepers`: a caged child starts a same-group sleeper and a setsid sleeper and prints their pids; after dropping the handle, both are dead within 1 s;
  - a detached handle leaves the child alive (the test kills it afterwards);
  - after the caller waited for the child (leader reaped), dropping the handle still kills the remaining same-group sleeper.

## Phase 4: US3 - environment and tmpdir (P2)

- [X] T007 [US3] [SR-005] Route `src/macos/spawn.rs::environment` through `hygiene::environment`; the handle carries `dropped`.
- [X] T008 [US3] [SR-006] Add the per-spawn tmpdir in `src/macos/mod.rs`/`child.rs`: if the policy declares grant `tmpdir`, create a 0700 directory under the canonical temp dir, bind the grant, and set `TMPDIR` unless explicit. A caller binding `tmpdir` is `GrantError::Reserved`. Drop removes the directory.
- [X] T009 [US3] [SR-005] [SR-006] Add tests:
  - an uncaged intermediary with `GITHUB_TOKEN`, `SSH_AUTH_SOCK` and `DYLD_INSERT_LIBRARIES` spawns a passthrough caged child: none is visible, all are reported, and an explicit `GITHUB_TOKEN` is visible;
  - two tmpdir spawns get different `TMPDIR`s, each writes its own file, each directory is removed after drop, and binding `tmpdir` explicitly is `Reserved`.

## Phase 5: Polish

- [X] T010 [SR-007] Docs: the `src/macos/mod.rs` "observed" list gains fds, lifetime, environment denylist and tmpdir; "not done" keeps double fork, pty (022) and Linux. Update the crate docs, the README status and the `THREAT_MODEL.md` release status; statuses stay unchanged.
- [X] T011 Extend the `latency` measurement with 1,000 extra fds, and record it.
- [X] T012 Inject the four quickstart defects (refreshing the restore time), confirm each is caught, and record the results.
- [X] T013 Run `just ci`, record the outcomes, and record the decision, including the later 022-pty feature. Then commit on `main`.

---

## Phase 6: Convergence

- [X] T014 Add a caged-child test that with `Tty::Inherit` the child leads its own process group (not a session), so lifetime control applies in that mode too, per FR-004 (partial)
