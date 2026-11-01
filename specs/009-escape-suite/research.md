# Research: The escape suite

Measured hosts: macOS 26.6.2 (25G83) arm64; Docker Desktop Linux
7.0.14-linuxkit aarch64, Landlock ABI 8, T1 (seccomp/apparmor unconfined)
and T2 (Docker default). Predictions below are confirmed or corrected in
quickstart.md after the run.

## R1 — Canary shape

- **Decision**: A canary spawns this test binary (`child_entry`, selected
  by `PROCAGE_CHILD`) or a system program, in a cage built from base V1
  plus the rules the attempt needs. It asserts the exact refusal: an
  errno, a non-zero Mach return code, or a typed `SpawnError` /
  `LowerError`. Every canary has a **positive control**:
  - (a) the same operation on a granted target succeeds; or
  - (b) the same attempt with the class waived (`policy.waive`) does
    *not* fail with the refusal errno.

  (b) proves that procage's rule, not the host, refuses.
- **Rationale**: A canary that asserts only failure passes for a missing
  file or tool (threat.false-pass). A control under the same cage rules
  that out.
- **Alternatives**:
  - Uncaged controls. These need `unsafe` `pre_exec` in tests and do not
    share the cage's setup.
  - Comparing emitted SBPL/BPF. That is not evidence (principle III).

## R2 — Open variants

- **Decision**: An open variant is a canary that asserts the refusal like
  any other and carries `#[ignore = "open: R-NN <variant>"]`. Running
  `cargo test --test escape_<os> -- --ignored` shows the escape. Such a
  canary kills every pid it learns before it asserts.
- **Rationale**: The open canary is then ready to be un-ignored when the
  fix lands, and the gate can find it by name.
- **Alternatives**: Tripwire canaries that assert the escape *succeeds*.
  They flip red on unrelated kernel changes, and they read as an
  endorsement of the escape.

## R3 — Status vocabulary

- **Decision**: Add `partial` (allowed for `mitigate` and `detect`). It
  needs at least one non-ignored canary as evidence and an
  `### Open variants` entry. `mitigated`/`detected` need non-ignored
  evidence in every listed platform's file and no open canary for the
  class. Evidence may be listed for any status, but it must be valid.
- **Rationale**: Several classes are handled on one system or for most
  variants. Collapsing them to `planned` hides real protection, and
  `mitigated` would overclaim.
- **Alternatives**: Per-platform status cells. These change the table
  grammar more, and a reader still needs the note.

## R4 — Linux lanes and tiers

- **Decision**: The CI Linux lanes run `spawn_linux` and `escape_linux`
  with `PROCAGE_EXPECT_TIER`:
  - Ubuntu as shipped: T2 (AppArmor restricts user namespaces);
  - Ubuntu with the restriction lifted: T1;
  - the Debian container: T2;
  - the 26.04 preview: unset, recorded only.

  Docker Desktop locally gives T1 (unconfined) and T2 (default).
- **Rationale**: 008 added the Linux spawn tests but no lane ran them.
- **Informative lanes**: under Docker's default profile, `unshare`,
  `mount`, `io_uring_*`, `bpf`, `keyctl`, `perf_event_open`,
  `userfaultfd` and AF_VSOCK are already blocked by the host. The R-28 and
  R-29 canaries therefore print `informative=false` there and take their
  evidence from T1 (threat.uninformative-lane, SR-002).

## R5 — Per class

Legend: **A** attempt, **R** expected refusal, **C** control, **P**
predicted status. M = macOS, L = Linux.

### R-02 Non-canonical path rules (M, L)

- **M**: protect `scratch/p`, spelled through `/var/folders/…`, the
  symlinked spelling of the temp dir; write on `scratch`.
  - A: write `/private/var/…/p/f`. R: EPERM.
  - C: write `scratch/q` succeeds.
- **L T1**: protect spelled through a symlink to `scratch/p`.
  - A: write through the real path. R: EROFS.
  - C: write a sibling succeeds.
- **L T2**: protect is refused with a typed gap (fail closed).
- **P**: mitigated.

### R-03 Pattern characters (M)

- Grant write on `scratch/a*`; `scratch/ab` exists.
- A: write `scratch/ab/f`. R: EPERM.
- C: write `scratch/a*/f` succeeds.
- **P**: mitigated.

### R-04 Ancestor rename (M, L)

- Write on W; protect `W/sub/p` with content.
- A: rename `W/sub` → `W/moved`, then write `p` under **both** names.
- R (M): the rename fails with EPERM (rename-anchor deny), and both writes
  fail.
- R (L T1): the mount follows the dentry, so the rename may succeed, but
  writes fail with EROFS under every name. On T2, protect is a typed gap.
- C: write `W/other` succeeds.
- Also (M): renaming W itself fails.
- **P**: mitigated.

### R-05 fcntl modify through a read-only fd (M)

- The child opens a granted file read-only.
- A: `fcntl(fd, 80 /* F_MAKECOMPRESSED */)` and `fcntl(fd, 110)`.
  R: EPERM.
- C: with `FcntlModify` waived, errno ≠ EPERM.
- **P**: mitigated.

### R-06 Service handoff (M)

- A: `bootstrap_look_up` for `com.apple.coreservices.launchservicesd`,
  `com.apple.coreservices.appleevents` and `com.apple.pasteboard.1`.
  R: kern_return ≠ 0.
- C: with `ServiceHandoff` waived and a raw `mach-lookup` allow for those
  names, the lookup succeeds.
- A lookup is not an action, so nothing is launched (FR-013).
- **P**: mitigated.

### R-07 Trust handoff (M, L; harness)

- Write on a scratch repo.
- A: write `.git/hooks/pre-commit`, `.git/config`, `.bashrc`.
  R: EPERM (M), EROFS (L T1); on L T2 the cage is refused unless waived.
- C: write `src.rs` succeeds.
- **P**: documented (harness), with canaries as evidence for the
  procage part.

### R-08 Pre-existing hard links (M, L; detect)

- A scratch `home/.ssh/id` and a hard link `ws/id-link` to it, with read
  on ws.
- **Open**: procage neither reports nor blocks this. The canary asserts
  a report or refusal and is ignored.
- **P**: planned.

### R-09 Local daemons (M, L)

- **M**: `Network::Loopback(port A)`, a parent listener on A and on B, and
  a unix socket in a readable scratch dir.
  - A: connect B, and connect the unix socket. R: EPERM (or
    ECONNREFUSED is *not* accepted: the listener exists).
  - C: connect A succeeds.
  - `Network::None` refuses all three.
- **L**: `Network::None`.
  - A: TCP connect to a parent listener, and unix connect to a parent
    socket in a readable dir. R: EPERM (`socket` denied).
  - C: with `Network::All`, the unix connect succeeds.
  - `Loopback` and `UnixSockets` (ABI < 9) are typed gaps.
- **P**: mitigated.

### R-10 Shared temporary directory (M, L)

- Run 1 with the `tmpdir` grant writes `f` in its TMPDIR and reports the
  path. Run 2, with its own `tmpdir` grant, reads that path.
  R: EPERM (M) or EACCES (L).
- Run 2 also cannot write the shared temp root.
- C: run 2 writes its own TMPDIR.
- **P**: mitigated.

### R-11 Unsandboxed exec modifier (M)

- The modifier cannot be expressed: there is no IR for it.
- The canary checks the effect the modifier would have. The caged child
  execs `/bin/cat` on a file outside the policy. R: the grandchild is
  refused (EPERM).
- C: `/bin/cat` on a granted file succeeds.
- **P**: mitigated.

### R-12 Firmlink spelling (M)

- Protect spelled `/System/Volumes/Data/private/var/folders/…/p`.
- A: write through `/private/var/…/p/f`. R: EPERM.
- C: write a sibling succeeds.
- **P**: mitigated.

### R-21 Inherited fds (M, L)

- The parent opens a file outside the policy without CLOEXEC.
- A: the child checks the fd. R: not open.
- C: the same fd handed over with `spawn_with_fds` is open and readable.
- **P**: mitigated.

### R-22 Terminal injection (M, L)

- The parent opens a pty and grants read+write on the slave path. The
  child, a session leader, opens the slave and makes it its controlling
  terminal (`TIOCSCTTY` on macOS; implicit on Linux).
- A: `ioctl(TIOCSTI, 'x')`. R: EPERM.
- C: with `TerminalInjection` waived, TIOCSTI succeeds (KF-M26:
  injecting into one's own terminal works sandboxed or not).
- **P**: mitigated, if the slave can be granted; else the canary records
  why.

### R-23 Outliving the run (M, L)

- **Kill**: the child starts one same-group sleeper and one `setsid`
  sleeper; dropping the handle kills both.
- **Double fork (open, M and L)**: the child starts an intermediate that
  starts a `setsid` sleeper and exits; the sleeper is reparented. Ignored
  `open: R-23 double fork`.
- **Persistence**:
  - M: write a unique plist into `~/Library/LaunchAgents` under a write
    grant there. R: refused, and the file does not exist (removed
    if created).
  - L T1: a fake home via `CageOptions::with_home` with
    `.config/systemd/user`. R: EROFS.
  - L T2: refused cage.
- **P**: partial (double fork).

### R-24 Secrets in the environment (M, L)

- The parent sets `GITHUB_TOKEN`, `AWS_SECRET_ACCESS_KEY` and
  `SSH_AUTH_SOCK`.
- A: the child lists its env under the default (allowlist) policy and
  under passthrough. R: none present.
- C: an explicitly set variable is present.
- **P**: mitigated.

### R-25 Process introspection (M, L)

- **M**:
  - A: `sysctl(KERN_PROCARGS2)` for the parent pid. R: EPERM.
  - A: `kill(parent, 0)`. R: EPERM.
  - C: KERN_PROCARGS2 for its own pid succeeds.
- **L**:
  - A: read `/proc/<parent>/environ`. R: EACCES/EPERM.
  - A: read `/proc/<parent>/cmdline`. R: refused, if base V1 grants no
    /proc read of other pids.
  - A: `ptrace` and `process_vm_readv`. R: EPERM.
  - C: `/proc/self/environ` is readable.
- **P**: mitigated, or partial if `cmdline` is readable on Linux (no PID
  namespace).

### R-26 Helper replacement (M, L)

- No helper exists in this release (path B, feature 021).
- The canary is ignored `open: R-26 no helper in this release`.
- **P**: planned.

### R-28 Filter-bypassing interfaces (L)

- A: `io_uring_setup`, `socket(AF_NETLINK)`, `socket(AF_VSOCK)`.
  R: EPERM.
- C: with `KernelSurface` and `SocketFamilies` waived, errno ≠ EPERM
  (informative on T1).
- **P**: mitigated (evidence from T1).

### R-29 Nested user namespaces (L)

- A: `unshare(CLONE_NEWUSER)`, `clone3` (ENOSYS), `mount` (remount rw of a
  protected path), `umount`. R: EPERM, or ENOSYS for clone3.
- C: with `Namespaces` waived, `unshare(CLONE_NEWUSER)` errno ≠ EPERM on T1.
- **P**: mitigated.

### R-30 Landlock rule loss (L)

- **T1**: protect file F.
  - A: write a temp file and rename it over F. R: EBUSY (F is a
    mountpoint).
  - A: write F. R: EROFS.
- A Literal rule on a missing path fails the spawn with `SpawnError::Path`
  (fail closed).
- **T2**: protect is a typed gap.
- **P**: mitigated.

## R6 — Follow-ups for open variants

- R-08: hard-link audit, both systems (follow-up 023-hardlink-audit).
- R-23: the double-fork escape. On Linux, a session/group lock in seccomp
  or a PID namespace; on macOS no kernel means is known (follow-up
  024-lifetime).
- R-26: helper integrity (existing follow-up 021-helper).
- Any class the run leaves partial gets a follow-up in the same way.
