# Implementation Plan: Path resolution that cannot be redirected or mis-spelled

**Branch**: `040-path-resolution` (local planning; commits on `main`) | **Date**: 2026-11-03 | **Spec**: [spec.md](spec.md)

## Design

### T1 mounts by identity (R-33)

1. **Canary first.** `escape_linux.rs` adds a deterministic test and a racing
   test.
   - The deterministic test uses a `pre_exec` closure the test registers
     before the spawn. It runs in the child before procage's sequence,
     where it renames a planned component away and puts a link or another
     directory in its place.
   - It covers each mount kind: protect, a hidden directory, a hidden
     file, a data-class cover, a foreign-socket cover and a pin (a bind of
     a path over itself, such as `.git`). The binds of the spec are these
     pins: grants on Linux are Landlock rules, not mounts.
   - The racing test swaps a directory and a link from another thread
     during `PROCAGE_RACE_ATTEMPTS` spawns (10,000 in CI; 1,000 is the
     local default).
   - The deterministic outcome before the change is recorded in the
     quickstart.
2. **Plan.** Each `ChildMount` carries the planned object's `(dev, ino)`,
   taken with `lstat` in the parent: for the target, and for the bind
   source when it differs. Paths are canonical:
   - socket covers use the resolved path from `/proc/net/unix`;
   - `/dev/shm` is canonicalized.

   *Decision (implementation):* the declared mounts (protect, hide, pin)
   take their identity **when the cage is made** (`spawn::declare`), not
   per spawn. Reason: with per-spawn identity, a swap made between two
   spawns is simply re-planned onto the decoy, and the racing canary
   exposes the protected file (measured). Landlock rules bind inodes at
   cage creation too, so both layers now agree. Consequence: a protected
   or hidden object replaced after the cage was made (an atomic save)
   refuses later spawns with `MountMoved`; the caller makes a new cage.
   Covers, found at spawn, hold an `O_PATH` descriptor and take their
   identity from it, so the child tells a removed file from a moved one.
   A removed cover (no name left) is skipped whatever its old name leads
   to now (`ENOENT`, `ESTALE` or `ELOOP`: a socket removed and bound
   again at the same path is a new file, never covered); a cover still
   named elsewhere was moved and refuses the spawn. A cover the caller
   cannot reach (`EACCES`: a GitHub runner's root-only `/run/podman`) is
   skipped, as 0.4.0 did: the child is the same user with no capability
   over the host's files, so it cannot reach it either (found by CI run
   41628757579; `a_cover_the_caller_cannot_reach_does_not_fail_the_spawn`). A cover beneath a hidden directory is dropped from the
   plan: the empty tmpfs shadows it already.
3. **Child sequence.** Only system calls, on buffers prepared in the parent.
   - After `unshare` and the id maps, the one path-based mount call stays:
     `mount(NULL, "/", NULL, MS_REC|MS_PRIVATE)`, the propagation change of
     the root. It moves nothing.
   - Each target: `openat2(AT_FDCWD, target, O_PATH|O_CLOEXEC,
     RESOLVE_NO_SYMLINKS)`, then `fstat` and an identity check. A mismatch
     fails with `ESTALE`, a link with `ELOOP`. An optional cover whose
     path is gone (`ENOENT`) is skipped as before.
   - Bind: `open_tree(fd, "", OPEN_TREE_CLONE|AT_EMPTY_PATH[|AT_RECURSIVE])`,
     then `mount_setattr` on the detached tree (read-only, or sealed for
     `/dev/null`, recursive as the bind is), then `move_mount` onto the
     target descriptor.
   - Tmpfs: `fsopen("tmpfs")`, `fsconfig` (`mode`, `CMD_CREATE`),
     `fsmount` with the attributes, then `move_mount`.
   - The separate remount step and `locked_flags` go away: `mount_setattr`
     only sets flags, so locked ones stay.
4. **Probe.** `probe_userns` mounts its `/tmp` tmpfs with the same calls. A
   host without them is not T1 (fail closed: T2 by default, and
   `Unsupported::Tier` with the errno when T1 is asked for).
5. **Error.** When the child fails with `ELOOP` or `ESTALE` at the mount
   step, the parent walks the plan's paths and returns
   `SpawnError::MountMoved { path, link }`: the first planned path that
   now resolves through a link, or to another object. If none is found,
   the plain `Apply` error is returned.

### macOS spellings

6. **Refusal.** `canon::resolve_policy` and grant resolution check each
   allow target (`Read`, `Write`, `Exec` rules, `ipc.unix_sockets`, allow
   rules of the Seatbelt layer, bound grants). They call
   `pathconf(_PC_CASE_SENSITIVE)` on the longest existing prefix, and a
   case-sensitive volume returns `SpawnError::CaseSensitive { path }`.
   Denies are unchanged.

   *Decision (implementation):* a volume where `pathconf` has no answer
   is accepted, not refused. Refusing broke the tty allow of R-22
   (devfs answers `EINVAL`), and devfs names are fixed by the kernel, so
   the child cannot create a case variant there.
7. **Matrix.** `spelling_macos.rs`:
   - on the default volume: case and NFC/NFD variants of denies and
     allows, nested links, a missing leaf in another case, a firmlink path;
   - on a case-sensitive APFS image (`hdiutil`, no root): a deny covers
     the variants, and allow rules, a socket and a grant are refused;
   - an image that cannot be created fails the test.
   - The threat-model gate wants each class's canary in the platform's
     escape suite, so R-37 also has one in `escape_macos.rs`, which adds
     a Seatbelt-layer allow and a missing leaf to the refused allows.

### Records

8. **Threat model and docs.**
   - Two new classes in `THREAT_MODEL.md`: R-33, a planted link or rename
     during setup, mitigated; R-37, case variants of an allow on a
     case-sensitive volume, mitigated.
   - The canonicalisation claim in the docs lists exactly the matrix, and
     says Linux case-folding is untested.
   - Changelog Security entries for both, release 0.4.1.

## Constitution Check

| Principle | Check | Status |
|---|---|---|
| I | A moved mount or an inexact allow refuses the cage; there is no fallback to by-path mounts | PASS |
| II | New errors are typed `SpawnError` variants (non_exhaustive, additive) | PASS |
| III | Race canary on T1, spelling matrix on macOS lanes | PASS |
| IV | The child adds `openat2`, `fstat`, `open_tree`, `mount_setattr`, `fsopen`, `fsconfig`, `fsmount`, `move_mount` and `close`: system calls only, all in `sys` | PASS |
| V | This makes V's "setup never follows a link the child could have planted" hold for T1 mounts; the race canary is its evidence | PASS |
| VI | The T1 probe makes the new calls, so T1 is probed, never inferred from the kernel release | PASS |
| VII | No API break; 0.4.1 | PASS |

**Remaining gaps**: Linux case-folding directories are untested (no lane
has one; the docs say so). Hard links to protected files stay with spec
023. A link planted on macOS after canonicalisation is R-02/R-04, not this
spec.

Principle IV's multithreaded test: a T1 test spawns 1,000 times a policy
with every mount kind while other threads allocate and lock.

Spawn latency (SC-003) is measured with `just bench` on T1 in Docker
before and after.
