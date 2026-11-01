# Research: 006-base-profile

All measurements: macOS 26.6.2 (25G83), 2026-10-30. Profiles were compiled
and applied with `sandbox-exec` (discovery only) under `(deny default)`.

## R1. What ordinary programs need

**Minimal base** (exec + read of the system code, read of `/`), and what failed:

| Program | Failure | Cause |
|---|---|---|
| `id -un` | printed `501` | no lookup of `com.apple.system.opendirectoryd.libinfo` |
| `date` | printed UTC | `/etc/localtime` points into `/private/var/db/timezone` |
| `sh` | could not start | `/private/var/select/sh` selects the shell |
| `uname` | failed | sysctl denied |
| `cat /dev/null` | denied | no `/dev` rule |
| Rust programs | abort at start | sysctl (page size) denied (found in 004) |

**Candidate V1** (the content of FR-002): every program of the set ran
correctly:

- `id -un` and `whoami` printed the user name;
- `date` printed CET;
- `uname -a`, `cat`, `sort`, `sed`, `awk`, `xxd` on `/dev/urandom`,
  `zsh -c`, `perl -e`, `tar --version` and `gzip -V` all worked.

`sh` and `bash` failed only on `getcwd`, because the working directory was
not granted. With it granted they work, and no ancestor metadata rule is
needed (`getcwd` gets the path from the descriptor).

**Refusals under V1**: `ls $HOME` and `stat $HOME/.zshrc` were refused.

## R2. Curated list or `system.sb`

- **Decision**: a curated list.
- **Rationale**:
  - `system.sb` (311 lines, "Apple System Private Interface… subject to
    change") is opaque to `explain` and changes between releases;
  - the curated list is small (about 15 rules) and every entry has a
    measured reason;
  - the program-set test on each CI lane catches a release that needs more.

## R3. Representation

- **IR**: `Base::{None (default), V1}` on `Policy`, with serde
  `"base": "v1"`. Construct `base-v1`.
- **Content**: `procage_policy::base` holds the content as constants, plus
  `macos_v1(tty) -> Vec<sbpl::Rule>` and `linux_v1(tty, handled) ->
  Vec<LandlockRule>`.
- **New SBPL filter**: `IpcPosixName` (`(ipc-posix-name "…")`), which
  compiles on 26.6.2.
- **Linux**: optional paths use a new `RuleTarget::PathIfExists`, so
  `/lib64` and `/lib32` may be absent.
- **Tty::Inherit** (macOS): `(allow file-read* file-write-data file-ioctl
  (literal "/dev/tty") (regex "^/dev/ttys[0-9]+$"))`. It lands in the allow
  block, before the hard-deny TIOCSTI deny.

## R4. Freezing

A test in `crates/procage-policy/tests/base.rs` pins:
- the exact SBPL lines base V1 adds (macOS, with and without `Tty::Inherit`);
- the exact Landlock rules (Linux, at ABI 6).

Changing V1 fails that test. The fix is a new variant, `V2`.
