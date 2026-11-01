# Research: Older Linux kernels

## R1 — Truncation below ABI 3

- **Measured** 2026-11-01, Docker Desktop, Linux 7.0.14-linuxkit (aarch64,
  ABI 8), uid 65534, a C probe that handles only one ABI's rights, `/`
  readable (execute, read file, read dir), `/tmp/w` writable:

  | Route on a file outside `/tmp/w` | ABI 1 | ABI 2 | ABI 3 |
  |---|---|---|---|
  | `truncate(path, 0)` | truncated | truncated | `EACCES` |
  | `open(O_RDONLY \| O_TRUNC)` | truncated | truncated | `EACCES` |
  | `open(3 \| O_TRUNC)` | truncated | truncated | `EACCES` |
  | `open(O_WRONLY \| O_TRUNC)` | `EACCES` | `EACCES` | `EACCES` |

- Landlock's documentation: truncation "could not be denied before the
  third Landlock ABI, so it is always allowed when using a kernel that only
  supports the first or second ABI". The `open` cases follow from Landlock's
  open hook checking the file mode (`f_mode`), which `O_TRUNC` does not
  change, while the VFS truncates with only the DAC write check.
- **Decision**: below ABI 3 add seccomp denies for `truncate` (`EPERM`),
  `open`/`openat` with `O_TRUNC` and an access mode of 0 or 3 (`EPERM`), and
  `openat2` (`ENOSYS`; its flags sit in a structure seccomp cannot read, and
  glibc and musl never use it for `open`). `ftruncate` needs a descriptor
  opened for writing, which Landlock already checks; `creat` is
  `O_WRONLY`; `io_uring` is a hard-deny syscall; `open_by_handle_at` needs
  `CAP_DAC_READ_SEARCH`, which the child never holds. `truncate64` and
  `socketcall` exist only for 32-bit calls, which the filter kills.
- **Alternatives**: read-only mounts for everything outside the writable
  paths (T1 only, not T2, and much larger plans); refusing ABI 1–2 (Debian
  12 and Ubuntu 22.04 lose the sandbox); a capability gap (an attacker gains
  nothing from an opt-in choice, but callers would have to opt in to a
  refusal, which is backwards).

## R2 — T2's minimum

- T2 picked ABI 4 for TCP port rules (research of 2026-10-27). With the
  network off, T2 denies `socket()` for every family but `AF_UNIX`, so
  the TCP rules repeat the seccomp deny. Loopback and proxy are
  gaps on T2 at any ABI. **Decision**: minimum 1. **Limit**: an IP socket
  the caller passes in can connect below ABI 4 (documented).

## R3 — Signals below ABI 6

- `SelfAndChildren` is a gap below ABI 6 on both tiers. A user namespace does
  not change the kill permission check (it compares kernel uids), and a PID
  namespace is not implemented (needs a reaper and a fresh `/proc`).
  Measured during this research: none; the check is by kernel source
  (`kill_ok_by_cred`) and asserted by the `SameUser` caged test.
- **Decision**: `Signals::SameUser`, exact everywhere, never chosen by
  procage. A harness that gets the gap may switch to it and tell its user.
- **Alternatives**: allow signals only to the process group (`kill(0)`,
  `kill(-pgid)`): breaks `kill $pid`, which shells, `timeout` and test
  runners use; an approximation for `SelfAndChildren`: it is not close.

## R4 — ABI cap

- **Decision**: `CageOptions::landlock_abi: Option<u8>`; effective ABI =
  `min(kernel, cap, BACKEND_MAX_ABI)`; a cap below the tier's minimum gives
  `Unsupported::Landlock { abi, needed }`. One value drives the tier check,
  the lowering and the Landlock ruleset.
- **Faithfulness**: a kernel enforces only the rights a ruleset handles, so
  handling an older ABI's rights reproduces that ABI's enforcement for
  rights; cross-directory renames stay refused (procage never grants
  `REFER`, and an ABI 1 kernel refuses them anyway). Scopes, network and
  ioctl rights follow the same rule. Not reproduced: kernel bugs fixed by
  errata.
- **Alternative**: an environment variable: rejected, it would let any
  process that sets the environment weaken the sandbox.

## R5 — Kernels in the field

| Landlock ABI | Linux | Examples (Landlock enabled by default) |
|---|---|---|
| 1 | 5.13 | Ubuntu 22.04 GA (5.15) |
| 2 | 5.19 | Debian 12 (6.1) |
| 3 | 6.2 | Ubuntu 23.10 (6.5), Ubuntu 22.04 HWE (6.5) |
| 4 | 6.7 | Ubuntu 24.04 GA (6.8) |
| 5 | 6.10 | RHEL 9.6 (backport) |
| 6 | 6.12 | Debian 13, RHEL 10 |
| 7 | 6.15 | GitHub `ubuntu-24.04` (6.17) |
| 8 | 7.0 | Ubuntu 26.04, Docker Desktop 7.0 |

From the Linux research of 2026-10-27; probe, never infer from `uname`
(distributions backport).
