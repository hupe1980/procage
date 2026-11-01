# Research: 036-base-v3

## R1 — What everyday commands are denied under V2 (macOS 26.6.2)

A scratch harness ran 22 commands (true, ls, cat, clang, git, make,
python3, ruby, perl, node, jq, curl, cargo, rustc, swift, xcrun, sed/awk/grep,
tar, env, date/uname/id/whoami, zsh, bash) under base V2 with a writable
workspace and violations on. All succeeded (cargo/rustc: not on a granted
path, 127). 43 distinct denials; by volume:

| Reports | Denial | Kind |
|---|---|---|
| 5,208 | mach-lookup com.apple.diagnosticd | not granted (os_log/activity) |
| 4,920 | mach-lookup com.apple.lsd.modifydb | hard-deny service handoff (xcodebuild retry loop) |
| 148 | file-ioctl /dev/dtracehelper | not granted (dyld DTrace registration) |
| 84 | mach-lookup com.apple.bsd.dirhelper | not granted (V2 leaves it out; TMPDIR is set) |
| 74 | mach-lookup com.apple.logd | not granted (os_log) |
| 56 | mach-lookup com.apple.system.opendirectoryd.membership | not granted |
| 37 | file-read-data /dev/tty | not granted (shells probing; Tty::None) |
| rest | xcodebuild reading preferences, caches, CoreSimulator; distributed notifications | not granted |

**Decision**: quiet (no-report) denies for the five every-process probes
(logd, diagnosticd, dtracehelper ioctl, dirhelper, membership) and /dev/tty
reads and writes. The xcodebuild-specific reads stay reported (they name real
files of the user); the LaunchServices lookup stays reported (hard-deny) and
is merged per process.

## R2 — `(with no-report)` semantics

`sandbox-exec` with a deny-default profile carrying a message: a
`(deny file-read-data (literal "/private/etc/hosts") (with no-report))`
refused the read (exit 1) and logged nothing; the same for `/etc/shells`
followed by `(allow file-read-data (literal "/private/etc/shells"))` let it
through (exit 0); the default deny of `~/.zshrc` was logged with the
message. **Decision**: quiet denies first, after `(deny default)`; KF-M30
pins both facts.

## R3 — Merging

Kernel dedup collapses some identical denials but not mach-lookup retries
(4,920 kept). **Decision**: the record merges equal (pid, process,
operation, target, kind) into one entry with `repeats` (saturating).
