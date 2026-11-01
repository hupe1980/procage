# Research: Base profile V2

Host: macOS 26.6.2 (25G83), Xcode 27.2 selected (`xcode-select -p` →
`/Applications/Xcode.app/Contents/Developer`), Homebrew under
`/opt/homebrew`. Harness: `research-harness.rs.txt` (a scratch binary
against procage): 27 workloads in a policy with the base, a writable
workspace, the `tmpdir` grant, fork, exec anywhere, no network, env
`PATH HOME LANG USER TERM`; denials from `/usr/bin/log stream --predicate
'sender == "Sandbox"'` (note: `log show` did not return these kernel
messages; a shell function named `log` shadowed the binary).

## R1 — V1 on developer tools

| Workload | V1 | Cause |
|---|---|---|
| git, clang, make, xcrun, swift, python3 (Apple shims) | fail | `xcode-select`: `/var/db/xcode_select_link` metadata denied; developer dir unreadable |
| ruby | fail | `/Library/Ruby` (gems) |
| node, npm, rg, Homebrew python | cannot run | `/opt/homebrew` not readable |
| perl, curl, openssl (system), ssh, find, grep, tar, zip, mktemp, sw_vers, locale, jq | ok | — |

## R2 — dirhelper is harmful

| Services added | `getconf DARWIN_USER_TEMP_DIR` in the cage | mktemp | shims |
|---|---|---|---|
| none (V1) | the private `TMPDIR` (libSystem falls back to `$TMPDIR`) | ok | (fail on R1) |
| dirhelper | `/var/folders/<x>/<y>/T/` (shared) | fails: write refused | fail: `couldn't create cache file …/T/xcrun_db-…` (exit 69) |
| membership only | shared, as above | fails | fail |

Writing the shared directory must stay refused (xcrun's `xcrun_db` there is
read by unsandboxed `xcrun`: poisoning it redirects tool lookups).
Decision: no `dirhelper`, no `membership`. The consumer's symptom (a
second per `git`) was the shim falling back to `xcodebuild` on every call;
with V2 and a persistent `TMPDIR` the cache makes later calls fast (R4).

Research trap: an SBPL rule with an empty filter list allows the operation
everywhere. An experiment with an empty service list produced
`(allow mach-lookup)` and briefly looked like "dirhelper not needed".
Decision: a test that no base rule is unfiltered (except V1's
`sysctl-read`).

## R3 — The additions, each from a denial

| Denial (V1) | Addition | Kind |
|---|---|---|
| `file-read-metadata /private/var/db/xcode_select_link` | read the link | data |
| developer directory (`/Applications/Xcode.app/Contents/Developer`) | read/exec/map `^/Applications/Xcode[^/]*\.app/Contents/`, `/Library/Developer/CommandLineTools` | code |
| "You have not agreed to the Xcode license agreements" (`/Library/Preferences/com.apple.dt.Xcode.plist`) | read that file | data |
| `/Library/Ruby` | read | code/data |
| `/Library/Perl/5.34/AppendToPath` | read `/Library/Perl` | data |
| `/opt/homebrew/bin/python3` metadata | read/exec/map Homebrew and `/usr/local` code dirs (`bin sbin lib libexec opt Cellar Caskroom share include Frameworks`) | code |
| `node: OpenSSL configuration error` (`/opt/homebrew/etc/openssl@4/openssl.cnf`) | read OpenSSL's `openssl.cnf`, `cert.pem`, `certs/` and `ca-certificates/cert.pem` under `etc` | public data |
| `/dev/autofs_nowait` | read | device |
| `~/.CFUserTextEncoding` | read (each home, a few bytes) | personal, harmless |
| `/Library/Preferences/.GlobalPreferences.plist` | read | system data |
| metadata of `/Users`, the home, `/Applications`, `/opt`, … | metadata | path lookup |

Kept denied: `logd`, `diagnosticd`, `system.logger` (log writing),
`analyticsd`, DTrace helper ioctl (kernel parser), `process-info` of
others, LaunchServices (`lsd.*`, handoff class), `CommandLineTools.installondemand`
(an unsandboxed installer), DiskArbitration, FSEvents, home preferences,
`~/Library/Caches`, `/dev/tty` (Tty::None), `system-fsctl`.

## R4 — Result with V2

All installed workloads run (27/27 except `cargo`, not on PATH). Timing:
shims 0.6–2.4 s on a cold `TMPDIR` (xcrun runs `xcodebuild` once), 0.01 s
warm (`git --version` ×3 with a reused `TMPDIR`: 1.11 s, 0.01 s, 0.01 s;
uncaged 0.01 s). `mktemp` and `getconf DARWIN_USER_TEMP_DIR` give the
private `TMPDIR`. `git` needs `GIT_CONFIG_GLOBAL` (or a `HOME` it can read)
because `EPERM` on `~/.gitconfig` is fatal for git.

## R5 — Linux

Docker T1 and T2 with Linux V1: git, python3 (incl. ssl, sqlite3,
multiprocessing), cc build, make, perl, curl, tar, mktemp, cargo, rustc
all run once `TMPDIR` (tmpdir grant) and `RUSTUP_HOME`/`CARGO_HOME` are set;
`ps` needs `/proc` (not granted, R-25); git's background maintenance prints
`setsid failed` (the lifetime lock of feature 024). Decision: Linux V2 = V1.
