# Research: 010-violations

All measurements on macOS 26.6.2 (25G83), an administrator account,
2026-11-01, with `sandbox-exec -f` profiles in the scratchpad (deny default,
explicit denies, parameters), `/usr/bin/log stream --style ndjson`.

## R1 — Which denials are logged

- **Decision**: rely on the log for every denial of procage's deny-default
  profiles, explicit denies included.
- **Evidence**: a deny-default profile with `(deny file-read-data (literal
  "/private/etc/hosts"))` after an allow logged `Sandbox: cat(39287)
  deny(1) file-read-data /private/etc/hosts`, followed by the rule's message
  when it had one, and nothing after the target when it had none.
- **Answer to the earlier observation**: the "explicit denies not logged"
  observation came from an allow-default profile; procage never emits one.
  `OSLogStore` is not needed: `log stream` suffices and avoids Objective-C.

## R2 — Tagging each denial with the run and the rule

- **Decision**: `(deny default (with message (param M)))` and, for every
  explicit deny except the run-marker block, `(with message (string-append
  (param M) " <code>"))`, where `M` is the run-marker parameter and `<code>`
  names the rule kind (`hd:<class>`, `protect`, `hide`, `layer`).
- **Evidence**: `-D TAG=procage-param-B` produced
  `…/private/etc/hosts\nprocage-param-B hd`; the default produced
  `…\nprocage-param-A`.
- **Alternatives**: a static tag per cage (no per-run attribution; the
  architecture's first idea); attributing by pid (descendants' pids are
  unknown; grandchildren logged with their own pids, e.g. `bash(39308)`).

## R3 — Delivery, ordering, rate

| Test | Result |
|---|---|
| Ready (first line seen after start), `logger` ping | 0.118 s |
| Ready, `syslog(3)` ping from the caller's pid | 0.065–0.068 s |
| Denial, then fence (`logger`), 40 runs | 40/40 fence after the denial; fence lag median 2 ms, max 6 ms |
| 300 processes, one denial each, then `syslog` fence, 3 runs | 300/300 before the fence each time |
| One process, 5,000 distinct denials in 0.12 s | 5,001/5,001 delivered (incl. a first `f0`) |
| Same process, 1,000 repeats of one path | reported once; no "duplicate report" line within 1 s |

- **Superseded during implementation**: KF-M29 in its first form failed once
  in `just ci` on a loaded host (round 17: the `syslog` fence arrived after a
  run's first denial but before its second). A comparison over 650 rounds
  (150 idle, 500 with every CPU busy, load 74) found the `syslog` fence
  overtaken 4 times (within the same delivery batch, up to 14 ms) and a
  fence that is itself a kernel denial overtaken 0 times. Kernel and
  userspace messages reach logd on different paths.
- **Decision**: a fence is a denial. A forked child applies a fixed profile
  (`(deny default (with message "<prefix>fence"))`), is denied opening `/`,
  and exits; the monitor waits for that denial with the child's pid. The
  child runs `__mac_syscall`, `open` and `_exit` only. KF-M29 pins the
  ordering (20 rounds; 10/10 runs idle and 8/8 with every CPU busy).
- **Dedup**: documented as kernel behaviour (one report per process,
  operation and path).

## R4 — The helper's lifetime

- **Evidence**: a `log stream` started by a process that then exits
  (`os._exit`) was still running 2 s later; started under `/bin/sh -c
  '… & read _; kill $!'` with standard input a pipe from the process, none
  remained.
- **Decision**: `/bin/sh` script: start `/usr/bin/log` in the background,
  a subshell that reads the inherited pipe (explicitly redirected, since
  asynchronous lists get `/dev/null` otherwise) and kills it on EOF, and
  `wait` for `log`, so a failing `log` closes the stream (EOF) and the
  monitor sees it. Empty environment, absolute paths.

## R5 — Accounts and CI

- Measured: administrator account works. Not measured: non-administrator
  accounts (expected to refuse) and GitHub's macOS VMs (admin runner).
- **Decision**: a stream that does not answer the ready ping within 2 s, or
  ends, makes coverage `Unavailable(<log's stderr>)`; spawning continues.
  The account question stays open until the CI lane and a non-admin run measure it.

## R6 — Parsing

- **Decision**: `serde_json` (already in the lock file, MIT/Apache) parses
  each ndjson line; only `eventMessage` is used. The message is
  `Sandbox: <name>(<pid>) deny(<n>) <operation> <target>\n<tag>[ <code>]`.
  Parse from both ends: the last line is the tag (kernel-written after the
  target, so a target cannot replace it); the first line's prefix gives
  name, pid, operation; everything between is the target (it may contain
  newlines).
- **Alternative**: a hand-written field scanner — rejected: the target is
  attacker-chosen text inside the JSON.

## R7 — Linux

- Landlock denials reach only the audit subsystem (ABI 7+, privileged
  reader). seccomp user notification gives exact, unprivileged reports of
  seccomp denials (listener fd per filter tree; one listener per chain).
- **Decision**: feature 034-linux-violations. Here Linux returns coverage
  `NotObserved`.

## R8 — Prior art

- sandbox-runtime (macOS): watches the log for sandbox denials without a
  per-run tag or rule kind.
- Codex: infers sandbox denials from exit codes and stderr to offer
  escalation.
- Neither reports which rule denied an access; procage's rule codes do.
