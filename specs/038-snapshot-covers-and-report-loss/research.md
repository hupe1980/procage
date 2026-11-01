# Research: Vanished snapshot covers and honest report loss

## T1 spawns and vanishing files

`foreign_sockets` lists every pathname socket in `/proc/net/unix` that
exists outside the allowed trees; `t1_covers` walks the writable trees for
data-class names. Both become mounts the child applies after `unshare`.
Between the scan and the child's `mount`, another program can remove the
file: `hide()` (parent, `stat`) or `mount()` (child) then fails with
`ENOENT`.

| Churn test (300 T1 spawns, a thread binding and removing a socket) | Result |
|---|---|
| Before | failed at spawn 3 (`cannot use …/s: No such file or directory`) |
| Child-side skip only | failed at spawn 275 (parent-side `stat` window) |
| Parent and child skip | 300 of 300, three runs |

A remount after a skipped bind would land on the mount that contains the
vanished path (for example making a whole tmpfs read-only), so it is
skipped with its bind.

## macOS report loss

Stress probe on macOS 26.6.2: 16 threads × 40 refused writes, each in its
own reporting cage, next to an independent `/usr/bin/log stream` with a
predicate on the targets.

| Denials | Seen by the independent stream | Missed by procage, record complete | of which the stream saw |
|---|---|---|---|
| 640 | 558 | 13 | 1 |

The system dropped about 13 % before any reader. Serial runs of a 19-test
suite missed none (8 of 8). One denial in 640 reached the independent
stream but not procage's record before its fence; kept as a known rare
case under load.
