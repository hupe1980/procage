# Research: Unix sockets under trees, and hiding on Linux T2

Measured in Docker Desktop Linux 7.0.14 (Landlock ABI 8), tier T1
container (seccomp and AppArmor unconfined), as uid 65534, with python3
servers and clients (session scratchpad `sock.sh`).

## R1 — Pathname sockets cross network namespaces

| Probe | Result |
|---|---|
| `/proc/net/unix` | lists `/tmp/outside.sock` and `@procage-abstract` |
| connect, host namespaces | both connected |
| `unshare -Urm`, `mount --bind /dev/null /tmp/outside.sock`, connect | refused, errno 111 (`ECONNREFUSED`); the path is now a character device |
| `unshare -Urn`, connect `@procage-abstract` | refused, 111 |
| `unshare -Urn`, connect `/tmp/outside.sock` | **connected** |

Decision: on T1 below ABI 9, mask every listening pathname socket outside
the allowed paths at spawn (the backend's existing file mask binds
`/dev/null` read-only over a non-directory); abstract sockets are isolated
by the cage's network namespace (and by Landlock's abstract scope, ABI ≥ 6,
as defence in depth). Sockets bound later, or bound in another network
namespace but visible in the file system, are not in the listing: an
approximation. T2 has no mount namespace: refused below ABI 9.

## R2 — ABI 9

`src/linux/mod.rs` clamps the ABI to `BACKEND_MAX_ABI = 8`; ABI 9's
`RESOLVE_UNIX` is not used by the backend (unverified on a kernel). The
lowering keeps the ABI-9 branch (rules with `RESOLVE_UNIX` on the paths),
checked by lowering tests only.

## R3 — macOS

The consumer harness's workaround allowed `network-outbound`,
`network-bind` and `network-inbound` with `(subpath …)` filters on the
writable trees; its socket tests passed, and the outside-socket and
container-socket tests stayed refused. A path filter on these operations
matches Unix-socket addresses only. Decision: the same rules from
`ipc.unix_sockets`, plus `system-socket`; and, for hidden paths, a deny of
the same operations in the deny-within-allow block.

## R4 — Piecewise grants (T2)

The consumer harness's builtin engine (`readable()` in its sandbox module) grants
every entry along the way to a hidden path except the hidden one.
Properties: later entries on the way are denied (over-restriction); the
directories on the way get no rule, so they cannot be listed; `stat` is not
controlled by Landlock, so the hidden path's metadata stays visible. A
symbolic-link sibling must not be granted (the rule would follow it and
could land inside the hidden path). Inside a writable tree it cannot work:
`MAKE_*`/`REMOVE_*` are checked on the parent directory and a rule grants
them beneath, so creating files in the tree's root would also allow it
inside the hidden directory.

Decision: T2 `Hide` → approximated when no write rule (path or raw Landlock)
is an ancestor of, or equal to, the hidden path; otherwise refused. The
backend expands every rule that is a strict ancestor of a hidden path,
drops rules at or under one, skips symlinks, counts entries against the walk
limit, and refuses a write grant bound around a hidden path. The secrets
class (`hide`) on T2: reached only by read rules → approximated, its paths
that exist at spawn join the hidden set; reached by a write rule → refused.

## R5 — Naming

The 026 option `accept_spawn_masks` accepted the T1 masks of the three
data-driven classes. The approximations of this feature are of the same
kind (they depend on the file system as read at spawn) but not all are
masks. Rename (unreleased API): `accept_spawn_snapshot`, accepting
`hd-secrets`, `hd-trust-handoff`, `hd-persistence`, `fs-hide`,
`ipc-unix-sockets`. Refusals of these constructs name the option.
