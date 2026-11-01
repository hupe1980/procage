# Research: service sockets

All measurements 2026-11-01. macOS 26.6.2 (25G83), Apple M4 Pro, from a
terminal outside any sandbox; profiles applied with `sandbox-exec -p` (inline
profiles, not named ones).

## R1 — A path deny on `network-outbound` refuses a Unix connect on macOS

A listener at `<dir>/home/u/.docker/run/docker.sock`, a symbolic link to it,
and a connect from a child under `(allow default)` plus one deny:

| Deny | direct | via symbolic link | other case spelling |
|---|---|---|---|
| none | connected | connected | connected |
| `(regex #"^<dir>/home/[^/]+/\.docker/run/docker\.sock$")` | EPERM | EPERM | EPERM |
| case-folded regex | EPERM | EPERM | EPERM |
| `(literal "<dir>/home/u/.docker/run/docker.sock")` | EPERM | EPERM | EPERM |

- **Decision**: deny `network-outbound` with the case-folded patterns of the
  class, like the other data classes.
- **Rationale**: Seatbelt matches the resolved socket, so `/var/run/docker.sock`
  (a link into the home on Docker Desktop) and other spellings are covered by
  the home pattern.

## R2 — Hard links to a denied socket on macOS

Unsandboxed, `link()` to a socket succeeds. Under the deny of R1, `ln` of the
denied socket into a writable directory fails with EPERM, so the route of a
second name made inside the cage is closed. The canary re-checks it under
procage's own deny-default profile.

## R3 — Linux: what can refuse a Unix connect

- Landlock below ABI 9 does not mediate pathname Unix connects; ABI 9's
  `RESOLVE_UNIX` is an allowlist and cannot express "everything except these"
  inside an allowed tree. The backend stops at ABI 8.
- seccomp cannot inspect the path argument of `connect`.
- Tier T1 can cover a socket file with an inaccessible mount (the mechanism
  already used for foreign sockets); a connect to the covered path then fails.
  A covered directory makes sockets bound in it later unreachable too.
- Abstract sockets have no file; Landlock ABI 6's abstract-socket scope
  refuses connects to abstract sockets outside the domain. With its own
  network namespace (T1, network off) the child cannot see the host's
  abstract sockets at all.
- **Decision**: discovery at cage creation and at each spawn; T1 covers, T2
  gaps; abstract scope when an abstract bus exists.
- **Alternative rejected**: always a gap on Linux with the network on —
  containers (Docker's default tier T2) usually have no service socket, and
  the gap would carry no information there.

## R4 — The socket lists

Sources: systemd's and D-Bus's documented paths, the engines' documentation.

| Class | Linux | macOS |
|---|---|---|
| service-handoff | `/run/dbus/system_bus_socket`; `/run/systemd/private`; runtime dir: `bus`, `systemd/private`; directories: `/run/dbus`, runtime `systemd`; abstract prefix `/tmp/dbus-` | (Mach services, unchanged) |
| container-engines | `/run/docker.sock`, `/run/podman/podman.sock`, `/run/containerd/containerd.sock`, `/run/buildkit/buildkitd.sock`, `/var/lib/incus/unix.socket`, `/var/lib/lxd/unix.socket`, `/var/snap/lxd/common/lxd/unix.socket`; runtime dir: `docker.sock`, `podman/podman.sock`, `containerd-rootless/api.sock`; directories: `/run/podman`, `/run/containerd`, runtime `podman` | home: `.docker/run/docker.sock`, `.colima/*/docker.sock`, `.orbstack/run/docker.sock`, `.lima/*/sock/docker.sock`, `.rd/docker.sock`, `.local/share/containers/podman/machine/**/*.sock`; system: `/private/var/run/docker.sock` |

`/var/run` is a link to `/run` on current distributions; paths are resolved
before covering, so both spellings meet the same cover.
