# Implementation Plan: An IP network without Unix sockets

**Branch**: `048-ip-network` (local planning; commits on `main`) | **Date**: 2026-11-02 | **Spec**: [spec.md](spec.md)

## Design

1. **Policy.** `Network::Ip` (serde `ip`), `Network` `#[non_exhaustive]`;
   construct `NetIp` (`net-ip`).
2. **Linux lowering.** `Ip`: `socket()` refused except `AF_INET`,
   `AF_INET6` (new constant) and, with `ipc.unix_sockets`, `AF_UNIX`; no
   network namespace on T1; Landlock's network rights not handled (as
   `All`). `RESOLVE_UNIX` stays handled (dropped only for `All`). The socket
   classes count Unix sockets as off for `Ip`. `ipc.unix_sockets` with `Ip`
   on T1 below ABI 9: approximated from ABI 6 (abstract scope), unsupported
   below (no network namespace keeps abstract sockets in).
3. **macOS lowering.** `Ip`: `network-outbound (remote ip "*:*")`,
   `network-bind network-inbound (local ip "*:*")`, outbound to the
   resolver socket, `system-socket`.
4. **Fitting.** `Relaxation::answers(construct)`; `NoUnixSockets` answers
   `ipc-unix-sockets`, `hd-service-handoff` and `hd-container-engines`.
   Applied to a socket-class gap it needs `Network::All` or `Network::Ip`
   (several gaps), sets `Ip` and clears `ipc.unix_sockets`; any other
   network leaves the gap unanswered.
5. **Tests.** Policy crate: lowering of `Ip` on all targets, the seccomp
   rule, fitting a socket-class gap and refusing it under `Loopback`, the
   construct table helper. procage: R-34 canaries on macOS and Linux (TCP,
   UDP, listen, a name, Unix connects refused, `ipc.unix_sockets` allowed);
   T2 fitting with a fake session bus and engine in a runtime directory
   (`CageOptions::with_runtime_dir`).

## Constitution Check

| Principle | Check | Status |
|---|---|---|
| I | Exact on every tier; the T1-below-ABI-6 case is reported, not approximated silently | PASS |
| II | Relaxation named by the caller; unanswered gaps stay typed gaps | PASS |
| III | Spawn tests on macOS, T1 and T2 | PASS |
| VII | Breaking enum change in 0.4.0; `Network` made `non_exhaustive` | PASS |
