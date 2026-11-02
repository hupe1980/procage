# Feature Specification: An IP network without Unix sockets

**Feature Branch**: `048-ip-network` (planning directory; commits land on `main`)

**Created**: 2026-11-02

**Status**: Implemented (2026-11-02)

**Input**: A harness reports, against 0.3.2, that on Linux tier T2 (Ubuntu
as shipped, user namespaces restricted) no command with `Network::All`
starts on a desktop: the D-Bus session bus and the Docker socket are
`hd-service-handoff` and `hd-container-engines` gaps, and only waiving the
classes answers them. It asks that `Relax::no_unix_sockets()` answer them by
refusing Unix sockets, as the network-off filter does.

## Context

With the network off or through the proxy, seccomp refuses Unix sockets, so
the socket classes hold on every tier without looking for sockets. With
`Network::All` every Unix socket is reachable: on T1 the cage covers the
sockets it finds, on T2 it cannot, at any Landlock ABI (procage handles
Landlock's Unix-socket right only with the network off). A relaxation must
change the policy, and the policy cannot say "the network, but no Unix
sockets".

## Clarifications

### Session 2026-11-02

- Q: The shape? → A: A new `Network::Ip`: connect to and listen on any IP
  address; Unix sockets only at `ipc.unix_sockets`, handled as with the
  network off. `Network` becomes `#[non_exhaustive]`. Breaking: 0.4.0.
- Q: Linux? → A: seccomp allows `socket()` for `AF_INET` and `AF_INET6`
  only, plus `AF_UNIX` with `ipc.unix_sockets`; no network namespace, as
  with `All`. The socket classes need no search unless `ipc.unix_sockets`
  is set.
- Q: macOS? → A: Seatbelt allows outbound to remote IP addresses and bind
  and inbound on local ones, plus the system resolver's socket
  (`/private/var/run/mDNSResponder`): without it no name resolves.
- Q: The relaxation? → A: `Relaxation::NoUnixSockets` also answers
  unsupported `hd-service-handoff` and `hd-container-engines` gaps of a
  policy with `Network::All`: the network becomes `Network::Ip` and
  `ipc.unix_sockets` is cleared. `Relaxation::answers(construct)` says which
  gaps a relaxation answers. The lift stays tier T1.
- Q: `ipc.unix_sockets` with `Network::Ip` on T1 below ABI 9? → A: Without
  a network namespace, abstract sockets are kept out only by Landlock's
  scope (ABI 6): approximated from ABI 6, unsupported below.

## User Scenarios & Testing

### User Story 1 - Networked commands on T2 next to D-Bus and Docker (Priority: P1)

**Acceptance Scenarios**:

1. **Given** T2, `Network::All` and a reachable session bus or engine
   socket, **When** fitting with `Relax::no_unix_sockets()`, **Then** the
   cage is made with `Network::Ip`, each gap is reported relaxed with the
   T1 lift, and the child reaches a TCP listener but connecting to any Unix
   socket (pathname or abstract) fails.
2. **Given** the same without the relaxation, **When** fitting, **Then** it
   fails with the gaps, as before.

### User Story 2 - The IP network as a setting (Priority: P1)

**Acceptance Scenarios**:

1. **Given** `Network::Ip` on macOS, T1 and T2, **When** the child connects
   over TCP and UDP, listens on a TCP port and resolves a name, **Then**
   each works; creating a Unix socket (Linux) or connecting to one (macOS)
   fails, except at `ipc.unix_sockets`.
2. **Given** `Network::Ip` and no `ipc.unix_sockets` on T2, **When** a bus
   or engine socket exists, **Then** the cage is made without a gap.
3. **Given** `Network::Ip` and `ipc.unix_sockets` on T2 below ABI 9,
   **When** lowering, **Then** `ipc-unix-sockets` is unsupported, as with
   the network off.

### Edge Cases

- Netlink and vsock stay refused by `socket-families`; with that class
  waived, `Network::Ip` still refuses them.
- Socket pairs are not routes and stay available.
- A Unix socket the caller hands over with `spawn_with_fds` stays usable.

## Requirements

- **FR-001**: `Network::Ip` MUST lower as above on macOS, T1 and T2, with
  the construct `net-ip` (exact on all three).
- **FR-002**: `Relax::no_unix_sockets()` MUST answer the socket classes'
  unsupported gaps under `Network::All` by switching to `Network::Ip`, and
  MUST NOT answer them under any other network.
- **FR-003**: The policies, fitting, hard-deny and Linux guides, the
  lowering table, the threat model and the changelog MUST describe it.

<!-- threatspec:begin -->
### Security Requirements *(managed by ThreatSpec — edit threat-model.yaml)*

- **SR-001** (P1): Under Network::Ip no Unix socket outside ipc.unix_sockets MUST be reachable on macOS, T1 or T2, while IP connects, listening and name resolution MUST work.
  - Mitigates: `threat.abstract-socket-without-namespace`, `threat.other-socket-family`, `threat.service-socket-under-ip` via `mitigation.ip-families-only`
  - Given Network::Ip without ipc.unix_sockets, when the child connects over TCP, listens, resolves a name and connects to a Unix socket, then the IP operations succeed and the Unix connect fails on every tier
  - Given Network::Ip with ipc.unix_sockets naming a socket, when the child connects to it, then it connects (T1 and T2 from ABI 9, macOS)
- **SR-002** (P1): Relax::no_unix_sockets MUST answer hd-service-handoff and hd-container-engines gaps only under Network::All, by switching the policy to Network::Ip; under any other network the gap MUST stay.
  - Mitigates: `threat.relaxation-changes-network` via `mitigation.relax-to-ip`
  - Given T2, Network::All and a session bus socket in a runtime directory, when fitting with no_unix_sockets, then the cage is made with Network::Ip, the gap is reported relaxed with the T1 lift, and the child cannot connect to the bus
  - Given a socket-class gap and a Loopback network, when applying no_unix_sockets, then the gap is returned unanswered and the policy is unchanged
- **SR-003** (P1): On Linux, Network::Ip MUST refuse every socket family but AF_INET, AF_INET6 and, with ipc.unix_sockets, AF_UNIX; ipc.unix_sockets with Network::Ip on T1 below ABI 6 MUST be unsupported.
  - Mitigates: `threat.abstract-socket-without-namespace`, `threat.other-socket-family`, `threat.service-socket-under-ip` via `mitigation.ip-families-only`
  - Given Network::Ip lowered for T1 and T2, when the plan is built, then seccomp refuses socket() except AF_INET and AF_INET6 (and AF_UNIX with ipc.unix_sockets), even with socket-families waived
  - Given Network::Ip with ipc.unix_sockets on T1 at ABI 5, when lowering, then ipc-unix-sockets is an unsupported gap
<!-- threatspec:end -->

## Success Criteria

- **SC-001**: On T2 with a session bus present, a fitted networked command
  runs and reaches the network; the bus is unreachable.
