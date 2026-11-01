# Feature Specification: Egress proxy with a domain allowlist

**Feature Branch**: `016-proxy` (planning directory; commits land on `main`)

**Created**: 2026-11-01

**Status**: Draft

**Input**: Agents need the network for package registries and APIs, but "network on" also means exfiltration to anywhere. Every leading agent sandbox now offers egress through a proxy with a domain allowlist. procage 0.1.0 can confine a macOS child to loopback ports (`Network::Proxy`) but ships no proxy, and on Linux loopback and proxy networking are capability gaps on both tiers.

## Context

A proxy-only cage has two halves:

1. **The cage**: the child can reach nothing but the proxy's ports. macOS
   lowers `Network::Proxy` exactly (outbound to localhost ports only). On
   Linux, Landlock port rules are **not** a sufficient boundary: TCP Fast Open
   connects without the hook Landlock checks (reported 2026-06 for every
   kernel with Landlock network rules) and MPTCP is out of their scope. So on
   Linux the boundary is a network namespace (tier T1) in which the only
   reachable endpoint is the proxy's listener, provided by the parent; tier T2
   has no namespace and stays a gap.
2. **The proxy**: HTTP `CONNECT` and SOCKS5, deciding by host name against an
   allowlist, then connecting out itself.

Known failure modes of such proxies, all seen in agent sandboxes in 2025–2026:
an empty allowlist that allowed everything (CVE-2025-66479); a host name read
differently by the check and by the resolver (a NUL byte in SOCKS5, fixed
2026-03); DNS answers pointing at private addresses (rebinding); IP literals
bypassing a domain list.

## Clarifications

### Session 2026-11-01

- Q: Separate crate? → A: Yes, `procage-proxy`: portable, no `unsafe`, usable
  without a cage; procage depends on it only behind a feature.
- Q: Where does the proxy run? → A: In the caller's process (a thread or a
  task); no helper binary.
- Q: TLS interception or credential injection? → A: Never. The proxy sees
  host names (CONNECT, SOCKS5, plain-HTTP absolute URIs), not content.
- Q: IP literals? → A: Refused unless an address range is allowlisted
  explicitly; private, loopback, link-local and metadata addresses are
  refused after resolution unless allowlisted explicitly.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Only allowed hosts are reachable (Priority: P1)

A harness allows `crates.io`, `*.npmjs.org` and `api.example.com`. A caged
`cargo build` works; `curl https://attacker.example` fails and is reported.

**Why this priority**: it closes the network gap every competitor has
closed, and makes "network on" safe enough for agents.

**Independent Test**: On macOS and Linux T1, a caged child connects through
the proxy to an allowed local test host and is refused for a non-allowed one;
direct connections (TCP, UDP, TCP Fast Open, MPTCP, raw IP) all fail.

**Acceptance Scenarios**:

1. **Given** an allowed host, **When** the child connects through the proxy,
   **Then** the connection succeeds.
2. **Given** a host not on the list, **Then** the proxy refuses it and the
   run's violations name the host.
3. **Given** any direct connection attempt, **Then** it fails on every tier
   that supports the proxy; on T2 the cage reports a gap instead.

---

### User Story 2 - The parser cannot be fooled (Priority: P1)

**Independent Test**: A fuzzed and table-driven suite of host spellings (NUL
bytes, trailing dots, mixed case, punycode and Unicode, percent-encoding, IP
literals in every notation, userinfo, ports) — the allow decision and the
host actually connected to are always the same canonical host.

**Acceptance Scenarios**:

1. **Given** `allowed.com\0.evil.com` in a SOCKS5 request, **Then** refused.
2. **Given** `ALLOWED.COM.` **Then** treated as `allowed.com`.
3. **Given** an allowed name resolving to `127.0.0.1` or `169.254.169.254`,
   **Then** refused unless that range was allowlisted.

---

### User Story 3 - Misconfiguration fails closed (Priority: P1)

**Acceptance Scenarios**:

1. **Given** an empty allowlist, **When** the proxy is built, **Then**
   construction fails.
2. **Given** the proxy stopped, **When** the child connects, **Then** it
   fails; nothing falls back to a direct connection.

### Edge Cases

- Long-lived connections when a run ends: closed with the run.
- Programs that ignore proxy variables: they fail (no direct route), and the
  denial is visible.
- IPv6-only hosts; DNS over the proxy for SOCKS5 with domain names.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: `procage-proxy` MUST serve HTTP `CONNECT`, plain-HTTP absolute
  URIs and SOCKS5 (domain-name and, when allowlisted, address requests).
- **FR-002**: One canonical host parser MUST produce the value that is both
  checked against the allowlist and used to connect.
- **FR-003**: Construction MUST fail on an empty allowlist; there is no
  "allow all" mode.
- **FR-004**: After resolution, the proxy MUST refuse private, loopback,
  link-local and cloud-metadata addresses unless allowlisted, and MUST connect
  to the address it checked.
- **FR-005**: Refusals MUST be reported as violations of the run that made
  the request.
- **FR-006**: On macOS a proxy-only cage MUST allow outbound connections to
  the proxy's ports only. On Linux T1 the child MUST run in a network
  namespace whose only reachable endpoint is the proxy listener provided by
  the parent; Landlock port rules MAY add a second layer but MUST NOT be the
  only boundary. On T2 proxy-only MUST stay a capability gap.
- **FR-007**: The proxy MUST NOT terminate TLS or alter payloads.
- **FR-008**: The threat model MUST gain the escape class for allowlist
  parser differentials, with the parser suite as evidence, and canaries for
  direct egress (including TCP Fast Open and MPTCP) on every proxy tier.

### Key Entities

- **Allowlist**: exact hosts, wildcard suffixes, optional ports, optional
  address ranges.
- **Proxy**: listener(s), allowlist, the runs it serves.

<!-- threatspec:begin -->
### Security Requirements *(managed by ThreatSpec — edit threat-model.yaml)*

- **SR-001** (P1): The proxy MUST derive one canonical host per request and use that same value for the allowlist check and the connect; it MUST refuse hosts with NUL or control bytes, percent-encoding, userinfo or invalid labels, and a plain-HTTP request whose Host header differs from its URI host.
  - Mitigates: `threat.parser-differential` via `mitigation.one-canonical-host`
  - Given allowed.com on the list and the SOCKS5 host allowed.com\0.evil.com, when the child requests it, then the proxy refuses it and opens no connection
  - Given allowed.com on the list, when the child requests ALLOWED.COM. through CONNECT, then it is treated as allowed.com and connects there
  - Given the table-driven spelling suite and the fuzz target, when they run in CI, then for every input the checked host equals the host connected to, with zero disagreements
- **SR-002** (P1): The proxy MUST parse every IP literal notation to one address and MUST refuse a literal unless an explicitly allowlisted address range contains that address.
  - Mitigates: `threat.ip-literal-bypass` via `mitigation.literal-as-address`
  - Given a domain-only allowlist, when the child requests 2130706433, 0x7f.1, 017700000001, [::ffff:127.0.0.1] and 127.1, then every request is refused
  - Given an allowlisted range 192.0.2.0/24, when the child requests 192.0.2.10 in decimal and dotted form, then both connect to 192.0.2.10
- **SR-003** (P1): The proxy MUST resolve an allowed name once, MUST refuse loopback, private, link-local, unspecified and metadata addresses (also in IPv4-mapped and translated IPv6 forms) unless allowlisted, and MUST connect only to an address it checked.
  - Mitigates: `threat.dns-exfil`, `threat.dns-rebinding` via `mitigation.check-resolved-connect-checked`
  - Given an allowed name resolving to 127.0.0.1, 169.254.169.254 or ::ffff:10.0.0.1, when the child requests it, then the proxy refuses it and the violation names the host and the address
  - Given a test resolver answering a public address first and 127.0.0.1 on any later query, when the child requests the name, then the proxy connects to the first, checked address and issues no second query
- **SR-004** (P2): The proxy MUST NOT send a DNS query for a name the allowlist refuses.
  - Mitigates: `threat.dns-exfil`, `threat.dns-rebinding` via `mitigation.check-resolved-connect-checked`
  - Given a counting test resolver, when the child requests a host not on the list, then the request is refused and the resolver saw no query
- **SR-005** (P1): Building a proxy MUST fail on an empty allowlist, a bare wildcard or a wildcard whose suffix is a single label; there MUST be no allow-all mode.
  - Mitigates: `threat.allowlist-fail-open` via `mitigation.no-allow-all`
  - Given an empty allowlist, '*' or '*.com', when the proxy is built, then construction returns a typed error
- **SR-006** (P1): When the proxy is stopped or was never started, a connection from a proxy-only child MUST fail; no code path MAY fall back to a direct connection.
  - Mitigates: `threat.direct-egress`, `threat.proxy-down-fallback` via `mitigation.kernel-boundary`
  - Given a proxy-only cage on macOS and Linux T1 whose proxy has been stopped, when the child connects to the proxy and to an allowed host directly, then both fail
- **SR-007** (P1): A proxy-only cage MUST block every direct route on macOS and Linux T1 by a kernel boundary (macOS outbound to the proxy ports only; on T1 a network namespace whose only endpoint is the proxy listener); Landlock port rules MUST NOT be the only boundary.
  - Mitigates: `threat.direct-egress`, `threat.proxy-down-fallback` via `mitigation.kernel-boundary`
  - Given a proxy-only cage on macOS and on Linux T1, when the child tries direct TCP, UDP, TCP Fast Open, MPTCP, raw IP, IPv6, a DNS query and another loopback port, then every attempt fails, one escape-suite canary per route
- **SR-008** (P1): On Linux T2 building a proxy-only cage MUST return a CapabilityGap; it MUST NOT be lowered to Landlock port rules alone.
  - Mitigates: `threat.t2-silent-downgrade` via `mitigation.t2-gap`
  - Given Linux T2, when a proxy-only cage is built, then it fails with CapabilityGap naming proxy-only networking
- **SR-009** (P2): Every proxy connection MUST be decided by the allowlist of exactly one run and its refusals recorded in that run's violations; a child MUST NOT reach the listener of another run.
  - Mitigates: `threat.run-confusion` via `mitigation.run-bound-listener`
  - Given two concurrent runs with different allowlists, when the child of run A requests a host only run B allows, also by connecting to run B's listener, then the request fails and only run A's violations record it
- **SR-010** (P2): The proxy MUST NOT terminate TLS or alter payloads; after the CONNECT or SOCKS5 reply it MUST relay bytes unchanged.
  - Mitigates: `threat.payload-tampering` via `mitigation.opaque-relay`
  - Given an allowed local test host that echoes and hashes what it receives, when the child sends random bytes through CONNECT and SOCKS5, then the hashes on both ends match
- **SR-011** (P2): The proxy MUST bound each run's concurrent connections and handshake time, and MUST close every connection of a run when the run ends.
  - Mitigates: `threat.proxy-exhaustion` via `mitigation.bounded-proxy`
  - Given a child opening connections beyond the cap and one that never finishes its handshake, when the run continues, then excess connections are refused, the stalled one is closed after the timeout, and other runs keep working
  - Given an open long-lived connection, when the run ends, then the connection is closed
- **SR-012** (P2): A refusal MUST record the host escaped, without raw control bytes, and within the run's violation cap with the rest counted.
  - Mitigates: `threat.record-spoof` via `mitigation.escaped-capped-record`
  - Given a refused host containing an escape sequence and a newline, when the violation is read, then the host is shown escaped
  - Given a child making more refused requests than the cap, when the record is read, then it holds the cap and counts the rest
- **SR-013** (P2): THREAT_MODEL MUST list the allowlist parser-differential escape class with the parser suite as evidence and direct-egress canaries per proxy tier, and the docs MUST state that the allowlist binds host names, not content.
  - Mitigates: `threat.allowlist-overclaim`, `threat.parser-differential` via `mitigation.honest-claims`
  - Given THREAT_MODEL.md and the proxy docs, when they are reviewed, then the class has evidence entries for the suite and canaries, and the docs name shared hosting and fronting as residual risk
<!-- threatspec:end -->

## Success Criteria *(mandatory)*

- **SC-001**: No caged child on macOS or T1 reaches a non-allowed host by any
  tested route.
- **SC-002**: The parser suite and a fuzz target run in CI with zero
  disagreements between checked and connected host.
- **SC-003**: Typical package installs (cargo, npm, pip) work through the
  proxy with only their registries allowed.

## Assumptions

- Package managers honour the standard proxy variables, which the cage sets.

## Out of Scope

- Content inspection, credential injection, per-URL rules.
- A system-wide or persistent proxy.
