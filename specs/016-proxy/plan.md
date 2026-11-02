# Implementation Plan: Egress proxy with a domain allowlist

**Branch**: `016-proxy` (local planning; commits on `main`) | **Date**: 2026-11-02 | **Spec**: [spec.md](spec.md)

## Summary

A new crate, `procage-proxy`, serves HTTP `CONNECT`, absolute-form plain
HTTP and SOCKS5 on listeners it is given, deciding each request by one
canonical host against an allowlist, resolving once and connecting only to
an address it checked. procage, behind a `proxy` feature, opens a listener
per run and protocol, keeps the child from every other route by the kernel
(macOS: the profile allows outbound connections to the run's ports only;
Linux T1: the run's own network namespace, in which the listener is the only
endpoint), records refusals in the run's violations and closes the run's
connections when it ends. Linux T2 stays a gap.

## Technical Context

- **Language**: Rust 2024, MSRV 1.99, `#![forbid(unsafe_code)]` in the new
  crate, std only (threads, `TcpListener`, `ToSocketAddrs`).
- **Dependencies**: none new; procage gains the optional
  `procage-proxy` path dependency (feature `proxy`).
- **Testing**: table-driven parser and decision tests and a fuzz target in
  the crate; integration tests with a local echo host and a counting test
  resolver; escape canaries per direct route on macOS and T1; the T2 gap.

## Design

1. **Host** (`host.rs`). `Host::parse` takes the bytes a request names and
   returns `Name` (lower-case, one trailing dot removed, LDH labels of 1–63
   bytes, at most 253 bytes, not all-numeric in the last label) or `Ip`.
   Refused: NUL and control bytes, `%`, `@`, `/`, `\`, spaces, non-ASCII
   (A-labels only), empty labels. Every IPv4 notation `inet_aton` accepts
   (1–4 parts, decimal, `0x` hex, leading-zero octal) and bracketed IPv6
   become `Ip`; IPv4-mapped IPv6 is normalised to IPv4.
2. **Allowlist** (`allow.rs`). Entries: `host`, `*.suffix` (the suffix has
   two or more labels; matches subdomains, not the suffix itself), either
   with an optional `:port`, and CIDR ranges. `Allowlist::new` fails on an
   empty list, `*` or a one-label suffix. `decide(host, port)`: a name must
   match a host or suffix entry; an `Ip` must lie in a range.
3. **Addresses** (`addr.rs`). Not public: unspecified, loopback, private,
   shared (100.64/10), link-local (incl. 169.254.169.254), multicast,
   broadcast, documentation and benchmarking ranges, IPv6 unique-local and
   link-local, `fd00:ec2::254`, and the IPv4 inside mapped (`::ffff:0:0/96`)
   and translated (`64:ff9b::/96`) forms. Such an address is refused unless
   a range entry contains it.
4. **Resolution** (`resolve.rs`). `trait Resolve` with the system resolver
   as default. An allowed name is resolved once; the first address that is
   public or in a range is connected to, with the rest unused; no second
   query. A refused name is never resolved.
5. **Protocols.** HTTP: a request head of at most 16 KiB within the
   handshake timeout; `CONNECT host:port` → `200` then opaque relay;
   `GET|POST|… http://host[:port]/…` with a `Host` header equal to the URI
   host → connect and forward the head unchanged, then relay; anything else
   `400`; refusals `403`. SOCKS5: no-authentication method only, `CONNECT`
   only, address types IPv4, domain and IPv6; refusals reply code 2. The
   connection stays bound to the checked host for its lifetime.
6. **Runs** (`Proxy`, `Run`). `Proxy::new(allowlist)` (plus
   `.with_resolver`) is cheap to clone; `proxy.serve(listeners, on_refusal)`
   returns a `Run` that accepts on its listeners, bounds itself to 64
   concurrent connections and a 10-second handshake and connect timeout,
   and on drop closes its listeners and shuts down every connection.
   Refusals carry the host escaped (`escape_debug`), the port and the
   reason.
7. **macOS.** The lowering of `Network::Proxy` refers to profile parameters
   (`procage.proxy.http`, `procage.proxy.socks`) whose defaults are the
   policy's ports, so the plan is unchanged without a managed proxy. With
   `CageOptions::with_proxy(proxy)`, each spawn binds `127.0.0.1:0` for each
   protocol the policy names, passes the ports as the parameters (one
   compile per run; the cache keys on parameters), sets the proxy variables
   and starts a `Run`.
8. **Linux T1.** `Network::Proxy` lowers on T1 to a network namespace plus
   Landlock `CONNECT_TCP` rules for the proxy ports (second layer) and no
   `BIND_TCP`; seccomp allows `AF_INET` and `AF_UNIX` sockets only. The
   child sequence, after the mounts and before dropping capabilities, brings
   `lo` up, binds and listens on `127.0.0.1:<port>` per protocol, sends the
   listeners to the parent over a socket pair (SCM_RIGHTS) and closes them;
   a failure is reported as `Step::Listener`.
   The parent receives them before `spawn` returns and starts a `Run`.
   Without `with_proxy` the cage fails with `Unsupported::Setting` (no new
   public variant). T2: unchanged gap (SR-008).
9. **Violations.** With reporting, a refusal is a `Violation` with operation
   `network-outbound`, the target `host:port`, `DeniedBy::Allowlist`, pid 0
   and process `proxy`; it uses the record's cap and merge. The run's
   `Run` lives in the child handle and is dropped when the run ends.
10. **Escape catalog.** R-35 (parser differential) gains the parser suite
    and the fuzz target as evidence; R-36 (direct egress around a proxy)
    gains canaries on macOS and T1: direct TCP to a host port, UDP, TCP Fast
    Open, MPTCP, raw socket, IPv6, DNS to a resolver, another loopback port,
    the proxy stopped.

## Constitution Check

| Principle | Check | Status |
|---|---|---|
| I | No approximation: T1 and macOS enforce by the kernel; T2 a gap; empty list refused | PASS |
| II | Typed errors (`AllowlistError`, `HostError`, `Unsupported::Setting`) | PASS |
| III | Canary per direct route on each proxy tier; parser suite and fuzz in CI | PASS |
| IV | New child-sequence step uses system calls only (socket, ioctl, bind, listen, sendmsg, close) | PASS |
| VII | The proxy crate is std-only; procage depends on it only behind `proxy` | PASS |

## Project Structure

```text
crates/procage-proxy/          # new: host, allow, addr, resolve, http, socks, run
  fuzz/                        # host parser target
crates/procage-policy/src/lower/{macos,linux}.rs  # parameters; T1 ProxyBridge exact
crates/procage/src/{macos,linux}/                 # with_proxy, per-run listeners
crates/procage/src/linux/sys.rs                    # PROXY step
crates/procage/tests/{proxy,escape_macos,escape_linux}.rs
```
