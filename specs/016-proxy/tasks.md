# Tasks: Egress proxy with a domain allowlist

## Phase 1: Setup

- [X] T001 Crate `procage-proxy` (std only, `unsafe` forbidden, workspace lints) and procage's optional dependency behind feature `proxy`; docs.rs features; `[[test]] proxy` with `required-features = ["proxy"]` — Cargo.toml, crates/procage-proxy/Cargo.toml, crates/procage/Cargo.toml

## Phase 2: Foundational

- [X] T002 [SR-001] [SR-002] [P] `Host::parse`: lower case, one trailing dot, LDH and `_` labels of 1–63 bytes, at most 253; NUL, control bytes, `%`, `@`, `/`, spaces and non-ASCII refused; every `inet_aton` IPv4 notation and bracketed IPv6 as `Ip`, IPv4-mapped as IPv4; tests — crates/procage-proxy/src/host.rs
- [X] T003 [SR-005] [P] `Allowlist::new`: hosts, `*.suffix` (two or more labels), `:port`, ranges and single addresses; `Empty`, `TooWide` (`*`, one-label suffix, `/0`), `Invalid`; tests — crates/procage-proxy/src/allow.rs
- [X] T004 [SR-003] [P] `is_public`: loopback, private, shared, link-local, unspecified, multicast, broadcast, documentation, benchmarking, reserved, IPv6 unique-local and link-local, mapped and NAT64 forms; tests — crates/procage-proxy/src/addr.rs
- [X] T005 [SR-003] [SR-004] `Resolve` with `SystemResolver`; `Proxy::open`: the name check before any query, one resolution, the first checked address, connect timeout — crates/procage-proxy/src/resolve.rs, crates/procage-proxy/src/lib.rs

## Phase 3: User Story 1 — Only allowed hosts are reachable (P1)

- [X] T006 [SR-001] [SR-010] [US1] HTTP: head of at most 16 KiB, `CONNECT` with `200` and the bytes after the head forwarded, absolute-form with exactly one matching `Host` forwarded unchanged, `400`/`403`/`431` — crates/procage-proxy/src/http.rs
- [X] T007 [SR-001] [SR-010] [US1] SOCKS5: no-authentication method, `CONNECT`, IPv4, domain and IPv6, reply codes 2, 4, 7, 8 — crates/procage-proxy/src/socks.rs
- [X] T008 [SR-011] [SR-012] [US1] `Proxy::serve` → `Run`: a thread per listener and connection, 64 connections and 10-second handshake and connect limits (`Limits`), refusals with the host escaped, opaque relay, drop closes listeners and connections — crates/procage-proxy/src/lib.rs
- [X] T009 [SR-007] [SR-009] [US1] macOS: `Network::Proxy` lowers to `(remote ip (param …))` with the policy's ports as defaults; `CageOptions::with_proxy`; each spawn binds `127.0.0.1:0` per protocol, overrides the parameters (one compile per run), sets the proxy variables and removes `NO_PROXY`; the run's `Run` lives in `Child` and ends with the run; `exec` refused with a proxy — crates/procage-policy/src/{sbpl,lower/macos,lower/mod}.rs, crates/procage/src/macos/{mod,child}.rs, crates/procage/src/proxied.rs
- [X] T010 [SR-006] [SR-007] [SR-008] [SR-009] [US1] Linux: `Network::Proxy` exact on T1 (network namespace, seccomp `AF_INET` only, plus `AF_UNIX` with `ipc.unix_sockets`; Landlock `CONNECT_TCP` to the proxy ports from ABI 4), unsupported on T2; the socket classes need no search while Unix sockets are refused; the child sequence brings `lo` up, listens on the policy's ports and sends the listeners to the parent before dropping capabilities (reported as `Step::Listener`); the parent serves them; `Network::Proxy` without `with_proxy` refused — crates/procage-policy/src/lower/linux.rs, crates/procage/src/linux/{mod,child,sys}.rs
- [X] T011 [SR-012] [US1] Refusals as violations (`DeniedBy::Allowlist`, process `proxy`, target `host:port (why)`) when the cage reports violations — crates/procage/src/violation.rs, crates/procage/src/proxied.rs
- [X] T012 [SR-007] [SR-009] [US1] procage tests: allowed hosts through HTTP and SOCKS5, refusals in the record, every direct route fails (and a datagram to the host's loopback does not arrive), a run reaches only its own listener, a cage without `Network::Proxy` refused, T2 a gap — crates/procage/tests/proxy.rs

## Phase 4: User Story 2 — The parser cannot be fooled (P1)

- [X] T013 [SR-001] [SR-002] [SR-003] [SR-004] [US2] Crate tests: case and trailing dot, NUL in SOCKS5, `evilallowed.test`, literals in every notation refused without a range and allowed with one, names resolving inward refused, the checked address connected to with one query, no query for a refused name, plain HTTP forwarded only for its own `Host` — crates/procage-proxy/tests/proxy.rs
- [X] T014 [SR-001] [US2] Fuzz target `host`: a parsed host is a fixed point, a name holds only label bytes and never reads as an address; `just fuzz-all` runs it — crates/procage-proxy/fuzz/, justfile

## Phase 5: User Story 3 — Misconfiguration fails closed (P1)

- [X] T015 [SR-005] [SR-006] [US3] Construction errors for an empty list, `*`, `*.com`, `/0`; no proxy listening means no route (macOS canary); Linux T1 refuses `Network::Proxy` without the proxy — crates/procage-proxy/src/allow.rs, crates/procage/tests/escape_{macos,linux}.rs

## Phase 6: Polish

- [X] T016 [SR-013] Escape catalog: R-35 (parser differential) and R-36 (direct egress around the proxy) with canaries in both suites (`proxy` feature), the published-id baseline, the release status — crates/procage/THREAT_MODEL.md, crates/procage/tests/{escape_macos,escape_linux,threat_model}.rs, crates/procage/tests/support/proxied.rs
- [X] T017 Gates and lanes: the async steps build `tokio,proxy` and run `tests/proxy.rs` (just, CI, kernel lane); `just features` keeps `procage-proxy` out of the default tree; `package-docs` packages the three crates; the release publishes `procage-proxy` before `procage`; `Proxy` and `Run` unwind safe — justfile, .github/workflows/{ci,release}.yml, .github/kernel-lane.sh, crates/procage-proxy/src/{lib,resolve}.rs
- [X] T018 [SR-013] Docs: crate docs section, site page `proxy.md`, Linux limits, README, CHANGELOG — crates/procage/src/lib.rs, site/content/docs/{proxy,linux}.md, README.md, CHANGELOG.md
- [X] T019 Run `just ci`, `just escape`, `just linux`, `just linux-t1`, the kernel lane; quickstart results; threat-model convergence; spec status Implemented; commit on `main`
