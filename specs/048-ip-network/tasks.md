# Tasks: An IP network without Unix sockets

## Phase 1: Foundational

- [X] T001 `Network::Ip`, `#[non_exhaustive]`, construct `NetIp`, test helper arm — crates/procage-policy/src/{policy,lower/mod}.rs, crates/procage-policy/tests/common/mod.rs, crates/procage-policy/fuzz/fuzz_targets/lower.rs

## Phase 2: User Story 2 — The IP network as a setting (P1)

- [X] T002 [SR-001] [SR-003] [US2] Linux lowering: socket families, no namespace, socket classes off, `ipc.unix_sockets` below ABI 9 — crates/procage-policy/src/{linux,lower/linux}.rs
- [X] T003 [SR-001] [US2] macOS lowering: IP addresses and the resolver socket — crates/procage-policy/src/lower/macos.rs
- [X] T004 [SR-001] [SR-003] [US2] Lowering tests on every target, and `Ip` in the socket-class matrix — crates/procage-policy/tests/{network_ip,sockets}.rs
- [X] T005 [SR-001] [US2] Canaries: TCP, UDP, listen, a name, Unix (pathname, abstract, engine) refused, `ipc.unix_sockets` allowed — crates/procage/tests/escape_{linux,macos}.rs

## Phase 3: User Story 1 — Networked commands on T2 next to D-Bus and Docker (P1)

- [X] T006 [SR-002] [US1] `Relaxation::answers`; `NoUnixSockets` for socket-class gaps under `All` — crates/procage-policy/src/lower/fit.rs
- [X] T007 [SR-002] [US1] Fitting tests: answered under `All`, refused under `Loopback`; T2 with a fake bus and engine — crates/procage-policy/tests/fit.rs, crates/procage/tests/escape_linux.rs

## Phase 4: Polish

- [X] T008 Docs: policies, fitting, hard-deny, Linux guides, rustdoc, lowering table, threat model, changelog — site/content/docs/{policies,fitting,hard-deny,linux}.md, crates/procage/src/linux/{mod,services}.rs, crates/procage-policy/src/lowering.md, crates/procage/THREAT_MODEL.md, CHANGELOG.md
- [X] T009 Version 0.4.0; run `just ci`, `just linux-t1`, `just linux`; CI; quickstart; status Implemented; commit on `main`
