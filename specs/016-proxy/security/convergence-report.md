## Security Convergence — 016-proxy

Commit `9348ab0` · 2026-11-02T17:37:46Z

| Metric | Value |
|---|---|
| Threats (active) | 13 |
| Open blocking threats | 0  |
| Security requirements | 13 |
| verified | 13 |
| implemented, unverified | 0  |
| partial | 0  |
| missing | 0  |
| Expired decisions | 0  |
| Source drift | none |

**Status: CONVERGED**

| Requirement | Verdict | Method | Evidence | Justification |
|---|---|---|---|---|
| SR-001 | verified | test | `crates/procage-proxy/tests/proxy.rs::a_host_not_on_the_list_is_refused_without_a_query` | A SOCKS5 request for allowed.test\0.evil.test is refused (reply 2) with no query and no connection; ALLOWED.TEST. connects as allowed.test (an_allowed_host_is_reached_unchanged_over_both_protocols); the escape canaries r35_a_host_is_read_one_way refuse percent encoding and NUL through the real cage on macOS and T1; the host fuzz target (18.4 million inputs) found no host that is not a fixed point or that a resolver would read as an address. |
| SR-002 | verified | test | `crates/procage-proxy/tests/proxy.rs::literals_are_refused_unless_a_range_holds_them` | With a domain-only list 2130706433, 0x7f.1, 017700000001, [::ffff:127.0.0.1], 127.1 and 127.0.0.1 are refused; with a range holding the address the decimal and dotted forms connect to the same echo host; no query is made. |
| SR-003 | verified | test | `crates/procage-proxy/tests/proxy.rs::an_allowed_name_that_resolves_inward_is_refused` | Allowed names resolving to 127.0.0.1, 169.254.169.254 and ::ffff:10.0.0.1 are refused with Reason::Address naming the address; the_checked_address_is_the_one_connected_to shows one query and a connect to the first checked address. |
| SR-004 | verified | test | `crates/procage-proxy/tests/proxy.rs::a_host_not_on_the_list_is_refused_without_a_query` | Three refused requests leave the counting resolver at zero queries. |
| SR-005 | verified | test | `crates/procage-proxy/src/allow.rs::tests::construction_fails_closed` | An empty list returns AllowlistError::Empty; *, *.com, *.com:443, 0.0.0.0/0 and [::]/0 return TooWide; there is no constructor without entries. |
| SR-006 | verified | test | `crates/procage/tests/escape_macos.rs::r36_a_proxy_only_child_has_no_other_route` | On macOS a proxy-only child with no proxy listening fails both through the proxy and directly; on Linux a proxy-only cage without the proxy is refused, and with it the T1 namespace has no route but the listeners (r36 on escape_linux.rs); no code path connects directly. |
| SR-007 | verified | test | `crates/procage/tests/escape_linux.rs::r36_a_proxy_only_child_has_no_other_route` | On T1 direct TCP to a host port, ::1, a public address, UDP to a public resolver, TCP Fast Open, MPTCP, a raw socket and IPv6 all fail, and a datagram to the host loopback does not arrive; the macOS canary covers TCP, IPv6, UDP and DNS; the control through the proxy succeeds. Landlock is a second layer only. |
| SR-008 | verified | test | `crates/procage/tests/proxy.rs::tier_t2_refuses_a_proxy_only_cage` | Cage::with_options on T2 returns LowerError::Gaps with Construct::NetProxy; r36 on escape_linux.rs checks the same. |
| SR-009 | verified | test | `crates/procage/tests/proxy.rs::a_run_reaches_only_its_own_listener` | A run with a narrow list cannot use a concurrent wide run's listener (macOS refuses the connect; on T1 the address is the narrow run's own listener), its request is refused, the refusal is in the narrow run's record and the wide run's record holds none. |
| SR-010 | verified | test | `crates/procage-proxy/tests/proxy.rs::an_allowed_host_is_reached_unchanged_over_both_protocols` | 64 KiB of pseudo-random bytes come back unchanged through CONNECT and SOCKS5; plain HTTP is forwarded byte for byte (plain_http_is_forwarded_only_for_the_host_it_names); the crate has no TLS code. |
| SR-011 | verified | test | `crates/procage-proxy/tests/proxy.rs::a_run_is_bounded_and_ends_its_connections` | A stalled handshake is closed after the timeout, a connection beyond the limit is closed at once with Reason::Busy, and dropping the run closes an open relay. |
| SR-012 | verified | test | `crates/procage-proxy/tests/proxy.rs::a_refused_host_is_recorded_escaped` | A host with an escape sequence and a newline is recorded without control bytes; refusals enter the run's record through Record::push, which merges repeats and counts what exceeds the cap (crates/procage/src/violation.rs tests). |
| SR-013 | verified | review | `crates/procage/THREAT_MODEL.md:219` | THREAT_MODEL lists R-35 (parser differential) and R-36 (direct egress) with canaries on both suites, the release status names shared hosting and fronting as residue, and site/content/docs/proxy.md says the allowlist binds host names, not content. |
