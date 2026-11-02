# Quickstart: validating the egress proxy

```sh
cargo test -p procage-proxy                                   # parser, allowlist, addresses, end to end
cargo test -p procage --features proxy --test proxy           # a cage's own proxy
cargo test -p procage --features proxy --test escape_macos -- r35 r36
just linux-t1 && just linux                                    # T1 canaries; T2 gap
just fuzz host 60 procage-proxy                               # nightly, cargo-fuzz
```

Expected:

- The crate: case and a trailing dot reach the allowed host; NUL, percent
  encoding, userinfo, a differing `Host` header and every IPv4 literal
  notation are refused without a query (with a range, literals connect);
  allowed names resolving to loopback, metadata or mapped private
  addresses are refused naming the address; one query per request, and
  the connect goes to the checked address; bytes relay unchanged; limits
  and the end of a run close connections; an empty or too-wide list fails
  to build.
- procage: through HTTP and SOCKS5 a run reaches the allowed echo host;
  refusals are `DeniedBy::Allowlist` violations of that run only; every
  direct route fails; a run cannot use another run's listener; T2 returns
  the `net-proxy` gap.
- R-35 and R-36 canaries pass on macOS and T1.

## Results (2026-11-02)

| Where | Run | Result |
|---|---|---|
| macOS 26 (arm64) | `procage-proxy` tests | 9 unit, 9 end-to-end, 1 doc test passed |
| macOS 26 (arm64) | `tests/proxy.rs` | 5 passed |
| macOS 26 (arm64) | `escape_macos` R-35, R-36 | passed |
| Linux T1 (container, kernel 7.0) | `tests/proxy.rs` | 6 passed (T2 gap included) |
| Linux T1 (container, kernel 7.0) | `escape_linux` with `proxy` | 34 passed, 1 ignored (an open class) |
| Linux T1 (guest, mainline 7.3.1, ABI 11) | `tests/proxy.rs` in the kernel lane | 6 passed |
| macOS | fuzz `host`, 61 s | 18.4 million inputs, no failure |
| macOS | `just ci` | every gate green |

Security convergence: SR-001 to SR-013 verified (see
`security/convergence-report.md`).
