# Quickstart: checking 041

```sh
cargo test -p procage-policy                  # lowering, presets, fixtures
cargo test -p procage --test escape_macos r34  # macOS canaries (outside any sandbox)
just linux-t1                                  # Linux T1 (Docker, unconfined)
just linux                                     # Linux T2 (Docker default seccomp)
just ci                                        # every gate
```

Expected: the R-34 canaries refuse each connect (T2: the cage reports the
gap naming the socket), and each waived control connects.

## Results, 2026-11-01 (after the security remediation)

| Lane | Result |
|---|---|
| macOS 26.6.2 (25G83), outside any sandbox | `just ci` green (every gate; kernel facts 30/30, profile compile 3/3); escape suite 24 passed, 3 open — also with reporting, and on base V3 with reporting; `an_engine_connect_is_reported_with_its_class` passes |
| Docker Linux 7.0.14 aarch64, tier T2 | lib 40, spawn 47 (+1 ignored), exec 10, native 5, unsafe 2, escape 27 (+2 open); escape with reporting 27 (+2 open) |
| Docker Linux 7.0.14 aarch64, tier T1 | the same, exec 20 |

Notes from implementation:

- Every Linux plan already scopes abstract sockets from Landlock ABI 6, so an
  abstract bus is out of reach there regardless of the class; the class adds
  the gap below ABI 6 (canaries with the ABI capped at 5, serialised because
  abstract names are shared by the whole network namespace).
- On macOS a hard link to a socket the child cannot write is refused by the
  deny-default profile itself; on Linux Landlock never grants linking across
  directories. Both canaries assert the refusal with and without the class.
- The preset fixtures differ only by one `network-outbound` deny each;
  `PROCAGE_BLESS=1` regenerates them for review.
