# Quickstart

1. `cargo test -p procage-policy --all-features`.
2. `cargo test -p procage --test escape_macos r09` (macOS).
3. `just linux`, `just linux-t1` (escape r09, spawn_linux T2 hiding).
4. `just ci`.

## Recorded outcomes (2026-10-31)

- Policy crate: 85 passed (snapshot set pinned, refusals name
  `accept_spawn_snapshot`, T2 hide with/without write, secrets on T2 read
  vs write, sockets per tier/ABI incl. the AF_UNIX-only filter and the ABI-9
  rules, macOS path-filtered rules and hidden denies, serde); preset
  fixtures unchanged.
- macOS: `r09_unix_sockets_reach_only_their_paths` passes (bind+connect in
  the workspace ok; daemon outside, socket under a hidden path, TCP: EPERM).
  A socket path spelled through `/tmp` matches the resolved rule. Negative
  control: without the hidden-path deny the hidden socket connects. Socket
  addresses are limited to 104 bytes on macOS (test uses a short dir).
- Linux T1 (18/18 exec, escape 20, spawn 31) and T2 (escape 20, spawn 31):
  R-09 socket canary on T1 gives `ok 111 111 1` (inside ok; daemon masked;
  host abstract socket in another netns; TCP denied) and is refused on T2
  naming `ipc-unix-sockets`; T2 hiding: sibling reads, hidden file and the
  same file through a symlink sibling and a listing denied, an entry created
  after the spawn denied; write rule around refused; write grant around fails
  the spawn with `GrantError::Covers`; reading `/` with a test home keeps
  `.ssh` unreadable. Negative control: without the piecewise expansion the
  hidden file reads. Linux clippy and rustdoc clean.
- `just ci`: all 10 gates.
