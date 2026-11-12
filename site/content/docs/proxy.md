+++
title = "Proxy: network through an allowlist"
description = "The proxy feature: a caged child reaches the hosts an allowlist names through a proxy of its run's own, and no other route. One canonical host parser, checked resolution, no allow-all."
weight = 81

[extra]
group = "Guides"
nav = "Proxy"
+++

"Network on" lets a caged program reach package registries and APIs, and anywhere else too. With the `proxy` feature, a cage gives each run a proxy of its own that connects only to the hosts an allowlist names, and the kernel keeps the child from every other route.

```toml
procage = { version = "0.8", features = ["proxy"] }
```

```rust
use procage::native::{Cage, CageOptions, Grants};
use procage::policy::{Network, Port};
use procage::proxy::{Allowlist, Proxy};

let allow = Allowlist::new(["crates.io", "*.crates.io", "static.rust-lang.org"])?;
let mut policy = policy.clone();
policy.net = Network::Proxy {
    http: Some(Port::new(3128).unwrap()),  // serve HTTP CONNECT and plain HTTP
    socks: Some(Port::new(1080).unwrap()), // serve SOCKS5
};
let options = CageOptions::default().with_proxy(Proxy::new(allow)).with_violations();
let cage = Cage::with_options(&policy, &options)?;
let mut child = cage.spawn(&mut std::process::Command::new("cargo").arg("fetch"), &Grants::new())?;
child.wait()?;
for v in &child.violations() {
    eprintln!("sandbox: {v}"); // proxy (pid 0) was denied network-outbound evil.example:443 (not on the allowlist)
}
```

The child gets `HTTP_PROXY`, `HTTPS_PROXY` and `ALL_PROXY` (and their lower-case forms) naming its run's proxy; `NO_PROXY` is removed. Programs that ignore these variables fail: there is no direct route.

## What the allowlist allows

| Entry | Allows |
|---|---|
| `crates.io` | that host, any port |
| `api.example.com:443` | that host on port 443 |
| `*.npmjs.org` | every subdomain (not `npmjs.org` itself) |
| `192.0.2.0/24`, `[2001:db8::]/32`, `10.1.2.3` | those addresses, as literals or after resolution |

An empty list, `*` and a wildcard over one label (`*.com`) are refused when the list is built: there is no allow-all mode.

## How a request is decided

- **One canonical host.** The host a request names (a `CONNECT` target, an absolute `http://` URI, a SOCKS5 name or address) is parsed once: lower case, one trailing dot removed, A-labels only. That value is checked and connected to. NUL and control bytes, percent encoding, userinfo, non-ASCII names and a `Host` header that differs from the URI are refused.
- **Addresses are addresses.** Every IPv4 notation (`2130706433`, `0x7f.1`, `017700000001`, `127.1`) and IPv4-mapped IPv6 read as the address they are, and need a range entry.
- **Resolution is checked.** A name the list refuses is never resolved. An allowed name is resolved once; loopback, private, link-local (cloud metadata included), shared and other non-public addresses, also inside mapped or translated IPv6, are refused unless a range entry holds them. The proxy connects to the address it checked.
- **No content.** After the `CONNECT` or SOCKS5 reply the proxy relays bytes unchanged. It never terminates TLS. The allowlist binds host names, not content: a host that serves other sites (shared hosting, domain fronting through a CDN) is reachable with whatever they serve.
- **Bounded.** A run has at most 64 connections and 10 seconds for a handshake and a connect; its connections close when the run ends.

## How the child is kept to it

| System | Boundary |
|---|---|
| macOS | The profile allows outbound connections to the run's proxy ports only: fresh loopback ports per run, passed as profile parameters. Every other address, UDP and DNS included, is denied. |
| Linux T1 | The child runs in a network namespace of its own. Before it is restricted it brings up the namespace's loopback, listens there on the policy's ports, and hands the listeners to the parent, which serves them. They are the only endpoints the child can reach; Landlock allows connecting to those ports only (ABI 4+), and seccomp allows only IP sockets (and Unix sockets if `ipc.unix_sockets` names paths). |
| Linux T2 | No network namespace, and port rules alone are no boundary (TCP Fast Open, MPTCP): `Network::Proxy` is a capability gap. |

A run cannot reach another run's proxy: on macOS its profile names only its own ports, on Linux the other run's listeners are in another namespace. The escape suites check every direct route on each proxy tier (R-36) and the parser's one reading of a host (R-35); the proxy crate's table-driven suite and a fuzz target back the parser.

## Without procage

`procage::proxy` is the `procage-proxy` crate: std only, no `unsafe`. It serves listeners you give it, for any process:

```rust
use std::net::TcpListener;
use procage::proxy::{Allowlist, Protocol, Proxy};

let proxy = Proxy::new(Allowlist::new(["crates.io"])?);
let run = proxy.serve(vec![(Protocol::Http, TcpListener::bind("127.0.0.1:0")?)], |r| eprintln!("{r}"))?;
// … dropping `run` closes the listener and every connection.
```

Without `with_proxy`, `Network::Proxy` on macOS keeps its plain meaning: outbound connections to your own proxy at the policy's ports.
