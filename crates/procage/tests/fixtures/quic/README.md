# QUIC Initial fixtures

`big-0.bin` and `big-1.bin` are two client Initial datagrams of one QUIC v1
connection ("big" ClientHello, split across the two), captured with
`openssl s_client -quic -alpn h3 -servername quic-big.example` (OpenSSL
3.5.7) during procage's Phase 0 research on 2026-11-24. They contain no
third-party content and no user data; the SNI is a documentation name.

| file | bytes | sha256 |
|---|---|---|
| `big-0.bin` | 1200 | `2b67904aa75439961823cdf32986d850a3de91f1b9923feafafc451c90824e1a` |
| `big-1.bin` | 1200 | `8bcdc8b0c8153fa5cbe77453709b4fe6e25350ba7e5768db9ba6fed2390a1bb9` |
| `ech-0.bin` | 1222 | `8662a404e460d41ff5d2e96b221eb902b61a7087f2e23a115bae3fa5c8f3937b` |
| `ech-1.bin` | 1222 | `2b92d232ca00270605018d709c0997365446360089f1b0edde67d00b759e05f2` |

`ech-0.bin` and `ech-1.bin` were generated locally (2026-11-25) by
`/tmp/opencode/quic-ech-gen`, a procage Phase 0 scratch tool using `ring` and
`aes`: it wraps the synthetic TLS ClientHello in
`/tmp/opencode/phase0-tunpolicy/tls-ch-ech-synthetic.bin` (outer SNI
`public.example`, opaque extension `0xfe0d`) in two QUIC v1 client Initials
and splits it at byte 1000. The ECH extension is synthetic and labelled as
such; no real HPKE handshake. The generator is not part of the repository;
the fixtures are input data for the relay's ECH test.
