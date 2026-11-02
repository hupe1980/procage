# Tasks: Published spawn benchmarks

- [X] T001 [US1] crates/procage/benches/spawn.rs and the `[[bench]]` entry in crates/procage/Cargo.toml: cases, warm-up, iterations, median/p90/p99, overhead, the header, `--quick`, the refusal inside another sandbox
- [X] T002 [US1] Run on the reference Mac and in Docker Linux (T1, T2); record the tables in specs/043-benchmarks/quickstart.md
- [X] T003 [US2] CI: the gates job builds the bench (`clippy --all-targets`); `--quick` runs in the macOS and Linux lanes; justfile `bench`
- [X] T004 [US1] Docs: README "Performance", site page, CHANGELOG
- [X] T005 Gates: `just ci`; commit on `main`
