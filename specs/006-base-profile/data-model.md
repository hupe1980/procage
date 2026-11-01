# Data model: 006-base-profile

| Item | Where | Notes |
|---|---|---|
| `Base::{None, V1}` | `procage-policy/src/policy.rs` | `#[non_exhaustive]`, default `None`; `Policy.base` |
| `Construct::BaseV1` (`base-v1`) | `lower/mod.rs` | lowering table: macOS exact, T1 exact, T2 exact |
| `base::{macos_v1, linux_v1}`, the content constants | `procage-policy/src/base.rs` | frozen |
| `sbpl::Filter::IpcPosixName(String)` | `sbpl.rs` | |
| `linux::RuleTarget::PathIfExists(AbsPath)` | `linux.rs` | skipped by the backend when absent |
| serde `base` field | `format.rs` | default `none` |
