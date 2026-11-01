# Data model: 007-hard-deny-and-presets

| Item | Where |
|---|---|
| `HardDenyClass::{Secrets, TrustHandoff, Persistence}` (`secrets`, `trust-handoff`, `persistence`) | `policy.rs` (appended to `ALL`) |
| `Construct::{HdSecrets, HdTrustHandoff, HdPersistence}` | `lower/mod.rs`, plus lowering-table rows |
| `presets::{SECRETS_HOME, HANDOFF_ANYWHERE, HANDOFF_HOME, PERSISTENCE_HOME, PERSISTENCE_SYSTEM}`, `patterns(class) -> Vec<Glob>` | `presets.rs` |
| `presets::{minimal, agent_readonly, agent_workspace, build}::v1` | `presets.rs` |
| `PresetTag { name: String, version: u32 }`; `Policy.preset: Option<PresetTag>` | `policy.rs`, `format.rs` |
| `Glob::to_sbpl_regex_folded()` | `glob.rs` |
