# Contract: Base V3 and quiet records

```rust
pub enum Base { None, V1, V2, V3 } // V3: V2 + quiet denies (macOS); V2 on Linux
pub mod base { pub const MACOS_V3_QUIET_SERVICES: &[&str]; pub fn macos_v3_quiet(tty: Tty) -> Vec<Rule>; }
pub mod presets { minimal::v3(), agent_readonly::v3(root), agent_workspace::v3(root), build::v3(root) }

pub struct Violation { …, pub repeats: u32 } // ≥ 1; Display appends " (×N)" when N > 1
```
Rendering: `(deny mach-lookup (global-name "com.apple.logd") … (with no-report))`;
`sbpl::Rule` gains `quiet: bool`.
