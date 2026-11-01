# Contract: public API of `procage-policy` (unpublished, 0.0.0)

```rust
// paths and patterns
pub struct AbsPath;  impl TryFrom<&[u8]>, TryFrom<&str>; fn as_bytes(&self) -> &[u8]
pub struct Glob;     impl TryFrom<&str>; fn as_str(&self) -> &str; fn to_sbpl_regex(&self) -> String
pub struct GrantName; pub struct Tag; pub struct Name;   // validated identifiers
pub mod sbpl { pub fn quote(value: &[u8]) -> Result<String, EscapeError>; pub const INLINE_LIMIT: usize = 1016; }

// intent layer
pub struct Policy { pub fs, pub net, pub process, pub ipc, pub env, pub limits, pub tty, pub waive, pub grants, pub seatbelt, pub linux }
impl Policy { pub fn validate(&self) -> Result<(), Vec<PolicyError>> }

// lowering
pub fn lower(policy: &Policy, target: Target, options: &LowerOptions) -> Result<Plan, LowerError>;
pub enum Target { MacOs, Linux { tier: Tier, landlock_abi: u8 } }
pub enum Plan { Seatbelt(SeatbeltPlan), Linux(LinuxPlan) }
pub struct CapabilityGap { pub construct: Construct, pub target: Target, pub kind: GapKind, pub subject: Option<String> }

// limits guard (public for tests and explain)
pub mod sbpl { pub struct Rule; pub fn merge_adjacent(rules: Vec<Rule>, max_filters: usize) -> Vec<Rule>; }
```

- All error types implement `core::fmt::Display`, `core::error::Error`,
  `Debug`, `Clone` and `PartialEq`.
- Data types derive `Debug`, `Clone` and `PartialEq`/`Eq` (and `Hash`/`Ord`
  where they are set keys). With feature `serde` they also implement
  `Serialize` and `Deserialize`.
- Features:
  - `serde` (off by default);
  - `unstable-operations` (off): `seatbelt::Operation::Other`.
- No `unsafe` and no `std`.
