# Contract: Older Linux kernels

```rust
// procage-policy
pub enum Signals { SelfAndChildren, SameUser, None }   // serde: same-user
pub enum Construct { /* … */ SignalsSameUser /* "signals-same-user" */ }
pub enum Condition { /* … */ TruncWithoutWrite { flags_arg: u8 } }
impl Tier { pub fn min_landlock_abi(self) -> u8 /* T1: 1, T2: 1 */ }

// procage::linux
impl CageOptions {
    pub landlock_abi: Option<u8>,
    pub fn with_landlock_abi(self, abi: u8) -> Self;
}
impl Cage { pub fn landlock_abi(&self) -> u8; }
```

Lowering below ABI 3 (both tiers) adds (the plan's deny list is sorted): `truncate` Always → EPERM; `open` (x86_64) TruncWithoutWrite{1} →
EPERM; `openat` TruncWithoutWrite{2} → EPERM; `openat2` Always → ENOSYS.
