# Contract

```rust
// procage-policy
pub enum Relaxation { LeaveOutProtect, LeaveOutHide, Waive(HardDenyClass), NoUnixSockets, SignalsSameUser, NoLoopback }
pub struct Relax { /* … */ }
impl Relax {
    pub fn new() -> Self;
    pub fn leave_out_protect(self) -> Self; pub fn leave_out_hide(self) -> Self;
    pub fn waive(self, class: HardDenyClass) -> Self;
    pub fn no_unix_sockets(self) -> Self; pub fn signals_same_user(self) -> Self; pub fn no_loopback(self) -> Self;
    pub fn apply(&self, policy: &mut Policy, gaps: &[CapabilityGap]) -> Result<Vec<(CapabilityGap, Relaxation)>, Vec<CapabilityGap>>;
}
pub struct Lift { pub tier1: bool, pub landlock_abi: Option<u8> }
pub fn lift(policy: &Policy, gap: &CapabilityGap, options: &LowerOptions, max_abi: u8) -> Lift;
pub struct Relaxed { pub gap: CapabilityGap, pub relaxation: Relaxation, pub lift: Lift }  // Display

// procage::{linux, macos}
impl Cage { pub fn fit(policy: &Policy, options: &CageOptions, relax: &Relax) -> Result<(Cage, Vec<Relaxed>), SpawnError>; }
```
