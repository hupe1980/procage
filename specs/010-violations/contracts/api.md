# Contract: violations API

## procage-policy

```rust
// LowerOptions: replaces the static `tag` (unused) with a switch.
impl LowerOptions {
    /// Every deny rule but the run-marker block carries a message naming
    /// the run (the run-marker parameter) and the rule's kind.
    pub fn with_violations(self) -> Self;
}

/// Why a rule denied: the code after the run marker in a denial message.
#[non_exhaustive]
pub enum DenyReason { HardDeny(HardDenyClass), Protect, Hide, Layer }
impl DenyReason {
    pub fn code(&self) -> String;              // "hd:privilege", "protect", …
    pub fn from_code(code: &str) -> Option<Self>;
}
```

Rendering: without the option, `write_profile` output is unchanged. With
it, `(deny default (with message (param "<RUN_MARKER_PARAM>")))` and each
explicit deny with a reason gets `(with message (string-append (param
"<RUN_MARKER_PARAM>") " <code>"))`. The run-marker block has no message.

## procage (both backends; `procage::native` subset)

```rust
impl CageOptions { pub fn with_violations(self) -> Self; }

impl Child {
    /// The record so far. After the child exited, first waits (≤ 1 s) for
    /// a fence, so `complete()` is true when it returns in time.
    pub fn violations(&mut self) -> Violations;
    /// Live violations, once (later calls return `None`); `None` when
    /// coverage is not `Observed`. Bounded: when the receiver lags, newer
    /// violations are only in the record.
    pub fn violation_receiver(&mut self) -> Option<std::sync::mpsc::Receiver<Violation>>;
}

pub struct Violation {
    pub pid: u32,
    pub process: String,          // the name the kernel logged
    pub operation: String,        // e.g. "file-read-data"
    pub target: Option<String>,   // path, service name, …
    pub denied_by: DeniedBy,
    pub received: std::time::SystemTime,
}
impl Display for Violation;       // "cat (pid 812) was denied file-read-data ~/.ssh/id: hidden by the policy"

#[non_exhaustive]
pub enum DeniedBy { NotGranted, HardDeny(HardDenyClass), Protect, Hide, Layer, Unknown(String) }

#[non_exhaustive]
pub enum Coverage {
    Off,                // the cage was built without `with_violations`
    Observed,           // macOS: every denial, best effort, deduplicated per process
    Unavailable(String),// the stream could not start or ended; the reason
    NotObserved,        // this platform reports nothing yet (Linux)
}

pub struct Violations { /* list, complete, coverage, dropped */ }
impl Violations {
    pub fn iter(&self) -> std::slice::Iter<'_, Violation>;
    pub fn len(&self) -> usize; pub fn is_empty(&self) -> bool;
    pub fn complete(&self) -> bool;   // child exited and a fence passed
    pub fn coverage(&self) -> &Coverage;
    pub fn dropped(&self) -> u64;     // beyond the cap (10,000 per run)
}
impl IntoIterator for Violations / &Violations;
```

`Cage::exec` has no record.
