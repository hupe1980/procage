# Contract: receipts

```rust
// procage (both systems)
#[non_exhaustive] pub struct Receipt { /* fields of data-model.md */ }
impl Receipt {
    pub fn to_json(&self) -> String;
    pub fn from_json(text: &str) -> Result<Receipt, ReceiptError>;
}
pub enum ReceiptBackend { MacOs { .. }, Linux { .. } }
pub struct ReceiptExit { pub code: Option<i32>, pub signal: Option<i32>, pub ended_by_caller: bool }
pub fn policy_digest(policy: &Policy) -> String;          // "sha256:…"

// procage::macos and procage::linux
impl CageOptions { pub fn with_policy_in_receipt(self) -> Self; }
impl Child { pub fn receipt(&mut self) -> Option<Receipt>; }  // None while running
```

`Cage::exec` gives no receipt (the caller's process is replaced).
