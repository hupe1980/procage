# Contract

```rust
// procage (both systems)
pub enum LinkAudit { Refuse, Report, Off }            // default Refuse
pub struct LinkFinding { pub path: PathBuf, pub links: u64, pub symbolic: bool }
pub enum HandoffKind { Created, Modified, Link { target: PathBuf }, Repository }
pub struct HandoffFinding { pub path: PathBuf, pub kind: HandoffKind }
pub struct Audit { pub mode: LinkAudit, pub links: Vec<LinkFinding>, pub links_complete: bool,
                   pub handoff: Option<Vec<HandoffFinding>>, pub handoff_complete: bool }

// procage::macos and procage::linux
impl CageOptions {
    pub fn with_link_audit(self, mode: LinkAudit) -> Self;
    pub fn with_handoff_audit(self) -> Self;
    pub fn with_walk_limit(self, limit: usize) -> Self;   // macOS: new
}
#[non_exhaustive] pub enum SpawnError { /* … */ HardLinks(Vec<LinkFinding>) }
impl Child { pub fn audit(&mut self) -> Option<Audit>; }   // None while running
```
