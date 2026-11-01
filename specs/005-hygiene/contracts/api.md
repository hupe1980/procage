# Contract changes (0.0.2, unreleased)

```rust
impl Cage {
    pub fn spawn(&self, cmd: &mut Command, grants: &Grants) -> Result<Child, SpawnError>;
    pub fn spawn_with_fds(&self, cmd: &mut Command, grants: &Grants, fds: &[BorrowedFd<'_>])
        -> Result<Child, SpawnError>;
}
pub struct Child;  // Deref/DerefMut to std::process::Child
impl Child {
    pub fn kill_all(&mut self) -> io::Result<()>;
    pub fn detach(self) -> std::process::Child;
    pub fn dropped_env(&self) -> &[String];
    pub fn tmpdir(&self) -> Option<&Path>;
}
pub mod hygiene {   // all OSes
    pub struct EnvDecision { pub set: Vec<(OsString, OsString)>, pub dropped: Vec<String> }
    pub fn environment(caller: impl IntoIterator<Item = (OsString, OsString)>, policy: &EnvPolicy,
                       explicit: &[(OsString, Option<OsString>)]) -> EnvDecision;
}
```

`std::process::Child::kill` (reachable through `Deref`) only kills the
direct child. `kill_all` and `Drop` kill the whole tree.
