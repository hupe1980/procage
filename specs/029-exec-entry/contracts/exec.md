# Contract: exec entry

```rust
impl Cage {
    pub fn exec(&self, command: &mut Command, grants: &Grants) -> SpawnError;
    pub fn exec_with_fds(&self, command: &mut Command, grants: &Grants, fds: &[BorrowedFd<'_>]) -> SpawnError;
}
```

| | spawn | exec |
|---|---|---|
| process | new child, `Child` handle | the caller becomes the command |
| session / group | new session (or group with `Tty::Inherit`) | the caller's, unchanged |
| lifetime | handle (drop / `kill_all`), feature 024 | outside code: kill the pid or the group |
| Linux descendants (`Lifetime::Run`) | in the child's group | in the caller's group |
| Linux parent death | child dies with the caller's thread | command dies with the helper's parent |
| macOS descendant in its own session | found by marker | not reached |
| `tmpdir` grant | private dir, removed on drop | refused |
| Linux T1 from a multithreaded process | fine | refused (`ExecThreads`) |

Refused before any change: nesting, probe, grants (incl. `tmpdir`), T1
threads, environment decision, program lookup. After the first change, an
error means the process may be partly confined: exit.
