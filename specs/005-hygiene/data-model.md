# Data model: 005-hygiene

| Type | Where | Notes |
|---|---|---|
| `hygiene::EnvDecision { set, dropped }` | `src/hygiene.rs` (all OSes) | pure output of `environment()` |
| `hygiene::DROPPED_PREFIXES`, `DROPPED_NAMES`, `DROPPED_SUFFIXES` | `src/hygiene.rs` | the passthrough denylist |
| `macos::Child` | `src/macos/child.rs` | `Deref<Target = std::process::Child>`, `DerefMut`; `kill_all()`, `detach()`, `dropped_env()`, `tmpdir()`; `Drop` kills the tree and removes the tmpdir |
| `Cage::spawn(&mut Command, &Grants) -> Result<Child, SpawnError>` | | return type changes from `std::process::Child` |
| `Cage::spawn_with_fds(&mut Command, &Grants, &[BorrowedFd<'_>])` | | named fds |
| `SpawnError::Fd { fd }` | | a named fd is not open |
| `GrantError::Reserved { name }` | | the caller bound `tmpdir` |
| `sys::ChildPlan` gains `keep: Vec<RawFd>`, `fd_buffer: Vec<proc_fdinfo>`, `new_session: bool` → `group: Group::{Session, ProcessGroup}` | | |
