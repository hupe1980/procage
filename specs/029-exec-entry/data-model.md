# Data model: Exec entry

- `Cage::exec(&self, &mut Command, &Grants) -> SpawnError`,
  `Cage::exec_with_fds(&self, &mut Command, &Grants, &[BorrowedFd]) -> SpawnError`.
- `sys::Session { New, Group, Keep }` (both backends; replaces `new_session: bool`).
- `GrantError::TmpdirWithExec` (both).
- `linux::Unsupported::ExecThreads { threads: usize }`.
- Program lookup: `SpawnError::Io(io::Error)` of kind `NotFound`.
