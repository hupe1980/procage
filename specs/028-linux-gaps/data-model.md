# Data model

- `procage_policy::Ipc { posix_shm, sysv, unix_sockets: Vec<AbsPath> }` (serde default `[]`).
- `Network` loses `UnixSockets`; `PolicyError` loses `EmptyUnixSockets`.
- `Construct::IpcUnixSockets` (`ipc-unix-sockets`) replaces `NetUnixSockets`;
  `Construct::SPAWN_SNAPSHOT = [HdSecrets, HdTrustHandoff, HdPersistence, FsHide, IpcUnixSockets]`.
- `LowerOptions::accept_spawn_snapshot()` (was `accept_spawn_masks`).
- `LinuxPlan.unix_socket_paths: Vec<AbsPath>` (with `mask_unix_sockets`).
- `linux::GrantError::Covers { name, hidden }`.
