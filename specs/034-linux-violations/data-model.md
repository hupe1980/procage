# Data model: 034-linux-violations

| Entity | Fields | Rules |
|---|---|---|
| `SeccompRule.reason` | `Option<DenyReason>` | set by lowering per origin; `None` = not granted |
| Notifying filter | same rules, `EPERM` verdict → `SECCOMP_RET_USER_NOTIF` | built by the one builder; `ENOSYS` unchanged |
| Hand-over message | 1 byte: `1` + SCM_RIGHTS listener, or `0` + 4-byte errno (fallback) | child → parent over a `SOCK_SEQPACKET` pair, before `execve` |
| Supervisor (per run) | listener, rules + syscall numbers, record, `done` flag | answers first; ends on `POLLHUP` |
| Record | as 010 (cap 10,000, bounded receiver) | complete = `done` and child reaped |
