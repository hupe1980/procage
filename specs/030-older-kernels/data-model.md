# Data model: Older Linux kernels

- **`Signals::SameUser`** (policy, serde `same-user`): the child may signal
  every process the operating system lets it signal. Construct
  `signals-same-user`: exact on macOS, T1 and T2 at every ABI.
- **`CageOptions::landlock_abi: Option<u8>`** (Linux): `None` = the kernel's
  ABI. Effective ABI = `min(kernel, cap, BACKEND_MAX_ABI)`; below the tier's
  minimum → `Unsupported::Landlock { abi: effective, needed }`.
- **`Cage::landlock_abi() -> u8`** (Linux): the effective ABI.
- **`Condition::TruncWithoutWrite { flags_arg: u8 }`** (policy, Linux
  seccomp): the call's argument `flags_arg` has `O_TRUNC` and an access mode
  that is neither `O_WRONLY` nor `O_RDWR`.
- **Syscalls** `truncate`, `open`, `openat`, `openat2` join `Syscall`.
- **Tier minimums**: T1 1, T2 1.
