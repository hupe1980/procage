# Research: Spawning a caged child on Linux

## R1: Landlock and seccomp without crates

- **Decision**: raw syscalls via `libc::syscall`, as the kernel facts do.
- **Rationale**: four small calls (`create_ruleset`, `add_rule`, `restrict_self`, `seccomp`); the `landlock` crate's best-effort compatibility layer is exactly what the no-best-effort rule forbids; no new dependency or license review; all unsafe stays in `linux::sys`.
- **Alternatives**: `landlock` crate (best-effort defaults, extra dependency), `seccompiler` (pulls serde and its own arch tables; its x32 handling is equivalent).

## R2: Tier probe

- **Decision**: Landlock ABI and errata queried in the caller (no side effects); user namespaces probed in a forked child that runs `unshare(USER|NS|NET|IPC|UTS)`, writes the id maps, makes `/` private and mounts a tmpfs, then `_exit`s with a code. T1 = ABI ≥ 1 and that child succeeded; T2 = ABI ≥ 4; otherwise `Unsupported`. Cached per process (`OnceLock`).
- **Rationale**: matches KF-L03/L05/L12; probing in the caller would change its namespaces.
- **Alternatives**: boot-id file cache (left for receipts); reading `apparmor_restrict_unprivileged_userns` (diagnostic only, never decisive).

## R3: Identity and capabilities in the user namespace

- **Decision**: map the caller's uid and gid to themselves; deny `setgroups`; after the mounts, drop the bounding set, clear ambient, `capset` to zero.
- **Rationale**: exec as a non-zero uid clears capabilities anyway; explicit dropping also covers a root caller. With no capabilities, `umount` and remounts fail even before seccomp.

## R4: Mounts on T1

- **Decision**: no new root, no pivot. The host tree stays visible and Landlock restricts it. Mounts only: `Protect` → recursive bind of the path onto itself, then a read-only remount that keeps the locked flags (computed in the parent with `statvfs`); `Hide` → directory: read-only tmpfs `mode=000`; file: bind of `/dev/null` remounted read-only and `nodev`; `.git` pin → bind onto itself (a mountpoint cannot be renamed or removed: `EBUSY`); private `/dev/shm` → tmpfs. Applied shallowest first.
- **Rationale**: Landlock rules attach to inodes; a bind of a path onto itself keeps them. Bwrap-style new roots are not needed when Landlock is the file filter.
- **Measured before** (KF-L04, L05, L09, L11): `EROFS` through ro binds; tmpfs hides; a nested namespace cannot remount rw or unmount; mount topology changes are denied after Landlock.

## R5: seccomp filter

- **Decision**: classic BPF, built in the parent: check `arch` (kill on mismatch), on x86_64 kill `nr ≥ 0x40000000` (x32), then one block per rule: `ld nr; jeq` → condition on `args[n]` low 32 bits (`socket` family, `ioctl` cmd — the kernel truncates cmd to 32 bits, so this matches the TIOCSTI high-bit trick; `clone` flags with `jset`) → `RET_ERRNO|EPERM` or `ENOSYS`; default `ALLOW`. Blocks are independent, so jump offsets stay below 255.
- **Syscall numbers**: from `libc::SYS_*` per target; a syscall absent on the architecture (`fork`, `vfork` on aarch64) needs no rule; `Syscall::Other` names have no table and are `Unsupported`.
- **Tests**: a 40-line interpreter of the emitted subset (`ld abs`, `jeq`, `jset`, `ret`) checks verdicts per rule and per architecture.

## R6: Data classes on Linux

- **Decision**: the lowering checks whether any rule can reach a class path (component-wise prefix overlap of the rule path with the class pattern, `*` matching one component, `**` any). Not covered → exact (Landlock's default deny holds). Covered → T1 approximated (masks at spawn), T2 unsupported. On T1 the backend always masks existing home paths (cheap; grants may reach them) and walks every writable rule and grant root for the anywhere names and `.git`. On T2 it refuses a grant whose path overlaps a class path.
- **Walk**: `symlink_metadata`, never following links; a matched entry that is a link is mounted through (the mount protects its target, which only adds restriction); bound 200,000 entries per spawn (option); over the bound → `SpawnError::Walk`.
- **Homes**: `/root` and each directory under `/home`, plus the caller's `$HOME` when it is elsewhere.

## R7: Lowering changes

- Loopback and proxy networks: unsupported on both tiers (no relay yet).
- Unix-socket allowlist: exact at ABI ≥ 9, unsupported below.
- Hide on T2 and glob allow rules: unsupported.
- `signals: self-and-children`: exact at ABI ≥ 6 on both tiers, unsupported below (no PID namespace yet; `Namespaces.pid` false).

## R8: Tests in containers

- **Decision**: `just linux` runs `cargo test -p procage --lib --test spawn_linux --test unsafe_confined` in `rust:1.99` as uid 65534 under Docker defaults (expects T2), and `just linux-t1` with `seccomp=unconfined,apparmor=unconfined` (expects T1). `PROCAGE_EXPECT_TIER` makes a mismatch fail, never skip. Both added to `ci-all`. `just lint` also runs clippy for `aarch64-unknown-linux-gnu` and `x86_64-unknown-linux-musl`.
