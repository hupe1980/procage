# Contract: `procage::linux` (cfg target_os = "linux")

```rust
pub fn probe() -> &'static Probe;
pub struct Probe { pub tier: Option<Tier>, pub landlock_abi: u8, pub errata: u32, pub userns_errno: Option<i32> }

pub struct CageOptions { pub lower: LowerOptions, pub tier: Option<Tier>, pub walk_limit: usize, pub homes: Vec<PathBuf> } // #[non_exhaustive], with_lower/with_tier/with_walk_limit/with_home
// homes: home directories besides /root, /home/* and $HOME (checked by the backend, masked on T1)
pub const BACKEND_MAX_ABI: u8 = 8; // Landlock rights beyond ABI 8 are not used until verified on a kernel
pub struct Cage; // Clone, Debug
impl Cage {
    pub fn new(&Policy) -> Result<Cage, SpawnError>;
    pub fn with_options(&Policy, &CageOptions) -> Result<Cage, SpawnError>;
    pub fn plan(&self) -> &LinuxPlan;
    pub fn tier(&self) -> Tier;
    pub fn spawn(&self, &mut Command, &Grants) -> Result<Child, SpawnError>;
    pub fn spawn_with_fds(&self, &mut Command, &Grants, &[BorrowedFd]) -> Result<Child, SpawnError>;
}
pub struct Grants; // new(), bind(name, path) — same as macOS
pub struct Child;  // Deref<Target = std::process::Child>, kill_all, detach, dropped_env, tmpdir
pub enum Step { Session, Lifetime, Namespaces, IdMap, Mounts, Capabilities, Rlimit, Fds, NoNewPrivs, Landlock, Seccomp, Verify }
pub enum Unsupported { Landlock { abi: u8, needed: u8 }, Tier { requested: Tier, userns_errno: Option<i32> }, Syscall { name: String }, Setting { setting: &'static str } }
pub enum GrantError { Undeclared, Missing, Reserved, CoversClass { name, class } }
pub enum SpawnError { Unsupported, Lower, Path { path, error }, Grant, Fd, Tmpdir, Walk { root, limit }, Apply { step, errno }, Io }
pub const TMPDIR_GRANT: &str = "tmpdir";
```
