# Contract: `procage::windows`

The public shape follows `procage::linux` and `procage::macos`. Code
written against `procage::native` compiles on all three OSes; differences
are listed.

```rust
pub mod windows {
    pub struct Cage;
    impl Cage {
        pub fn new(policy: &Policy) -> Result<Cage, SpawnError>;
        pub fn with_options(policy: &Policy, options: &CageOptions) -> Result<Cage, SpawnError>;
        pub fn fit(policy: &Policy, options: &CageOptions, relax: &Relax) -> Result<(Cage, Vec<Relaxed>), SpawnError>;
        pub fn plan(&self) -> &WindowsPlan;
        pub fn features(&self) -> WindowsFeatures;
        pub fn explain(&self, op: explain::Op, path: impl AsRef<Path>, grants: &Grants) -> Result<explain::Answer, SpawnError>;
        pub fn spawn(&self, command: &mut Command, grants: &Grants) -> Result<Child, SpawnError>;
        /// Windows form of `spawn_with_fds`.
        pub fn spawn_with_handles(&self, command: &mut Command, grants: &Grants,
                                  handles: &[BorrowedHandle<'_>]) -> Result<Child, SpawnError>;
        /// Always `SpawnError::Unsupported(Unsupported::NoExec)`.
        pub fn exec(&self, command: &mut Command, grants: &Grants) -> SpawnError;
        pub fn exec_session(&self, command: &mut Command, grants: &Grants) -> SpawnError;
    }
    pub struct CageOptions;   // with_lower, with_policy_in_receipt, with_proxy (feature),
                              // with_violations → gap at construction
    pub struct Grants;        // bind(name, path); resolved again at every spawn
    pub enum GrantError { …, Link { path: PathBuf } }   // a reparse point inside a writable tree (SR-016)
    pub struct Child;         // id, wait, try_wait, kill_all, receipt, stdin/stdout/stderr
    pub enum Unsupported { NoSecurityEnvironment, UntestedVersion { major: u16, minor: u16 },
                           MissingFeature(&'static str), AlreadySandboxed, UnsupportedOs { build: u32 }, NoExec }
    pub enum SpawnError { Unsupported(Unsupported), Lower(LowerError), Grant(GrantError),
                          Apply { step: Step, hresult: i32 }, Io(io::Error) }
    pub enum Step { Environment, Job, Attributes, Create, Assign, Verify, Resume }
    /// `C:\x` ↔ `/C:/x`; resolves to the final long path, refuses UNC,
    /// device paths and case-sensitive directories.
    pub fn abs_path(path: &Path) -> Result<AbsPath, PathError>;
}
#[cfg(windows)] pub use windows as native;
```

## procage-policy

```rust
#[non_exhaustive]
pub enum Target { MacOs, Linux { tier: Tier, landlock_abi: u8 }, Windows { features: WindowsFeatures } }
pub fn lower(policy: &Policy, target: Target, options: &LowerOptions) -> Result<Plan, LowerError>;
// Plan::Windows(WindowsPlan) beside Plan::Seatbelt and Plan::Linux; Plan becomes #[non_exhaustive] too.
// Construct::ExecWhereReadable: the named approximation.
```

## Receipts

`Receipt.target` gains `"windows"` with `build`, `schema` (`"1.1"`),
`features` (the flags), and `base` (`"windows-base-1"`). The receipt JSON
format stays version 1; the fields are additive (SR-002).
