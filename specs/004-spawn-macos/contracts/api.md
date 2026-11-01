# Contract: `procage::macos` (development version 0.0.2)

```rust
pub use procage_policy as policy;                 // root re-export

#[cfg(target_os = "macos")]
pub mod macos {
    pub struct Cage;
    impl Cage {
        pub fn new(policy: &Policy) -> Result<Cage, SpawnError>;
        pub fn with_options(policy: &Policy, options: &CageOptions) -> Result<Cage, SpawnError>;
        pub fn spawn(&self, command: &mut std::process::Command, grants: &Grants)
            -> Result<std::process::Child, SpawnError>;
        pub fn plan(&self) -> &SeatbeltPlan;
        pub fn rewrites(&self) -> &[PathRewrite];
        pub fn compiled(&self) -> bool;
    }
    pub struct CageOptions;  // Default; with_lower(LowerOptions), with_compile_limit(usize)
    pub struct Grants;       // new(), bind(name: &str, path: impl AsRef<Path>) -> Grants
    pub fn probe() -> Result<ApplyMethod, SpawnError>;
    pub fn is_sandboxed() -> Result<bool, SpawnError>;
    pub enum SpawnError { … }   // see data-model.md
}
```

Behaviour:
- `Cage::new` resolves paths, lowers, applies the compile limit, compiles (or
  takes the result from the cache), and refuses `Tty::NewPty`.
- `spawn` does the following, in order:
  1. resolve the symbol table;
  2. check `is_sandboxed()` → `AlreadySandboxed`;
  3. run the probe;
  4. resolve the grants and issue their tokens;
  5. build the environment;
  6. install `pre_exec`;
  7. call `Command::spawn`.

  An apply failure decodes into `Apply { step, errno }`. Other spawn I/O
  errors are `Io`.
