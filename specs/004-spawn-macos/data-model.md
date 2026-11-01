# Data model: 004-spawn-macos

All in `procage::macos` (`cfg(target_os = "macos")`).

| Type | Fields / variants | Notes |
|---|---|---|
| `Cage` | `plan: SeatbeltPlan`, `bytecode: Arc<[u8]>`, `rewrites: Vec<PathRewrite>`, `compiled: bool`, `grants: Vec<GrantSlot>`, `hygiene: Hygiene` | `Send + Sync`; reusable; `Cage::new(&Policy)`, `Cage::with_options(&Policy, &CageOptions)`, `spawn(&self, &mut Command, &Grants)` |
| `CageOptions` | `lower: LowerOptions`, `compile_limit: usize = 2000` | `#[non_exhaustive]`, builder methods |
| `PathRewrite` | `from: String`, `to: String` | display text of the spellings |
| `Grants` | `BTreeMap<String, PathBuf>` | `new()`, `bind(name, path) -> Self` |
| `ApplyMethod` | `PathA` | `probe() -> Result<ApplyMethod, SpawnError>` |
| `Step` | `Session = 1`, `Rlimit = 2`, `Apply = 3`, `Verify = 4`, `Consume = 5` | the in-child sequence |
| `Unsupported` | `Symbol { symbol, os_build }`, `ApplyMethod { os_build, detail }`, `Setting { setting }` | |
| `GrantError` | `Undeclared { name }`, `Missing { name, path, error }`, `Issue { name, path }` | |
| `SpawnError` | `Unsupported(Unsupported)`, `AlreadySandboxed`, `Lower(LowerError)`, `Path { path, error }`, `Compile { message }`, `LimitExceeded { limit, rules }`, `Grant(GrantError)`, `Apply { step, errno }`, `Io(io::Error)` | `Display`, `Error`, `source()` |

Invariants:
1. No child runs its target unless steps 1–5 succeeded.
2. The cache holds `(profile, params) → bytecode` in memory only.
3. Every spawn binds tokens of class `procage.<name>` only for declared grants.
4. The step code is `0x5043_0000 | step << 12 | errno`; the probe marker is
   step `0xE`.
