# Data model: explain and diff

All types live in `procage_policy::explain`.

| Type | Fields / variants | Rules |
|---|---|---|
| `Op` | `Read`, `Write`, `Exec`, `Other(String)` | `MODELLED` lists the first three; `Other` (a Seatbelt operation or Landlock right name) always answers `NotModelled` |
| `Question` | `op`, `path: Vec<u8>`, `mode: u32` (default `0o644`; `0o755` for exec) | The path must be canonical for the target (FR-005, SR-006) |
| `Context` | `grants: Vec<(GrantName, AbsPath)>`, `homes: Vec<AbsPath>` | Grants as bound at spawn; homes used on Linux only |
| `Decision` | `Allowed`, `Denied`, `NotModelled` | |
| `Decider` | `Rule(FsRule)`, `Grant(GrantName)`, `HardDeny(HardDenyClass)`, `Base(Base)`, `Layer`, `Setting(&'static str)`, `Unhandled`, `Default`, `None` | `None` only with `NotModelled` |
| `Answer` | `decision`, `by: Decider`, `caveat: Option<&'static str>`, `remedy: Option<Remedy>` | A remedy only for `Denied` |
| `Remedy` | `changes: Vec<Change>`, `accept: Vec<Construct>`, `diff: Diff` | Verified to flip the question |
| `Change` | `Add(FsRule)`, `Remove(FsRule)`, `Waive(HardDenyClass)` | |
| `PathSet` | `Every`, `Literal`, `Subpath`, `Regex`, `Ancestors`, `Grant`, `Class`, `Glob` | `contains(path, ctx)` uses the evaluator's matchers |
| `Direction` | `Loosens`, `Tightens` | |
| `DiffEntry` | `target`, `direction`, `ops: Vec<Op>`, `paths: PathSet`, `by: Decider` | `covers(op, path, ctx)` |
| `Diff` | `entries`, `settings: Vec<(Target, &'static str)>` | Empty means the plans decide every question alike |
| `ExplainError` | `NotCanonical { canonical: Option<AbsPath> }` | `None` for a relative path |

`Explainer::new(policy, target, options) -> Result<Explainer, LowerError>`
lowers once; `explain(&Question, &Context) -> Result<Answer, ExplainError>`.
`diff(a, b, targets, options) -> Result<Diff, LowerError>`.
