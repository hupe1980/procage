# Research: explain and diff

Decided 2026-11-02 by the scope rule (best-in-class, no overengineering).

## R1. Which operations

- **Decision**: read (open for reading), write (open an existing file for
  writing), exec. Everything else is `NotModelled`.
- **Rationale**: these are what a failed command most often hit, and a
  caged child can prove each on every target with one `open` or `execve`.
  Create, unlink, rename and metadata differ per target in ways (parent
  directory rights, Seatbelt's metadata rules) that need their own oracle.
- **Alternatives rejected**: the eleven operations of the first draft
  (each needs a separate oracle path; none blocks 0.2.0).

## R2. The macOS model

- **Decision**: evaluate the emitted rules in profile order; the last
  matching rule decides, the default denies. Read is `file-read-data`,
  write `file-write-data`, exec `process-exec`. A rule op matches by name or
  by `*` prefix. Rules are taken from the lowering before reasons are
  stripped and before merging: within a block every rule has the same
  effect, so the order inside a block and merging change no decision.
- **Rationale**: one source of truth with the profile; no SBPL parser.
- **Alternatives rejected**: parsing the rendered profile (a second
  representation to keep in step); `sandbox_check` (a private call whose
  reliability per operation would need its own kernel facts).

## R3. The regex subset

- **Decision**: a Thompson NFA over bytes for what the lowering emits:
  `^`, `$`, literals and `\` escapes, `.`, bracket classes with ranges and
  negation, groups with `|`, `*`, `+`, `?`, `{m,n}`. Anything else is a
  parse error, which makes the answer `NotModelled`. Linear in path length
  times pattern size.
- **Alternatives rejected**: the `regex` crate (a dependency, not `no_std`
  by default); backtracking (not linear).

## R4. The Linux model

- **Decision**: rights per operation (`READ_FILE`, `WRITE_FILE`,
  `EXECUTE`); a right the ruleset does not handle is allowed; otherwise the
  union of covering rules decides. On T1, masks (hide) and read-only binds
  (protect) deny over Landlock; class paths in the context's homes and
  system paths, and the `anywhere` names under writable trees, deny with
  the caveat "covered if it exists at spawn". On T2 the piecewise hides and
  hidden classes deny with the piecewise caveat. The deciding Landlock rule
  is attributed to the policy rule, grant, layer entry or base it came from.
- **Rationale**: the plan is authoritative; the attribution only names it.

## R5. Remedy

- **Decision**: repeat at most three times: take the narrowest change for
  the deciding rule (a literal rule of the asked access for the default or
  a base, a waiver for a hard-deny class, removing a protect or hide rule),
  re-lower and re-ask. Approximations the new rule needs are accepted by
  name and listed. The remedy carries the diff of the change, so it names
  everything else it flips. No remedy when nothing flips.
- **Alternatives rejected**: suggesting a subpath grant (broader than the
  question); suggesting without verifying.

## R6. Diff

- **Decision**: per target, the multiset difference of the tagged rules
  (macOS) or of the Landlock rules, mounts, classes and seccomp rules
  (Linux). An added allow or a removed deny loosens; the opposite
  tightens. Every other plan field that differs, and the base, preset tag
  and waivers, are listed as changed settings. No pattern intersection, so
  there is no pair bound: sorting dominates.
- **Rationale (soundness)**: an answer changes only if the sequence of
  rules matching the question changes, so some added or removed rule
  matches it; if it became allowed, either the new deciding allow was added
  or a later deny that matched before was removed — both entries loosen.
  The same holds for a union of allows plus denying mounts.

## R7. Oracle

- **Decision**: caged children on every lane. One child per policy and
  target opens every read and write question (`O_RDONLY`, `O_WRONLY`
  without `O_TRUNC`, nothing written) and prints the errno; exec questions
  are caged spawns of copies of `true`. 0 is allowed; `EACCES`, `EPERM`,
  `EROFS` are denied; anything else, including `ENOENT` for a file the
  generator made, is unresolved and fails. Write questions are asked only
  of files the test owns and `/dev/null`. The policy under test is the
  preset plus exec of the test binary, and that is what is explained.
- **Rule-kinds coverage**: a kinds policy per target adds protect (macOS,
  T1), hide, a grant, `.git/hooks` and home class paths (Linux homes are
  the test's own, passed with `with_home`), so allow, protect, hide,
  hard-deny class, base, default, grant and T1 cover are all reached.
