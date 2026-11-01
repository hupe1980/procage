# Research: 007-hard-deny-and-presets

macOS 26.6.2 (25G83), 2026-10-30.

## R1. Case

- **Volume**: the volume is case-insensitive (`ls cf/ABC` finds `cf/abc`).
- **Existing files**: an unfolded deny on `.ssh` in any home under `/Users` (an anchored regex) also
  denied `~/.SSH`, and so did a `subpath` deny. The kernel matches the
  on-disk name.
- **New names**: an unfolded write deny on `\.zshrc$` also denied *creating*
  `.ZSHRC`. On this volume, Seatbelt matches case-insensitively for new
  names too.
- **Decision**: emit case-folded patterns anyway (`[sS][sS][hH]`). They cost
  nothing and stay correct if that kernel behaviour changes. Folded regexes
  compile.

## R2. Pattern representation

- **Decision**: fixed globs in `procage_policy::presets`:
  - home paths: `<rel>/**` under every home in `/Users` (the trailing `/**` also matches the path
    itself);
  - names that apply anywhere: `/**/<name>/**`.

  They are compiled by `Glob::to_sbpl_regex_folded()`, a new method that
  turns every ASCII letter into a `[xX]` class.

  Emission:
  - `secrets`: `(deny file-read* file-write* (require-any (regex …)…))`;
  - `trust-handoff`: `(deny file-write* …)` plus
    `(deny file-write-unlink (regex "^(.*/)?\.[gG][iI][tT]$"))`;
  - `persistence`: `(deny file-write* …)`.

  All are emitted in the hard-deny block.

## R3. Rename around a pattern

- **The bypass**: `mv .git z; edit z/hooks/pre-commit; mv z .git`.
- **Decision**: deny `file-write-unlink` of `.git`. Renaming a directory is
  checked as an unlink of the source (the rename-anchor class relies on the
  same). Tested: `mv .git z` is refused.

## R4. Presets

- **Decision**: `procage_policy::presets::{minimal, agent_readonly,
  agent_workspace, build}::v1(…)` return a `Policy` with `preset:
  Some(PresetTag { name, version: 1 })`.
- **Pinning**: the lowered macOS profile of each preset, with workspace
  `/work`, is pinned as a fixture file in
  `crates/procage-policy/tests/fixtures/presets/`.

## R5. Linux

- **Decision**: the Linux cells of the three classes are `n/a`, with the
  note "not yet expressible on Linux; the Linux spawn backend (008) must
  mask them at spawn before it ships". The 008 spec carries this.
- **Rationale**: Landlock cannot deny inside a granted tree, T1 masks are
  set up at spawn, and no Linux spawn exists yet to observe either.
