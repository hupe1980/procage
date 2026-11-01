# procage Constitution

## Core Principles

### I. Fail closed, never silently weaker

A capability procage cannot enforce is a typed error, never a no-op or a
broader rule. This covers:

- a missing libsandbox symbol;
- an already-sandboxed parent;
- a profile over its limits;
- a construct a backend or Linux tier cannot express (`CapabilityGap`);
- a relative or unexpanded path;
- a failed post-apply check.

A degradation happens only when the caller allowed that construct by name, and
it is recorded in the receipt. Linux never uses Landlock BestEffort silently. A
child that cannot confirm it is caged never runs its target. `(with no-sandbox)`
and `(with no-profile)` cannot be expressed. The limits guard never broadens an
allow.

Checked by error-path tests, the lowering-table fixtures and the escape suite.

### II. Types over strings

- Policy is a two-layer IR: a portable intent layer, plus typed backend layers.
- Literal paths, subpaths, globs and SBPL regexes are distinct types, and a glob
  is never inferred from a string.
- Untrusted data reaches SBPL only through the one audited, fuzzed escaper or
  `(param …)`.
- Paths are byte-exact and never lossy.
- The default effect is deny.
- Every policy emits the hard-deny tier last. It can be waived only by class
  name, and every waiver is recorded.

Checked by property tests and fuzz targets in `procage-policy`, and by
differential compilation through libsandbox.

### III. The kernel is the oracle

No claim about enforcement — in rustdoc, the README, a spec or a concept — is
made without a test that runs a caged child on a real kernel and observes the
outcome. Comparing emitted SBPL or BPF is not evidence of enforcement. `explain`
must agree with the kernel for every operation proven reliable. Findings carry
the date and the macOS build or kernel release they were measured on.

Enforcement tests that hit `AlreadySandboxed` (for example inside an agent's
own sandbox) **fail**; they never skip.

Checked by the CI matrix (macOS lanes; Linux T1 and T2 lanes) and the escape
suite: one canary per escape class in `crates/procage/THREAT_MODEL.md`.

### IV. Syscalls only between fork and exec; unsafe in `sys` only

`unsafe_code` is forbidden everywhere except `procage::macos::sys` and
`procage::linux::sys`, and every `unsafe` block carries a `SAFETY:` comment.

Code that runs in the child between `fork` and `execve` issues syscalls only:

- no allocation, no locks, no `dlsym`, no libsandbox calls that are not proven
  to be syscalls;
- everything it needs is prepared in the parent.

The plan that introduces such code lists its full call sequence, and a test
covers it with a multithreaded parent.

Checked by lints, review of the `sys` modules, and the multithreaded spawn
tests.

### V. Hygiene by default

A caged child receives:

- only stdio and the fds the caller declared;
- an environment built from an allowlist;
- no inherited controlling terminal, unless the caller asked for one;
- rlimits.

The child and its descendants do not outlive the run. A helper binary that
procage executes is write-protected by every policy and digest-checked before
use.

Checked by escape-suite canaries for fds, env, tty, lifetime and helper integrity.

### VI. Private interfaces, honestly

libsandbox's compile, apply and extension symbols are undocumented. procage:

- resolves them at runtime, before any fork;
- probes them before first use;
- surfaces their absence as `Unsupported`.

Linux capabilities are probed, never inferred from `uname`. The public docs
state these dependencies, the threat model and the non-goals.

Checked by the probe tests and rustdoc review.

### VII. A library, not a harness

- **Allowed global state**: the resolved symbol table, the probe results, the
  in-memory compile cache, the run-marker slots (a per-process prefix and the
  slots in use, so concurrent runs stay apart without defeating the cache)
  and the violation monitor. Nothing else.
- **No async runtime required**: tokio sits behind a feature.
- **Overridable defaults**: safe presets by default, but no opinion the caller
  cannot override, and every override is recorded.
- **Presets are versioned and frozen**: loosening one is a breaking change.
- **Toolchain**: edition 2024, MSRV 1.99.
- **`procage-policy`** stays portable, `no_std` + `alloc`, and free of `unsafe`.
- **Breaking changes** ship with a migration note for consumers.

Checked by the MSRV, feature-matrix and `no_std` jobs, `cargo-semver-checks`
and `cargo-deny`.

## Development Workflow

- **One change, one spec.** Each coherent change has one numbered
  `specs/NNN-slug/spec.md`.
- **Spec Kit sequence**: specify → clarify when needed → plan → tasks → analyze
  → implement → converge.
- **Plans** check every principle above and name their evidence and their
  remaining gaps. Principles I and V cannot be waived by a complexity
  justification.
- **Design records are public; notes are private.** `specs/` and `.specify/`
  are published as design records: each stands alone, names no consumer
  project and points to no private note. Private notes, `.claude/` and
  `CLAUDE.md` stay local. The crates never cite planning files; README and
  the site may link the records. The planning-paths gate checks all of it.
- **Decisions follow the code.** If implementation changes a design decision,
  the change records it, with its reason, in the same commit.
- **Tests.** Run focused tests after each change, and `just ci` before merging.
- **Authorization.** Do not create commits, branches, tags or releases without
  the user's authorization. Releases go through crates.io Trusted Publishing only.

## Governance

This constitution governs new plans. Amendments state the changed rule, its
evidence and the affected specifications. Major versions remove or redefine a
principle, minor versions add material guidance, and patch versions clarify
wording.

2.0.0 (2026-10-27) makes Linux first-class and adds principle V (hygiene). It
redefines IV (syscalls only; path C removed) and I (typed capability gaps).

2.1.0 (2026-10-31) adds the run-marker slots to VII's allowed global state.
Evidence: a per-run marker must differ between concurrent runs, and a
per-cage or per-spawn marker recompiles the profile (~7 ms against a ~2 ms
cached spawn). Affects spec 024-lifetime.

2.2.0 (2026-11-01) publishes the design records: `specs/` and `.specify/`
are tracked, stand alone and name no consumer; private notes stay local.
Evidence: the records are procage's evidence for its claims (threat models,
measurements, verification). Affects every specification (rewritten, spec
037-public-design-records).

**Version**: 2.2.0 | **Ratified**: 2026-10-27 | **Last Amended**: 2026-11-01
