# Feature Specification: Portable policy IR and its lowering to each backend

**Feature Branch**: `003-policy-ir`

**Created**: 2026-10-30

**Status**: Shipped in 0.1.0 (2026-11-01)

**Input**: User description: "003-policy-ir: `procage-policy`: intent layer, backend layers, `AbsPath`, glob compiler, escaper, SBPL lowering, Linux plan lowering, `CapabilityGap`, limits guard, serde schema, fuzz targets; lowering table as fixtures."

## Context

procage will cage a child process on macOS (Seatbelt) and on Linux (Landlock,
seccomp and namespaces). Before anything can be applied to a child, a caller
needs one way to say what the child may do, and procage needs to turn that
statement into what each backend understands. Today the policy crate is an
empty placeholder.

The tools procage learns from failed in exactly this layer:

- a resolved path whose characters were read as glob syntax (a published
  Seatbelt escape);
- quoting that let a quote character inside a path end the string early;
- a path rule that was silently ignored because it was relative;
- a lower Linux sandbox that was used silently in place of the one asked for;
- a size limit that crashed the host process.

This feature builds the portable half of procage:

- a policy written once, as data, in two layers: a portable **intent layer**
  and typed, opt-in **backend layers**;
- its **lowering** to a Seatbelt profile and to a Linux plan for each tier.
  Any construct a target cannot express comes back as a typed **capability
  gap**, never a weaker rule.

It applies nothing to any process. Applying, and therefore every enforcement
claim, belongs to the macOS and Linux spawn features (004, 008) and to the
escape suite (009).

Readers are procage's own spawn backends (the first consumer), harness authors
who will build policies, procage's maintainers and its CI.

## Clarifications

### Session 2026-10-30

- Q: Is hiding a subtree on Linux T1, where the child sees "not found" instead of "permission denied", an exact lowering or an approximation? → A: Exact. The child can neither read nor write the subtree on either target. The lowering table notes the different error code.
- Q: How does a glob lower for Linux, which has no native pattern rules? → A: As the approximation "expanded at spawn": the plan carries the glob for the spawn backend to expand into path rules when it spawns. Files created later are not covered. It is a gap unless the caller allows it by name.
- Q: How is a path that is not valid UTF-8 written in the data format? → A: As text when the bytes are valid UTF-8, otherwise as a list of byte values. Both forms read back to identical bytes, and the writer always picks the text form when it can.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Write a policy once and get an exact plan, or a typed reason why not (Priority: P1)

A harness author describes what a child may do:

- file access by path, of a chosen kind: read, write, execute, protect a
  subtree as read-only, or hide one;
- network: none, loopback ports, named unix sockets, a proxy, or everything;
- process creation and signals, and inter-process communication;
- the child's environment, resource limits and terminal;
- a fixed final tier of hard denies;
- named slots for paths that are bound per spawn ("grants").

The author asks for that policy to be lowered for macOS, or for Linux at a
given tier and Landlock version. They get back either a complete plan for that
target, or the full list of constructs the target cannot express exactly, each
naming the construct, the target and the reason. A construct that can only be
approximated is accepted only when the author allowed that construct by name.
Each such approximation is listed in the plan.

**Why this priority**: This is the product. Without a single portable policy
that lowers exactly or fails with a typed reason, each backend would accept a
different language, and gaps would silently become weaker sandboxes, the
failure the project exists to prevent.

**Independent Test**: Lower a set of reference policies for every target.
Every construct produces the outcome its row in the published lowering table
states: exact, approximated (only with permission), or a gap. No target ever
returns a plan with fewer restrictions than the policy asked for, unless the
caller allowed it.

**Acceptance Scenarios**:

1. **Given** a policy granting read access to one directory and nothing else,
   **When** it is lowered for macOS, Linux T1 and Linux T2, **Then** each
   returns a plan, and each plan denies by default and grants exactly that
   directory for reading.
2. **Given** a policy that protects a subtree as read-only inside a writable
   directory, **When** it is lowered for Linux T2, **Then** lowering fails
   with a gap naming that construct, Linux and tier T2, and no plan is
   returned.
3. **Given** the same policy and the caller has *not* allowed any
   degradation, **When** lowering fails, **Then** the error lists every gap in
   the policy, not only the first.
4. **Given** a policy with a single-file rule, **When** it is lowered for Linux
   with the caller allowing the "single file" approximation by name, **Then**
   a plan is returned, and its list of degradations names that construct.
5. **Given** any construct of the lowering table, **When** the table's row is
   compared with the lowering's actual outcome for every target, **Then** they
   agree. A changed outcome without a changed table fails the test suite.

---

### User Story 2 - Untrusted path data can never change what a policy means (Priority: P1)

Paths in a policy usually come from untrusted places: a workspace directory
named by a user, a repository checked out from the internet, a temporary
directory. A path may contain quote characters, backslashes, parentheses, glob
characters (`*`, `?`, `[`), regular-expression characters, very long names, or
bytes that are not text. Whatever it contains, the lowered output treats it as
exactly that one path, and never as syntax. A relative path or one starting
with `~` is refused. A pattern only exists when the author built one as a
pattern on purpose. A raw backend rule cannot express the Seatbelt modifiers
that switch the sandbox off for the next program.

**Why this priority**: These are the escape classes R-02 (a non-canonical path
rule silently does nothing), R-03 (glob characters in resolved paths widen a
rule) and R-11 (`(with no-sandbox)` reaches a profile). A single quoting bug
here turns every downstream policy into an escape.

**Independent Test**: Feed adversarial paths and patterns through every
emitting function. A test decoder reads each emitted string back to exactly
the original bytes. No input yields an unbalanced quote, an unescaped pattern
character, or extra profile syntax. The same properties hold under
coverage-guided fuzzing.

**Acceptance Scenarios**:

1. **Given** a directory named `/tmp/a"b(c)*?[d]`, **When** a policy grants it
   by subtree and is lowered for macOS, **Then** the profile contains exactly
   one subtree rule whose quoted string decodes to that exact name.
2. **Given** the text `relative/dir` or `~/dir` or `/a/../b`, **When** it is
   used as a policy path, **Then** it is refused with a typed error naming the
   reason. Nothing is silently resolved.
3. **Given** a glob `/work/**/*.rs` built as a glob, **When** it is lowered for
   macOS, **Then** it becomes one anchored pattern in which every character
   outside the glob syntax is escaped.
4. **Given** a path containing a control character such as a newline, or bytes
   that are not valid UTF-8, **When** it is lowered for macOS, **Then**
   lowering fails with a typed error. The path is neither dropped nor altered.
5. **Given** a raw backend operation name containing a parenthesis, a space or
   a quote, **When** it is constructed or deserialised, **Then** it is
   refused, so no raw rule can carry `(with no-sandbox)` or `(with
   no-profile)`.

---

### User Story 3 - Large policies fail closed instead of crashing or widening (Priority: P2)

A harness builds a policy with thousands of rules, or with a path longer than
the profile language accepts in one string. The lowering either produces a
profile within the configured limits, or fails with a typed "limit exceeded"
error that names the limit and the size. A path that is too long for one
inline string is passed by reference (a profile parameter) instead of being
cut. Any rewrite the guard applies to shrink a profile matches exactly the
same requests as before. It never matches more.

**Why this priority**: libsandbox aborts its calling process on very large
profiles, rejects string literals of about 1 KiB, and caps bytecode at
64 KiB. These were measured on macOS 26.6.2. A policy layer that crashes the
harness, or "fixes" size by merging rules into broader ones, breaks
constitution principle I.

**Independent Test**: Lower policies just under and just over the configured
rule limit, and with paths just under and over the inline string limit.
Compare a policy against its guarded rewrite with a reference evaluator over
generated requests. The decisions are identical in every case.

**Acceptance Scenarios**:

1. **Given** a policy whose profile would exceed the configured rule limit,
   **When** it is lowered for macOS, **Then** lowering fails with "limit
   exceeded" naming the limit and the actual count.
2. **Given** a path whose quoted form exceeds the inline string limit, **When**
   it is lowered for macOS, **Then** the profile refers to a named parameter,
   and the plan carries that parameter's exact value.
3. **Given** many adjacent rules with the same effect and operation, **When**
   the guard merges them, **Then** for every generated request the merged
   profile decides exactly as the unmerged one did.

---

### User Story 4 - Policies are data that survive storage and transport unchanged (Priority: P2)

A harness stores a policy in a configuration file or sends it to another
process, and reads it back. The read policy is equal to the written one. On
reading, invalid values are refused with an error: a relative path, an
unknown field, a malformed glob, an unknown operation name. An unknown field
is never silently ignored, because it might be a restriction the reader would
drop.

**Why this priority**: Policies will be written by harness configuration,
compared, and recorded in receipts. A lossy or permissive format would drop
restrictions without notice.

**Independent Test**: Round-trip every reference policy through the
serialised form and compare. Feed malformed documents and check each is
refused with a typed reason.

**Acceptance Scenarios**:

1. **Given** any reference policy, **When** it is serialised and read back,
   **Then** it is equal to the original, including paths that are not valid
   UTF-8.
2. **Given** a document with a field the schema does not define, **When** it
   is read, **Then** reading fails and names the field.
3. **Given** a document with a relative path or a malformed glob, **When** it
   is read, **Then** reading fails with the same error the constructor would
   give.

---

### Edge Cases

- A policy with no rules at all lowers to a plan that denies everything,
  apart from the hard-deny tier, which is always present.
- The same path appears in an allow rule and a protect or hide rule. The
  deny-within-allow rule wins on every target that can express it. On T2
  (Landlock alone) the result is a gap, never "allow wins".
- Rules are given in an arbitrary order. The lowered profile's order follows
  fixed precedence: allows, then protect or hide, then the hard-deny tier last.
  Shuffling the input order does not change the plan.
- Two rules for the same path and access kind are deduplicated without
  changing meaning.
- The root directory `/` is a valid path. A trailing slash and repeated
  slashes are refused, rather than normalised in a way the caller did not see.
- A glob with no wildcard at all is still a glob. It is not silently turned
  into a literal.
- Loopback on all ports and loopback on named ports lower to different
  rules on macOS. On Linux neither can be confined to the loopback address
  (Landlock filters ports, not addresses), so both are an approximation on T1
  and a gap on T2. Neither is ever widened to "all network".
- A Landlock version below the minimum a tier needs (T2 needs version 4 or
  higher) is refused for that tier with a typed error. Lowering never falls
  back to a lower tier.
- A hard-deny class can be waived only by naming it. The waiver appears in
  the plan, and an unknown class name is refused.
- A grant name that is not a short identifier (it contains a quote, a space or
  a slash) is refused, because it becomes part of an extension class name.

## Requirements *(mandatory)*

### Functional Requirements

**Paths and patterns**

- **FR-001**: The policy MUST represent a filesystem path as exact bytes. It
  MUST refuse, with a typed error, a path that:
  - is empty or relative, or starts with `~`;
  - contains `.` or `..` components, an empty component (`//`) or a NUL byte;
  - ends in `/`, unless it is `/` itself.
  A path MUST never be altered lossily.
- **FR-002**: A single-file path, a subtree, and a glob MUST be distinct kinds,
  chosen explicitly by the author. No construct may infer a pattern from text.
- **FR-003**: A glob MUST support `*` (any characters within one path
  component), `**` (any number of whole components), `?` (one character
  within a component) and a backslash escape for a literal wildcard
  character. Any other wildcard syntax (`[`, `{`) MUST be refused with a typed
  error rather than taken literally or guessed. A glob MUST be absolute.
- **FR-004**: When lowered for macOS, a glob MUST become one pattern anchored
  at both ends, in which every character that is not glob syntax is escaped.

**Escaping (Seatbelt)**

- **FR-005**: Every path, name and pattern text that reaches the Seatbelt
  profile MUST pass through one quoting function, or MUST be passed as a
  named profile parameter. That function:
  - escapes `"` and `\`;
  - refuses NUL, control characters (U+0000–U+001F, U+007F) and bytes that
    are not valid UTF-8, with a typed error.
- **FR-006**: A quoted value whose quoted form is longer than the inline limit
  (1016 bytes, below the ~1023-byte cap measured on 26.6.2) MUST be emitted as
  a reference to a named parameter. The plan MUST carry that parameter's exact
  value.

**Intent layer**

- **FR-007**: The intent layer MUST express:
  - file rules: access read, write (implies read), execute (implies read),
    protect (read-only inside a writable tree) or hide (neither readable nor
    writable inside a readable tree), each targeting a single file, a
    subtree or a glob;
  - network: none; loopback (all ports or listed ports); named unix sockets;
    a proxy at loopback ports; or all;
  - process: execution (allowed, denied, or limited to listed paths), forking
    (yes or no) and signals (self and children, or none);
  - inter-process communication: POSIX shared memory and System V IPC, each
    allowed or not;
  - environment (an allowlist, or passthrough with a denylist), resource
    limits and terminal mode. These are carried into the plan unchanged for
    the spawn backends;
  - hard-deny classes and named waivers;
  - named grants with an access kind.
- **FR-008**: The default effect of every policy MUST be deny, and the intent
  layer MUST have no way to express allow-by-default.
- **FR-009**: Every lowered plan MUST include the hard-deny tier last, minus
  only the classes the policy waived by name. Each waiver MUST be listed in
  the plan. This feature MUST provide the hard-deny classes whose content is
  fixed and needs no data file:
  - the fcntl modification trick;
  - setuid/setgid writes and setuid execution;
  - handing work to unsandboxed services (Launch Services, Apple events,
    pasteboard and XPC services, on macOS);
  - task ports and process introspection outside the sandbox;
  - rename anchors for protected paths;
  - on Linux, the syscall and socket-family denies (io_uring, ptrace,
    process_vm_*, keyctl, bpf, perf_event_open, userfaultfd, namespace
    creation, AF_VSOCK and AF_NETLINK, TIOCSTI and TIOCLINUX).
  Data-driven classes (secrets, trust handoff, persistence, procage's own
  files) are added by later features.

**Backend layers**

- **FR-010**: A typed Seatbelt layer MUST let an author add raw rules with an
  effect, an operation from a closed list, and typed filters. Each operation
  name in the list MUST be proven to compile on this Mac's libsandbox. An
  operation name outside the list MUST be available only behind an
  explicitly unstable option. It MUST be accepted only if it consists of
  lowercase letters, digits, `-` and `*`.
- **FR-011**: No value of the Seatbelt layer, including deserialised values,
  can produce `(with no-sandbox)`, `(with no-profile)` or any modifier other
  than the run tag (`with message`).
- **FR-012**: A typed Linux layer MUST let an author add extra syscall denies
  and extra Landlock path rules. Both MUST be checked against the same tier and
  version rules as the intent layer.

**Lowering**

- **FR-013**: Lowering MUST take a policy, a target and options:
  - the target is macOS, or Linux with tier T1 or T2 and a Landlock version;
  - the options include the constructs the caller allows to degrade, by name.
  Lowering MUST return either a plan or the complete list of capability gaps.
  Each gap names the construct, the target, the tier where relevant, and the
  reason.
- **FR-014**: An approximated construct MUST be a gap unless the caller
  allowed that construct by name. When allowed, the plan MUST list it as a
  degradation.
- **FR-014a**: On Linux, a glob MUST lower to the approximation "expanded at
  spawn". The plan carries the glob for the spawn backend, and it is a gap
  unless the caller allowed that construct by name.
- **FR-015**: The Linux lowering MUST refuse T2 with a Landlock version below
  4, refuse any unknown tier, and never substitute a different tier from the
  one asked for.
- **FR-016**: The lowering outcome of every construct, for every target, MUST
  be published as a lowering table in the crate documentation. The same table
  MUST be the fixture of a test that lowers that construct for that target and
  asserts the stated outcome. Each cell is one of: exact, approximated (it
  needs permission by name), gap, or not applicable. A note states any
  observable difference, such as hiding on Linux T1 giving "not found"
  where macOS gives "permission denied".
- **FR-017**: Lowering MUST be deterministic and independent of the input rule
  order. Equal policies (as sets of rules) MUST produce byte-identical
  profiles and equal plans.
- **FR-018**: A plan MUST never be less restrictive than its policy, apart from
  the degradations it lists. Each allow in a plan traces to an intent rule, a
  grant, or a raw rule.

**Limits**

- **FR-019**: Lowering for macOS MUST apply a limits guard with a configurable
  maximum rule count (default 2,000). A profile over the limit MUST fail with
  "limit exceeded", naming the limit and the count.
- **FR-020**: The limits guard MUST only apply rewrites that match exactly the
  same requests. Merging adjacent rules with the same effect and operation into
  one alternative is one such rewrite. The guard MUST never broaden an allow.

**Data format**

- **FR-021**: Policies and both backend layers MUST have an optional,
  versioned, serialised form that round-trips to an equal value, including
  non-UTF-8 paths. A path is written as text when its bytes are valid UTF-8,
  and as a list of byte values otherwise. Reading MUST apply every
  constructor check and MUST refuse unknown fields.

**Portability and assurance**

- **FR-022**: The policy crate MUST stay free of `unsafe` and buildable without
  the standard library, with and without the data-format option.
- **FR-023**: Coverage-guided fuzz targets MUST exist for:
  - the quoting function, which must round-trip to the input or refuse it;
  - glob compilation, which must leave no input literal unescaped;
  - reading the data format, which must never panic, and every accepted
    document must round-trip;
  - lowering, which must never panic.
  The same properties MUST also run as ordinary tests over generated inputs.
- **FR-024**: Every profile emitted by the reference policies, and every
  operation in the closed list, MUST be compiled by this Mac's libsandbox in a
  test. Compiling proves only that the profile is well-formed; it MUST NOT be
  cited as evidence of enforcement.
- **FR-025**: The crate documentation MUST describe what lowering produces, and
  MUST NOT claim that any profile or plan is enforced. The published tree MUST
  not cite local planning paths.

### Key Entities

- **Policy (intent layer)**: The portable statement of what a child may do. It
  holds file rules, network, process, IPC, environment, limits, terminal,
  hard-deny waivers, grants, and optional backend layers.
- **Absolute path**: Exact bytes of an absolute, lexically normal path.
- **Glob**: An explicitly built absolute pattern with `*`, `**` and `?`.
- **File rule**: An access kind applied to a target, which is a single file, a
  subtree or a glob.
- **Grant**: A named slot for a path bound per spawn, with an access kind.
- **Hard-deny class**: A named member of the fixed final deny tier. It can be
  waived only by name.
- **Seatbelt layer / Linux layer**: Typed raw additions for one backend.
- **Target**: macOS, or Linux with tier and Landlock version.
- **Capability gap**: A construct a target cannot express exactly, with the
  reason.
- **Degradation**: An allowed approximation, recorded in the plan.
- **Plan**: The lowering result for one target. For macOS it holds the
  profile text, parameters, grant classes and degradations. For Linux it holds
  mounts (T1), Landlock rules, seccomp denies, the network mode, the grant
  slots, hygiene settings and degradations.
- **Lowering table**: The published construct × target outcome matrix, which
  also serves as a test fixture.

<!-- threatspec:begin -->
### Security Requirements *(managed by ThreatSpec — edit threat-model.yaml)*

- **SR-001** (P1): Every path, name and pattern text emitted into SBPL MUST pass through the one quoting function or be passed as a named parameter; the function MUST escape backslash and quote and MUST refuse NUL, control characters and invalid UTF-8 with a typed error, and every accepted value MUST decode back to the exact input.
  - Mitigates: `threat.lossy-path`, `threat.quote-injection` via `mitigation.single-escaper`
  - Given a subtree named /tmp/a"b\c(d), when the policy is lowered for macOS, then the profile holds one subtree rule whose quoted string decodes to exactly those bytes and adds no other syntax
  - Given a path containing a newline or a non-UTF-8 byte, when it is lowered for macOS, then lowering fails with a typed error and the path is not altered or dropped
  - Given at least 10,000 generated byte strings and the fuzz corpus, when each is quoted, then each result either decodes to its input or is refused
- **SR-002** (P1): Literal, subtree and glob MUST be distinct kinds chosen by the author; a glob MUST lower to one anchored pattern in which every non-glob character is escaped, and unsupported wildcard syntax MUST be refused.
  - Mitigates: `threat.glob-metachar-widening` via `mitigation.typed-patterns`
  - Given a subtree whose name contains * ? [ ] . + ( ) |, when it is lowered for macOS, then it is emitted as a subtree, not a pattern
  - Given the glob /work/**/*.rs, when it is lowered for macOS, then the result is one pattern anchored at both ends with the dot escaped
  - Given a glob containing [ or {, when it is constructed, then it is refused with a typed error
- **SR-003** (P1): A policy path MUST be exact bytes of an absolute, lexically normal path; empty, relative, tilde, dot, dot-dot, empty-component, trailing-slash and NUL inputs MUST be refused with typed errors and nothing is silently resolved.
  - Mitigates: `threat.lossy-path`, `threat.relative-path-silent` via `mitigation.abs-path-validation`
  - Given relative/dir, ~/dir, /a/../b, /a//b, /a/ or a NUL byte, when each is used as a policy path, then each is refused with an error naming its reason
  - Given a valid path with non-UTF-8 bytes, when it is stored and read back, then the bytes are identical
- **SR-004** (P1): No value of the Seatbelt layer, including deserialised values, MUST be able to produce (with no-sandbox), (with no-profile) or any modifier other than the run tag; operation names outside the closed list MUST be accepted only behind the unstable option and only if they match [a-z0-9*-]+; grant and parameter names MUST be short identifiers.
  - Mitigates: `threat.identifier-injection`, `threat.raw-layer-sandbox-off` via `mitigation.closed-raw-layer`
  - Given an unstable operation name containing a parenthesis, space or quote, when it is constructed or read from a document, then it is refused
  - Given every operation in the closed list, when each is compiled through libsandbox on the development Mac, then each compiles
  - Given a grant name containing a quote, space or slash, when it is constructed, then it is refused
- **SR-005** (P1): Lowering MUST return the complete list of capability gaps for constructs the target cannot express exactly; an approximation MUST be accepted only when the caller allowed that construct by name and MUST then be listed as a degradation in the plan; tier T2 with a Landlock version below 4 MUST be refused and no other tier substituted.
  - Mitigates: `threat.silent-degradation`, `threat.unrecorded-degradation` via `mitigation.typed-gaps`
  - Given a policy with a protect rule and a glob rule, when it is lowered for Linux T2 without allowed degradations, then lowering fails listing both gaps with construct, target and tier
  - Given a single-file rule and the single-file approximation allowed by name, when it is lowered for Linux, then a plan is returned and its degradations name that construct
  - Given tier T2 with Landlock version 3, when lowering runs, then it fails with a typed tier error and returns no plan
- **SR-006** (P2): The lowering table published in the crate docs MUST be the fixture of a test that lowers each construct for each target and asserts the stated outcome.
  - Mitigates: `threat.table-drift` via `mitigation.table-as-fixture`
  - Given a row of the table changed without a matching change to lowering (or the reverse), when the tests run, then they fail naming the construct and target
- **SR-007** (P1): Every plan MUST place allows first, then protect and hide rules, then the hard-deny tier last, regardless of input order, and MUST list every hard-deny waiver; a waiver MUST name a known class.
  - Mitigates: `threat.hard-deny-missing-or-shadowed`, `threat.unrecorded-degradation` via `mitigation.fixed-precedence`
  - Given any reference policy with its rules shuffled, when it is lowered for macOS, then the profile is byte-identical and its last rules are the hard-deny tier
  - Given a policy waiving one hard-deny class by name, when it is lowered, then that class is absent and the plan lists the waiver
- **SR-008** (P1): The limits guard MUST only apply rewrites that match exactly the same requests and MUST never broaden an allow.
  - Mitigates: `threat.guard-broadens` via `mitigation.exact-rewrite-only`
  - Given generated profiles and at least 10,000 generated requests, when guarded and unguarded profiles are evaluated by the reference evaluator, then every decision is identical
- **SR-009** (P2): Lowering for macOS MUST fail with a typed limit error naming the limit and the count when the profile exceeds the configured rule limit, and MUST emit a quoted value over the inline cap as a named parameter whose exact value the plan carries.
  - Mitigates: `threat.oversize-profile` via `mitigation.limits-and-params`
  - Given a policy one rule over the configured limit, when it is lowered for macOS, then it fails naming the limit and the count
  - Given a path whose quoted form is longer than 1016 bytes, when it is lowered for macOS, then the profile references a parameter and the plan holds the exact path bytes
- **SR-010** (P1): The data format MUST be versioned, MUST refuse unknown fields, MUST apply every constructor check on reading, and reading and lowering MUST never panic on any input.
  - Mitigates: `threat.format-drops-restriction`, `threat.lowering-panic` via `mitigation.strict-format`
  - Given a document with an unknown field, when it is read, then reading fails naming the field
  - Given a document with a relative path or a malformed glob, when it is read, then reading fails with the constructor's error
  - Given the fuzz targets for reading and lowering, when each runs at least 60 seconds, then no panic occurs and every accepted document round-trips
- **SR-011** (P2): Crate docs MUST describe what lowering produces and MUST NOT claim that a profile or plan is enforced; the libsandbox compile test MUST be described as a well-formedness check only.
  - Mitigates: `threat.overclaimed-enforcement` via `mitigation.no-enforcement-wording`
  - Given the policy crate docs and the compile test, when they are reviewed, then no sentence states or implies that a child is caged by them
<!-- threatspec:end -->

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: 100% of the lowering table's rows (construct × target) have a test
  that asserts the outcome the table states, and all of them pass.
- **SC-002**: 0 adversarial inputs, across at least 10,000 generated cases per
  property plus the fuzz corpora, produce an emitted string that does not
  decode back to the exact input, or an unescaped pattern character.
- **SC-003**: 100% of the reference policies' macOS profiles, and 100% of the
  operations in the closed list, compile through libsandbox on the
  development Mac.
- **SC-004**: Guarded and unguarded profiles agree on 100% of at least 10,000
  generated requests.
- **SC-005**: 100% of reference policies round-trip through the data format
  unchanged. Each malformed-document kind tested is refused.
- **SC-006**: The policy crate builds for a target without the standard
  library, with and without the data-format option, and contains no `unsafe`.
- **SC-007**: Each fuzz target runs for at least 60 seconds without a failure
  before the feature is called done.

## Assumptions

- **Lexical paths only.** The policy crate checks that a path is absolute and
  lexically normal. Resolving symlinks and firmlinks to the real path
  needs the filesystem and belongs to the spawn backends.
- **No fluent builder yet.** The typestate builder over the IR is a
  convenience layer and comes in a later feature, before the 0.1.0 API
  freeze. This feature delivers the IR as data.
- **Only fixed hard-deny classes.** Classes that need curated data (secret
  paths, trust-handoff paths, persistence locations, procage's own files) are
  added by the hard-deny and presets feature (007). The class list is open for
  extension.
- **Closed operation list.** It covers the operation names the design needs,
  taken from the names mined on macOS 26.6.2. Each is proven by compiling it,
  not by trusting the earlier list.
- **Seccomp as rules, not filters.** The Linux plan states syscall denies by
  name with argument conditions. Building BPF for an architecture belongs to
  the Linux spawn feature (008), as does applying mounts and Landlock.
- **Default rule limit 2,000**, as in the design, configurable.
  Choosing the in-process compile limit from measured bytecode size is
  the macOS spawn feature's decision.
- **Data format optional.** It is behind an opt-in option so that consumers
  who build policies in code pay nothing for it.
- **Fuzzing uses the nightly toolchain**, which is installed locally. It runs
  outside the stable `ci` recipe, as its own recipe and CI job.
- **Unpublished crate.** The policy crate stays unpublished in this feature
  (version 0.0.0); `procage` does not yet re-export it. Neither published
  README nor threat model changes status: no escape class becomes
  `mitigated`, because nothing is applied to a child.

## Out of Scope

- Applying any profile or plan to a process, spawning, probing tiers or
  Landlock versions, canonicalising paths on disk (specs 004, 005, 008).
- Explaining or diffing policies, and receipts (spec 011).
- Data-driven hard-deny content and presets (spec 007).
- Building seccomp BPF, or opening rule file descriptors (spec 008).
- A fluent builder (later, before 0.1.0).
- Changing the published threat model's statuses.
