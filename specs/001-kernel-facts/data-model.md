# Data Model: 001-kernel-facts

All types live in `tests/kernel_facts` (unpublished). None are public API of
`procage`.

## Fact

| Field | Type | Rules |
|---|---|---|
| `id` | `&'static str` | `KF-M\d\d` or `KF-L\d\d`; unique; never renumbered or reused (FR-001) |
| `statement` | `&'static str` | one line, the expected outcome |
| `platform` | `Macos \| Linux` | facts of the other platform are not compiled in |
| `kind` | `Enforcement \| Observation` | `Enforcement` (applies a profile or restriction) facts are failed by the sandbox precheck (FR-007); `Observation` covers compile-only facts, probe readings and question facts that apply nothing |
| `tiers` | `&[Tier]` (Linux) | empty for macOS; for Linux, the tiers where it applies (FR-011) |
| `slow` | `bool` | true for KF-M17 and KF-M24: still run by default, listed in the report with their duration |
| `run` | `fn(&Ctx) -> Outcome` | performs steps through `kf-probe`, compares observations |

## Outcome

`Pass { observed }` · `Fail { expected, observed }` · `NotApplicable { reason }`
· `SetupFailed { detail }`. The last counts as a failure: a control run that
did not succeed (SR-002).

## Observation

The output of one `kf-probe` step: an ordered map of `key → value`. Values are
integers, `errno` numbers or names, byte counts, `0/1` flags, or short fixed
tokens. Also `exit: Code(i32) | Signal(i32) | Timeout`. Never file contents or
environment values (SR-014). Format: [contracts/probe-protocol.md](contracts/probe-protocol.md).

## Ctx

`probe: PathBuf` (`CARGO_BIN_EXE_kf-probe`), `sandboxed: bool` (macOS
precheck), `tier: Option<Tier>` (Linux), `scratch_root` (0700, removed at the
end), and timeouts (`default = 30 s`, `compile_heavy = 120 s`).

## ProbeResult (Linux)

| Field | Type | Source |
|---|---|---|
| `landlock_abi` | `Option<u32>` | `landlock_create_ruleset(NULL,0,VERSION)` in a child |
| `landlock_errata` | `Option<u32>` | `…ERRATA` flag |
| `seccomp_actions` | `Vec<String>` | `/proc/sys/kernel/seccomp/actions_avail` |
| `seccomp_filter` | `bool` | an allow-all filter installed in a child |
| `userns` | `bool` | `unshare(CLONE_NEWUSER)` in a child |
| `uid_map` | `bool` | `setgroups deny` plus uid/gid map writes |
| `tmpfs` | `bool` | tmpfs mount in userns+mntns |
| `ro_bind_erofs` | `bool` | locked ro bind, write → EROFS |
| `fresh_proc` | `bool` | `mount proc` in userns+pidns |
| `netns_lo_down` | `bool` | new netns: only `lo`, not `IFF_UP` |
| `apparmor_restrict_userns` | `Option<bool>` | sysctl read, diagnostics only |
| `boot_id` | `String` | `/proc/sys/kernel/random/boot_id` |
| `tier` | `Tier` | derived (research R5); a crashed or timed-out measurement → false |

Tier: `T1 | T2 | T3`, ordered T1 > T2 > T3. Measured < expected lane tier →
the run fails.

## QuestionFinding

Constants in `tests/kernel_facts.rs`, each with a doc comment:

| Field | Example |
|---|---|
| question | compile-abort threshold |
| answer | the bracket `(lower_ok, upper_abort)` per shape |
| method | bisection in isolated children |
| build | macOS 26.6.2 (25G83) |
| date | 2026-10-29 |
| proven | `true` (measured) / `false` (inferred, e.g. the extension question's syscalls-only part) |

The asserting fact (KF-M23…M26) checks the answer each run. Changing a
constant needs a dated, recorded decision.

## Lane

| Field | Example |
|---|---|
| image | `macos-26`, `ubuntu-24.04-arm`, `debian:13` container |
| arch | arm64, x86_64 |
| config | `shipped`, `userns-unrestricted` |
| expected tier | `T2` (`PROCAGE_KF_EXPECT_TIER`) |
| allowed missing | true for preview images (newest macOS, ubuntu-26.04, Rosetta) |

## State

Each run goes `precheck → (Linux) measure tier → facts in catalog order →
report`. A fact moves `pending → running → {pass, fail, n/a, setup-failed}`.
A child timeout ends the fact in fail. Process exit status is non-zero if any
fact is fail or setup-failed, or the tier mismatches.
