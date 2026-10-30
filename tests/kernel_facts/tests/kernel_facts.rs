//! The kernel facts runner (`harness = false`).
//!
//! Runs every fact of the catalog through `kf-probe`, each in fresh child
//! processes, and prints a three-state report (pass, fail, not applicable)
//! headed by the OS build, architecture and date. The process fails if any
//! fact fails, if a control run did not succeed, or if the measured Linux tier
//! differs from `PROCAGE_KF_EXPECT_TIER`.
//!
//! Enforcement facts must run outside any Seatbelt sandbox: when this process
//! is already sandboxed (for example inside an agent harness), every
//! enforcement fact fails. None is skipped.
//!
//! `cargo test -p procage-kernel-facts --test kernel_facts -- KF-M1` runs only
//! the facts whose id starts with `KF-M1`. `PROCAGE_KF_BISECT=1` also runs the
//! compile-abort bisection before KF-M24.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
#[cfg(target_os = "macos")]
use std::time::Duration;
use std::time::Instant;

use procage_kernel_facts::{
    Check, Outcome, Scratch, Step, TIMEOUT, Tier, control, expect, ran, run_step, utc_date,
};
#[cfg(target_os = "macos")]
use procage_kernel_facts::{Exit, TIMEOUT_HEAVY};

#[derive(Clone, Copy, PartialEq, Eq)]
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
enum Kind {
    /// Applies a profile or restriction; fails when the runner is sandboxed.
    Enforcement,
    /// Compiles or measures only.
    Observation,
}

struct Fact {
    id: &'static str,
    statement: &'static str,
    kind: Kind,
    /// Linux tiers the fact applies to; empty means every tier.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    tiers: &'static [Tier],
    slow: bool,
    run: fn(&Ctx) -> Check,
}

/// What a fact needs from the run.
struct Ctx {
    probe: PathBuf,
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    linux: Option<linux::Probe>,
}

impl Ctx {
    fn step(&self, args: &[&str]) -> Step {
        run_step(&self.probe, args, TIMEOUT, None)
    }

    #[cfg(target_os = "macos")]
    fn heavy(&self, args: &[&str]) -> Step {
        run_step(&self.probe, args, TIMEOUT_HEAVY, None)
    }
}

fn scratch() -> Result<Scratch, Outcome> {
    Scratch::new().map_err(|e| Outcome::SetupFailed(format!("scratch: {e}")))
}

/// Facts deliberately not in the catalog, with the reason.
const EXCLUDED: &[(&str, &str)] = &[
    (
        "compile-time and namespace-setup figures",
        "recorded as observations (`ms=`), not asserted: CI hardware varies",
    ),
    (
        "Landlock audit records and tracepoints",
        "need CAP_AUDIT_READ or CAP_BPF; the suite runs unprivileged",
    ),
    (
        "sandbox_apply after fork does not deadlock",
        "informs only the helper fallback, which does not apply after fork",
    ),
    (
        "sandbox_check for file-write-create is unreliable",
        "a negative property of an operation the oracle will not use",
    ),
];

#[cfg(target_os = "macos")]
mod macos {
    //! The macOS catalog.

    use super::*;

    /// Q-09 answer, measured 2026-10-29 on macOS 26.6.2 (25G83) by bisection
    /// in isolated children (`just bisect`). The abort depends on rule shape.
    /// With the deny-default, one-allow-per-directory shape, this many rules
    /// still return from the compiler (with the clean 64 KiB bytecode-cap
    /// error) …
    pub(super) const ABORT_FREE_RULES: &str = "15625";
    /// … and this many abort libsandbox (jump-length assertion). The
    /// allow-default, one-deny-per-path shape aborts later, between 33,750
    /// and 35,000 rules; that bracket is recorded, not asserted (a compile of
    /// that size exceeds the step timeout).
    pub(super) const ABORTING_RULES: &str = "16250";
    /// The rule count of KF-M17, the original measurement.
    pub(super) const ORIGINAL_ABORT_RULES: &str = "20000";

    pub(super) const FACTS: &[Fact] = &[
        Fact {
            id: "KF-M01",
            statement: "libsandbox and __mac_syscall symbols resolve by dynamic lookup",
            kind: Kind::Observation,
            tiers: &[],
            slow: false,
            run: m01,
        },
        Fact {
            id: "KF-M02",
            statement: "a small profile compiles to bytecode with no builtin name",
            kind: Kind::Observation,
            tiers: &[],
            slow: false,
            run: m02,
        },
        Fact {
            id: "KF-M03",
            statement: "compile errors carry line and column; success leaves the error slot untouched",
            kind: Kind::Observation,
            tiers: &[],
            slow: false,
            run: m03,
        },
        Fact {
            id: "KF-M04",
            statement: "an unset (param …) fails the compile",
            kind: Kind::Observation,
            tiers: &[],
            slow: false,
            run: m04,
        },
        Fact {
            id: "KF-M05",
            statement: "after apply the self-check reports 1 and stays 1",
            kind: Kind::Enforcement,
            tiers: &[],
            slow: false,
            run: m05,
        },
        Fact {
            id: "KF-M06",
            statement: "the sandbox is inherited across fork and exec",
            kind: Kind::Enforcement,
            tiers: &[],
            slow: false,
            run: m06,
        },
        Fact {
            id: "KF-M07",
            statement: "literal /etc/hosts does not block reading it; /private/etc/hosts does",
            kind: Kind::Enforcement,
            tiers: &[],
            slow: false,
            run: m07,
        },
        Fact {
            id: "KF-M08",
            statement: "subpath /tmp/… does not allow creating there; /private/tmp/… does",
            kind: Kind::Enforcement,
            tiers: &[],
            slow: false,
            run: m08,
        },
        Fact {
            id: "KF-M09",
            statement: "a different second profile fails with EPERM and is not enforced; an identical one returns 0",
            kind: Kind::Enforcement,
            tiers: &[],
            slow: false,
            run: m09,
        },
        Fact {
            id: "KF-M10",
            statement: "compiling inside a sandbox works",
            kind: Kind::Enforcement,
            tiers: &[],
            slow: false,
            run: m10,
        },
        Fact {
            id: "KF-M11",
            statement: "a sandboxed process cannot exec a setuid binary (EPERM)",
            kind: Kind::Enforcement,
            tiers: &[],
            slow: false,
            run: m11,
        },
        Fact {
            id: "KF-M12",
            statement: "(with no-sandbox) on process-exec runs the exec'd child unsandboxed",
            kind: Kind::Enforcement,
            tiers: &[],
            slow: false,
            run: m12,
        },
        Fact {
            id: "KF-M13",
            statement: "a specific IP in a network filter fails to compile",
            kind: Kind::Observation,
            tiers: &[],
            slow: false,
            run: m13,
        },
        Fact {
            id: "KF-M14",
            statement: "every hard-deny and network form compiles under (deny default (with message …))",
            kind: Kind::Observation,
            tiers: &[],
            slow: false,
            run: m14,
        },
        Fact {
            id: "KF-M15",
            statement: "(param …) is accepted by subpath, literal, prefix, regex, path-literal, global-name, string-append",
            kind: Kind::Observation,
            tiers: &[],
            slow: false,
            run: m15,
        },
        Fact {
            id: "KF-M16",
            statement: "a 1016 B literal compiles, 1024 B is rejected, a 4000 B param compiles",
            kind: Kind::Observation,
            tiers: &[],
            slow: false,
            run: m16,
        },
        Fact {
            id: "KF-M17",
            statement: "20,000 deny-default allow rules abort the compiling process",
            kind: Kind::Observation,
            tiers: &[],
            slow: true,
            run: m17,
        },
        Fact {
            id: "KF-M18",
            statement: "path A apply after fork under dyld contention is enforced every time, without hangs",
            kind: Kind::Enforcement,
            tiers: &[],
            slow: false,
            run: m18,
        },
        Fact {
            id: "KF-M19",
            statement: "an fd inherited from before apply reads a denied file; a fresh open is denied",
            kind: Kind::Enforcement,
            tiers: &[],
            slow: false,
            run: m19,
        },
        Fact {
            id: "KF-M20",
            statement: "one compiled profile plus a per-spawn extension grants exactly the issued path",
            kind: Kind::Enforcement,
            tiers: &[],
            slow: false,
            run: m20,
        },
        Fact {
            id: "KF-M21",
            statement: "a subpath /Users deny is enforced through the firmlink",
            kind: Kind::Enforcement,
            tiers: &[],
            slow: false,
            run: m21,
        },
        Fact {
            id: "KF-M22",
            statement: "sandbox_check is reliable for file-read-data/path and mach-lookup/global-name",
            kind: Kind::Enforcement,
            tiers: &[],
            slow: false,
            run: m22,
        },
        Fact {
            id: "KF-M23",
            statement: "path A's {data, size, NULL, 0} layout is accepted and enforced on this release",
            kind: Kind::Enforcement,
            tiers: &[],
            slow: false,
            run: m23,
        },
        Fact {
            id: "KF-M24",
            statement: "the compile-abort threshold lies in the recorded bracket",
            kind: Kind::Observation,
            tiers: &[],
            slow: true,
            run: m24,
        },
        Fact {
            id: "KF-M25",
            statement: "an extension consumed before apply grants nothing after apply (consume after apply)",
            kind: Kind::Enforcement,
            tiers: &[],
            slow: false,
            run: m25,
        },
        Fact {
            id: "KF-M26",
            statement: "TIOCSTI injects into a process's own controlling terminal, sandboxed or not",
            kind: Kind::Enforcement,
            tiers: &[],
            slow: false,
            run: m26,
        },
        Fact {
            id: "KF-M27",
            statement: "bytecode over 65,535 bytes fails cleanly with 'exceeds maximum'",
            kind: Kind::Observation,
            tiers: &[],
            slow: true,
            run: m27,
        },
        Fact {
            id: "KF-M28",
            statement: "a 10,000-literal require-any fails with no error text",
            kind: Kind::Observation,
            tiers: &[],
            slow: false,
            run: m28,
        },
    ];

    fn m01(c: &Ctx) -> Check {
        let s = ran(c.step(&["symbols"]))?;
        expect(&s, &[("missing_count", "0")])?;
        Ok(s.summary())
    }

    fn m02(c: &Ctx) -> Check {
        let s = ran(c.step(&["compile", "small"]))?;
        expect(&s, &[("ok", "1"), ("builtin_null", "1")])?;
        Ok(s.summary())
    }

    fn m03(c: &Ctx) -> Check {
        let e = ran(c.step(&["compile", "error"]))?;
        expect(
            &e,
            &[
                ("ok", "0"),
                ("err_kind", "unbound"),
                ("err_line", "1"),
                ("err_col", "19"),
            ],
        )?;
        let k = ran(c.step(&["compile", "keeps-slot"]))?;
        expect(&k, &[("slot_kept", "1")])?;
        Ok(format!("{} | {}", e.summary(), k.summary()))
    }

    fn m04(c: &Ctx) -> Check {
        let s = ran(c.step(&["compile", "unset-param"]))?;
        expect(&s, &[("ok", "0"), ("err_kind", "unset_param")])?;
        Ok(s.summary())
    }

    fn m05(c: &Ctx) -> Check {
        let s = ran(c.step(&["apply-selfcheck"]))?;
        control(&s, &[("before", "0")])?;
        expect(
            &s,
            &[
                ("apply_errno", "0"),
                ("after", "1"),
                ("again_errno", "0"),
                ("after_again", "1"),
            ],
        )?;
        Ok(s.summary())
    }

    fn m06(c: &Ctx) -> Check {
        control(&c.step(&["selfcheck"]), &[("sandboxed", "0")])?;
        let s = ran(c.step(&["apply-then-spawn"]))?;
        expect(&s, &[("child_sandboxed", "1")])?;
        Ok(s.summary())
    }

    fn m07(c: &Ctx) -> Check {
        control(&c.step(&["read", "control"]), &[("errno", "0")])?;
        let etc = c.step(&["read", "literal-etc"]);
        let private = c.step(&["read", "literal-private"]);
        expect(&etc, &[("errno", "0")])?;
        expect(&private, &[("errno", "1")])?;
        Ok(format!(
            "etc: {} | private: {}",
            etc.summary(),
            private.summary()
        ))
    }

    fn m08(c: &Ctx) -> Check {
        let run = |variant: &str| -> Result<Step, Outcome> {
            let dir = Scratch::new_in(Path::new("/private/tmp"))
                .map_err(|e| Outcome::SetupFailed(e.to_string()))?;
            Ok(c.step(&["tmp-create", variant, dir.as_str()]))
        };
        control(&run("control")?, &[("errno", "0")])?;
        let tmp = run("subpath-tmp")?;
        let private = run("subpath-private")?;
        expect(&tmp, &[("errno", "1")])?;
        expect(&private, &[("errno", "0")])?;
        Ok(format!(
            "tmp: {} | private: {}",
            tmp.summary(),
            private.summary()
        ))
    }

    fn m09(c: &Ctx) -> Check {
        let dir = scratch()?;
        let s = ran(c.step(&["nest", dir.as_str()]))?;
        control(&s, &[("first_errno", "0"), ("a_errno", "1")])?;
        expect(
            &s,
            &[("second_errno", "1"), ("b_errno", "0"), ("same_errno", "0")],
        )?;
        Ok(s.summary())
    }

    fn m10(c: &Ctx) -> Check {
        let s = ran(c.step(&["compile-inside"]))?;
        expect(&s, &[("sandboxed", "1"), ("ok", "1")])?;
        Ok(s.summary())
    }

    fn m11(c: &Ctx) -> Check {
        control(&c.step(&["setuid-exec", "control"]), &[("exec_errno", "0")])?;
        let s = ran(c.step(&["setuid-exec", "caged"]))?;
        expect(&s, &[("exec_errno", "1")])?;
        Ok(s.summary())
    }

    fn m12(c: &Ctx) -> Check {
        control(
            &c.step(&["no-sandbox-exec", "control"]),
            &[("sandboxed", "1"), ("child_sandboxed", "1")],
        )?;
        let s = ran(c.step(&["no-sandbox-exec", "escape"]))?;
        expect(&s, &[("sandboxed", "1"), ("child_sandboxed", "0")])?;
        Ok(s.summary())
    }

    fn m13(c: &Ctx) -> Check {
        let s = ran(c.step(&["compile", "ip-host"]))?;
        expect(&s, &[("ok", "0"), ("err_kind", "ip_host")])?;
        Ok(s.summary())
    }

    fn m14(c: &Ctx) -> Check {
        let s = ran(c.step(&["compile", "hard-deny"]))?;
        expect(&s, &[("failed", "0")])?;
        Ok(s.summary())
    }

    fn m15(c: &Ctx) -> Check {
        let s = ran(c.step(&["compile", "params"]))?;
        expect(&s, &[("failed", "0")])?;
        Ok(s.summary())
    }

    fn m16(c: &Ctx) -> Check {
        let ok = ran(c.step(&["compile", "literal-1016"]))?;
        let long = ran(c.step(&["compile", "literal-1024"]))?;
        let param = ran(c.step(&["compile", "param-4000"]))?;
        expect(&ok, &[("ok", "1")])?;
        expect(&long, &[("ok", "0"), ("err_kind", "string_read")])?;
        expect(&param, &[("ok", "1")])?;
        Ok(format!(
            "1016: ok | 1024: {} | param 4000: ok",
            long.summary()
        ))
    }

    fn m17(c: &Ctx) -> Check {
        let s = c.heavy(&["compile-rules", "deny-default-allow", ORIGINAL_ABORT_RULES]);
        if s.exit != Exit::Signal(libc::SIGABRT) {
            return Err(Outcome::Fail {
                expected: "exit=signal:6".into(),
                observed: s.summary(),
            });
        }
        Ok(s.summary())
    }

    fn patha(c: &Ctx) -> Check {
        control(
            &c.step(&["patha-contention", "5", "control"]),
            &[("ok", "5")],
        )?;
        let s = ran(c.step(&["patha-contention", "200", "apply"]))?;
        expect(
            &s,
            &[
                ("denied", "200"),
                ("hangs", "0"),
                ("apply_failed", "0"),
                ("other", "0"),
            ],
        )?;
        Ok(s.summary())
    }

    fn m18(c: &Ctx) -> Check {
        patha(c)
    }

    fn m19(c: &Ctx) -> Check {
        let dir = scratch()?;
        let s = ran(c.step(&["fd-parent", dir.as_str()]))?;
        expect(
            &s,
            &[("fd_errno", "0"), ("fd_bytes", "16"), ("open_errno", "1")],
        )?;
        Ok(s.summary())
    }

    fn m20(c: &Ctx) -> Check {
        let dir = scratch()?;
        let s = ran(c.step(&["ext-parent", dir.as_str(), "apply-first"]))?;
        expect(
            &s,
            &[
                ("run0_consume_ok", "1"),
                ("run0_a_errno", "0"),
                ("run0_b_errno", "1"),
                ("run1_consume_ok", "1"),
                ("run1_a_errno", "1"),
                ("run1_b_errno", "0"),
            ],
        )?;
        Ok(s.summary())
    }

    fn m21(c: &Ctx) -> Check {
        control(&c.step(&["read", "control-users"]), &[("errno", "0")])?;
        let s = ran(c.step(&["read", "deny-users"]))?;
        expect(&s, &[("errno", "1")])?;
        Ok(s.summary())
    }

    fn m22(c: &Ctx) -> Check {
        let dir = scratch()?;
        let s = ran(c.step(&["check-oracle", dir.as_str()]))?;
        control(&s, &[("read_errno", "1")])?;
        expect(
            &s,
            &[
                ("read_denied", "1"),
                ("read_allowed", "0"),
                ("mach_denied", "1"),
                ("mach_allowed", "0"),
            ],
        )?;
        Ok(s.summary())
    }

    /// Q-01, answered 2026-10-29 on macOS 26.6.2 (25G83): yes, 200 of 200
    /// children forked under dyld contention were enforced, none hung.
    fn m23(c: &Ctx) -> Check {
        patha(c)
    }

    fn m24(c: &Ctx) -> Check {
        if std::env::var_os("PROCAGE_KF_BISECT").is_some_and(|v| v == "1") {
            super::bisect(c);
        }
        let ok = c.heavy(&["compile-rules", "deny-default-allow", ABORT_FREE_RULES]);
        if !ok.ran() {
            return Err(Outcome::Fail {
                expected: format!("{ABORT_FREE_RULES} rules: exit=code:0"),
                observed: ok.summary(),
            });
        }
        let abort = c.heavy(&["compile-rules", "deny-default-allow", ABORTING_RULES]);
        if abort.exit != Exit::Signal(libc::SIGABRT) {
            return Err(Outcome::Fail {
                expected: format!("{ABORTING_RULES} rules: exit=signal:6"),
                observed: abort.summary(),
            });
        }
        Ok(format!("ok<={ABORT_FREE_RULES} abort>={ABORTING_RULES}"))
    }

    /// Q-10, answered 2026-10-29 on macOS 26.6.2 (25G83), measured: a token
    /// consumed *before* apply returns a valid handle but grants nothing once
    /// the profile is applied, so a child must consume its tokens after
    /// apply (as KF-M20 does). Whether consume is free of user-space locks is
    /// recorded separately as an inference, not asserted here.
    fn m25(c: &Ctx) -> Check {
        let dir = scratch()?;
        let s = ran(c.step(&["ext-parent", dir.as_str(), "consume-first"]))?;
        expect(
            &s,
            &[
                ("run0_consume_ok", "1"),
                ("run0_a_errno", "1"),
                ("run0_b_errno", "1"),
                ("run1_a_errno", "1"),
                ("run1_b_errno", "1"),
            ],
        )?;
        Ok(s.summary())
    }

    /// Q-13, answered 2026-10-29 on macOS 26.6.2 (25G83): yes. TIOCSTI
    /// pushes input into the caller's own controlling terminal, also under an
    /// allow-default profile, so a caged child must not share the caller's
    /// terminal unless the profile denies the ioctl.
    fn m26(c: &Ctx) -> Check {
        control(
            &c.step(&["tiocsti", "control"]),
            &[
                ("ctty_before_errno", "6"),
                ("errno", "0"),
                ("injected", "1"),
            ],
        )?;
        let s = ran(c.step(&["tiocsti", "caged"]))?;
        expect(
            &s,
            &[
                ("ctty_before_errno", "6"),
                ("errno", "0"),
                ("injected", "1"),
            ],
        )?;
        Ok(s.summary())
    }

    fn m27(c: &Ctx) -> Check {
        let s = ran(c.heavy(&["compile-rules", "deny-default-allow", "10000"]))?;
        expect(&s, &[("ok", "0"), ("err_kind", "data_too_long")])?;
        Ok(s.summary())
    }

    fn m28(c: &Ctx) -> Check {
        let s = ran(c.heavy(&["compile-rules", "require-any", "10000"]))?;
        expect(&s, &[("ok", "0"), ("err_kind", "none")])?;
        Ok(s.summary())
    }
}

/// Q-09 bisection (opt-in): finds, per rule shape, the largest rule count
/// that compiles without aborting and the smallest that aborts.
#[cfg(target_os = "macos")]
fn bisect(c: &Ctx) {
    const BUDGET: Duration = Duration::from_secs(600);
    const STEP_TIMEOUT: Duration = Duration::from_secs(600);
    for (shape, mut lo, mut hi) in [
        ("deny-default-allow", 10_000u32, 20_000u32),
        ("allow-default-deny", 20_000, 40_000),
    ] {
        let start = Instant::now();
        let aborts = |n: u32| -> Option<bool> {
            let s = run_step(
                &c.probe,
                &["compile-rules", shape, &n.to_string()],
                STEP_TIMEOUT,
                None,
            );
            match s.exit {
                Exit::Signal(sig) if sig == libc::SIGABRT => Some(true),
                Exit::Code(0) => Some(false),
                _ => None,
            }
        };
        match (aborts(lo), aborts(hi)) {
            (Some(false), Some(true)) => {}
            (lo_r, hi_r) => {
                println!(
                    "bisect {shape}: no bracket (at {lo}: {lo_r:?} abort, at {hi}: {hi_r:?} abort)"
                );
                continue;
            }
        }
        while hi - lo > lo / 20 && start.elapsed() < BUDGET {
            let mid = lo + (hi - lo) / 2;
            match aborts(mid) {
                Some(true) => hi = mid,
                Some(false) => lo = mid,
                None => break,
            }
        }
        let width = f64::from(hi - lo) * 100.0 / f64::from(lo);
        println!(
            "bisect {shape}: ok<={lo} abort>={hi} (width {width:.1}%) in {:.0}s",
            start.elapsed().as_secs_f64()
        );
    }
}

#[cfg(target_os = "linux")]
mod linux {
    //! The Linux catalog and the tier probe.

    use super::*;

    /// What the probe measured, each in a throwaway child.
    pub(super) struct Probe {
        pub landlock_abi: Option<u32>,
        pub landlock_errata: Option<u32>,
        pub seccomp_actions: String,
        pub seccomp_filter: bool,
        pub userns: bool,
        pub userns_errno: Option<i64>,
        pub uid_map: bool,
        pub tmpfs: bool,
        pub ro_bind: bool,
        pub fresh_proc: bool,
        pub netns: bool,
        pub container: bool,
        pub tier: Tier,
    }

    impl Probe {
        pub fn measure(probe: &Path) -> Self {
            let m = |cap: &str| run_step(probe, &["measure", cap], TIMEOUT, None);
            let ok = procage_kernel_facts::measured;
            let landlock = m("landlock");
            let seccomp = m("seccomp");
            let userns = m("userns");
            let landlock_abi = ok(&landlock)
                .then(|| landlock.obs.int("abi"))
                .flatten()
                .map(|v| v as u32);
            let mut p = Self {
                landlock_abi,
                landlock_errata: landlock.obs.int("errata").map(|v| v as u32),
                seccomp_actions: seccomp.obs.get("actions").unwrap_or("").to_owned(),
                seccomp_filter: ok(&seccomp),
                userns: ok(&userns),
                userns_errno: userns.obs.int("errno"),
                uid_map: ok(&m("uid_map")),
                tmpfs: ok(&m("tmpfs")),
                ro_bind: ok(&m("ro_bind")),
                fresh_proc: ok(&m("fresh_proc")),
                netns: ok(&m("netns")),
                container: Path::new("/.dockerenv").exists()
                    || Path::new("/run/.containerenv").exists(),
                tier: Tier::T3,
            };
            p.tier = procage_kernel_facts::derive_tier(&procage_kernel_facts::Capabilities {
                userns: p.userns,
                uid_map: p.uid_map,
                tmpfs: p.tmpfs,
                ro_bind: p.ro_bind,
                landlock_abi: p.landlock_abi,
                seccomp_filter: p.seccomp_filter,
            });
            p
        }

        pub fn describe(&self) -> String {
            format!(
                "{:?} (landlock abi {} errata {}; seccomp filter {}; userns {}{}; uid_map {}; tmpfs {}; ro_bind {}; fresh_proc {}; netns {}; container {})",
                self.tier,
                self.landlock_abi.map_or("none".into(), |v| v.to_string()),
                self.landlock_errata.map_or("-".into(), |v| v.to_string()),
                yn(self.seccomp_filter),
                yn(self.userns),
                self.userns_errno
                    .filter(|e| *e != 0)
                    .map_or(String::new(), |e| format!(" errno {e}")),
                yn(self.uid_map),
                yn(self.tmpfs),
                yn(self.ro_bind),
                yn(self.fresh_proc),
                yn(self.netns),
                yn(self.container),
            )
        }
    }

    fn yn(b: bool) -> &'static str {
        if b { "yes" } else { "no" }
    }

    fn probe(c: &Ctx) -> &Probe {
        c.linux.as_ref().expect("measured before facts")
    }

    const ALL: &[Tier] = &[Tier::T1, Tier::T2];
    const T1: &[Tier] = &[Tier::T1];

    pub(super) const FACTS: &[Fact] = &[
        Fact {
            id: "KF-L01",
            statement: "the probe reports a Landlock ABI ≥ 1 and its errata",
            kind: Kind::Observation,
            tiers: ALL,
            slow: false,
            run: l01,
        },
        Fact {
            id: "KF-L02",
            statement: "seccomp lists user_notif among available actions",
            kind: Kind::Observation,
            tiers: &[],
            slow: false,
            run: l02,
        },
        Fact {
            id: "KF-L03",
            statement: "an unprivileged user namespace with self uid/gid map is created",
            kind: Kind::Enforcement,
            tiers: T1,
            slow: false,
            run: l03,
        },
        Fact {
            id: "KF-L04",
            statement: "writing through a read-only bind fails with EROFS",
            kind: Kind::Enforcement,
            tiers: T1,
            slow: false,
            run: l04,
        },
        Fact {
            id: "KF-L05",
            statement: "a tmpfs over a directory hides its entries",
            kind: Kind::Enforcement,
            tiers: T1,
            slow: false,
            run: l05,
        },
        Fact {
            id: "KF-L06",
            statement: "Landlock denies a write outside the allowed tree with EACCES",
            kind: Kind::Enforcement,
            tiers: ALL,
            slow: false,
            run: l06,
        },
        Fact {
            id: "KF-L07",
            statement: "a new network namespace has no interface up (lo included)",
            kind: Kind::Enforcement,
            tiers: T1,
            slow: false,
            run: l07,
        },
        Fact {
            id: "KF-L08",
            statement: "under Landlock, /dev/null writes are denied until it is given a rule",
            kind: Kind::Enforcement,
            tiers: ALL,
            slow: false,
            run: l08,
        },
        Fact {
            id: "KF-L09",
            statement: "a nested user namespace cannot remount rw, unmount the tmpfs, or bind the parent non-recursively",
            kind: Kind::Enforcement,
            tiers: T1,
            slow: false,
            run: l09,
        },
        Fact {
            id: "KF-L10",
            statement: "under Landlock, a nested user namespace cannot write its uid_map (EACCES)",
            kind: Kind::Enforcement,
            tiers: T1,
            slow: false,
            run: l10,
        },
        Fact {
            id: "KF-L11",
            statement: "mount topology changes are denied after Landlock restriction",
            kind: Kind::Enforcement,
            tiers: T1,
            slow: false,
            run: l11,
        },
        Fact {
            id: "KF-L12",
            statement: "in a container under default seccomp, user namespaces fail with EPERM while Landlock is available",
            kind: Kind::Observation,
            tiers: &[Tier::T2],
            slow: false,
            run: l12,
        },
        Fact {
            id: "KF-L13",
            statement: "with /proc masked, a fresh /proc cannot be mounted in a PID namespace",
            kind: Kind::Enforcement,
            tiers: T1,
            slow: false,
            run: l13,
        },
    ];

    fn l01(c: &Ctx) -> Check {
        let p = probe(c);
        match (p.landlock_abi, p.landlock_errata) {
            (Some(abi), Some(errata)) if abi >= 1 => Ok(format!("abi={abi} errata={errata}")),
            (abi, errata) => Err(Outcome::Fail {
                expected: "abi>=1 errata reported".into(),
                observed: format!("abi={abi:?} errata={errata:?}"),
            }),
        }
    }

    fn l02(c: &Ctx) -> Check {
        let p = probe(c);
        if p.seccomp_actions.split('+').any(|a| a == "user_notif") {
            Ok(format!("actions={}", p.seccomp_actions))
        } else {
            Err(Outcome::Fail {
                expected: "user_notif in actions".into(),
                observed: format!("actions={}", p.seccomp_actions),
            })
        }
    }

    fn l03(c: &Ctx) -> Check {
        let s = ran(c.step(&["userns"]))?;
        expect(&s, &[("errno", "0"), ("uid", "0")])?;
        Ok(s.summary())
    }

    fn l04(c: &Ctx) -> Check {
        let dir = scratch()?;
        let s = ran(c.step(&["ro-bind", dir.as_str()]))?;
        control(&s, &[("before_errno", "0")])?;
        expect(&s, &[("after_errno", "30")])?;
        Ok(s.summary())
    }

    fn l05(c: &Ctx) -> Check {
        let dir = scratch()?;
        let s = ran(c.step(&["tmpfs", dir.as_str()]))?;
        control(&s, &[("before_entries", "1")])?;
        expect(&s, &[("after_entries", "0")])?;
        Ok(s.summary())
    }

    fn l06(c: &Ctx) -> Check {
        let dir = scratch()?;
        let s = ran(c.step(&["landlock-write", dir.as_str()]))?;
        control(&s, &[("control_errno", "0")])?;
        expect(&s, &[("a_errno", "0"), ("b_errno", "13")])?;
        Ok(s.summary())
    }

    fn l07(c: &Ctx) -> Check {
        let s = ran(c.step(&["netns"]))?;
        if s.obs.int("host_up").unwrap_or(0) < 1 {
            return Err(Outcome::SetupFailed(format!(
                "control: no interface up on the host: {}",
                s.summary()
            )));
        }
        expect(&s, &[("errno", "0"), ("has_lo", "1"), ("up", "0")])?;
        Ok(s.summary())
    }

    fn l08(c: &Ctx) -> Check {
        let dir = scratch()?;
        let norule = ran(c.step(&["landlock-devnull", dir.as_str(), "no-rule"]))?;
        let rule = ran(c.step(&["landlock-devnull", dir.as_str(), "rule"]))?;
        expect(&norule, &[("errno", "13")])?;
        expect(&rule, &[("errno", "0")])?;
        Ok(format!(
            "no rule: {} | rule: {}",
            norule.summary(),
            rule.summary()
        ))
    }

    fn l09(c: &Ctx) -> Check {
        let dir = scratch()?;
        let s = ran(c.step(&["nested-undo", dir.as_str()]))?;
        expect(
            &s,
            &[
                ("remount_errno", "1"),
                ("umount_errno", "22"),
                ("bind_errno", "22"),
            ],
        )?;
        Ok(s.summary())
    }

    fn l10(c: &Ctx) -> Check {
        let dir = scratch()?;
        let s = ran(c.step(&["nested-uidmap", dir.as_str()]))?;
        expect(&s, &[("map_errno", "13")])?;
        Ok(s.summary())
    }

    fn l11(c: &Ctx) -> Check {
        let dir = scratch()?;
        let s = ran(c.step(&["mount-after-landlock", dir.as_str()]))?;
        control(&s, &[("before_errno", "0")])?;
        expect(&s, &[("after_errno", "1")])?;
        Ok(s.summary())
    }

    fn l12(c: &Ctx) -> Check {
        let p = probe(c);
        if !p.container {
            return Err(Outcome::NotApplicable("not inside a container".into()));
        }
        match (p.userns_errno, p.landlock_abi) {
            (Some(1), Some(abi)) => Ok(format!("userns errno=1 landlock abi={abi}")),
            (e, abi) => Err(Outcome::Fail {
                expected: "userns errno=1, landlock present".into(),
                observed: format!("userns errno={e:?} abi={abi:?}"),
            }),
        }
    }

    fn l13(c: &Ctx) -> Check {
        if !probe(c).container {
            return Err(Outcome::NotApplicable(
                "/proc is not masked outside a container".into(),
            ));
        }
        let s = ran(c.step(&["proc-mount"]))?;
        expect(&s, &[("ok", "0")])?;
        Ok(s.summary())
    }
}

#[cfg(not(target_os = "linux"))]
mod linux {
    /// Linux probe results; never measured on this OS.
    pub(super) struct Probe;
}

fn catalog() -> &'static [Fact] {
    #[cfg(target_os = "macos")]
    return macos::FACTS;
    #[cfg(target_os = "linux")]
    return linux::FACTS;
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    return &[];
}

fn header(c: &Ctx, sandboxed: Option<bool>) -> String {
    let os = c.step(&["osinfo"]);
    let o = |k: &str| os.obs.get(k).unwrap_or("unknown").to_owned();
    let sys = if cfg!(target_os = "macos") {
        format!("macos {} ({})", o("product"), o("build"))
    } else {
        format!("linux {}", o("kernel"))
    };
    let sandboxed = match sandboxed {
        Some(true) => "yes",
        Some(false) => "no",
        None => "n/a",
    };
    format!(
        "os: {sys} | arch: {} | date: {} | sandboxed: {sandboxed}",
        std::env::consts::ARCH,
        utc_date()
    )
}

fn main() -> ExitCode {
    let filter = std::env::args()
        .skip(1)
        .find(|a| !a.starts_with('-'))
        .unwrap_or_default();
    #[cfg_attr(not(target_os = "linux"), allow(unused_mut))]
    let mut c = Ctx {
        probe: PathBuf::from(env!("CARGO_BIN_EXE_kf-probe")),
        linux: None,
    };
    let mut report = String::from("procage kernel facts\n");
    #[cfg_attr(not(target_os = "linux"), allow(unused_mut))]
    let mut failed = false;

    // The precheck: a Seatbelt-sandboxed runner cannot verify enforcement.
    let sandboxed =
        cfg!(target_os = "macos").then(|| c.step(&["selfcheck"]).obs.get("sandboxed") != Some("0"));
    let _ = writeln!(report, "{}", header(&c, sandboxed));

    #[cfg(target_os = "linux")]
    {
        let p = linux::Probe::measure(&c.probe);
        let _ = writeln!(report, "tier: {}", p.describe());
        if let Ok(want) = std::env::var("PROCAGE_KF_EXPECT_TIER")
            && format!("{:?}", p.tier) != want
        {
            let _ = writeln!(
                report,
                "TIER MISMATCH: expected {want}, measured {:?}",
                p.tier
            );
            failed = true;
        }
        c.linux = Some(p);
    }
    #[cfg(not(target_os = "linux"))]
    let _ = writeln!(report, "tier: -");
    print!("{report}");

    let started = Instant::now();
    let (mut pass, mut fail, mut na, mut setup) = (0, 0, 0, 0);
    for fact in catalog().iter().filter(|f| f.id.starts_with(&filter)) {
        let t = Instant::now();
        let outcome = if fact.kind == Kind::Enforcement && sandboxed == Some(true) {
            Outcome::Fail {
                expected: "a runner outside any Seatbelt sandbox".into(),
                observed: "already inside a Seatbelt sandbox: run `just test-outside` from a terminal that is not inside an agent sandbox".into(),
            }
        } else if let Some(reason) = tier_gap(&c, fact) {
            Outcome::NotApplicable(reason)
        } else {
            match (fact.run)(&c) {
                Ok(observed) => Outcome::Pass(observed),
                Err(o) => o,
            }
        };
        let secs = t.elapsed().as_secs_f64();
        let slow = if fact.slow { " [slow]" } else { "" };
        let line = match &outcome {
            Outcome::Pass(obs) => {
                pass += 1;
                format!(
                    "{} PASS   {secs:6.2}s  {}{slow}\n       observed {obs}\n",
                    fact.id, fact.statement
                )
            }
            Outcome::Fail { expected, observed } => {
                fail += 1;
                format!(
                    "{} FAIL   {secs:6.2}s  {}{slow}\n       expected {expected} observed {observed}\n",
                    fact.id, fact.statement
                )
            }
            Outcome::NotApplicable(reason) => {
                na += 1;
                format!(
                    "{} N/A           {}\n       {reason}\n",
                    fact.id, fact.statement
                )
            }
            Outcome::SetupFailed(detail) => {
                setup += 1;
                format!(
                    "{} SETUP-FAILED {secs:6.2}s  {}\n       {detail}\n",
                    fact.id, fact.statement
                )
            }
        };
        print!("{line}");
        report.push_str(&line);
    }
    let mut tail = String::from("excluded:\n");
    for (what, why) in EXCLUDED {
        let _ = writeln!(tail, "  {what}: {why}");
    }
    let _ = writeln!(
        tail,
        "summary: {pass} pass, {fail} fail, {na} n/a, {setup} setup-failed in {:.1}s",
        started.elapsed().as_secs_f64()
    );
    print!("{tail}");
    report.push_str(&tail);
    write_report(&report);
    if failed || fail > 0 || setup > 0 {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

/// Why `fact` does not apply to the measured Linux tier, if it does not.
fn tier_gap(c: &Ctx, fact: &Fact) -> Option<String> {
    #[cfg(target_os = "linux")]
    if let Some(p) = &c.linux
        && !fact.tiers.is_empty()
        && !fact.tiers.contains(&p.tier)
    {
        return Some(format!("tier {:?}: applies to {:?}", p.tier, fact.tiers));
    }
    let _ = (c, fact);
    None
}

fn write_report(report: &str) {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join("../kernel-facts");
    let os = std::env::consts::OS;
    let arch = std::env::consts::ARCH;
    if std::fs::create_dir_all(&dir).is_ok() {
        let _ = std::fs::write(dir.join(format!("report-{os}-{arch}.txt")), report);
    }
}
