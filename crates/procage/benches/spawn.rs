//! Spawn benchmarks: what a caged spawn costs next to a plain one and next to
//! the tools others shell out to.
//!
//! `cargo bench -p procage --bench spawn` (add `-- --quick` for a short run).
//! Each case spawns a no-op program and waits for it; the table gives the
//! median, p90 and p99 and the median's overhead over a plain spawn. Run it
//! outside any other sandbox; numbers are only comparable on one machine.

use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use procage::native::{Cage, CageOptions, Grants};
use procage::policy::{Policy, presets};

#[cfg(target_os = "macos")]
const TRUE: &str = "/usr/bin/true";
#[cfg(target_os = "linux")]
const TRUE: &str = "/bin/true";

fn command() -> Command {
    let mut c = Command::new(TRUE);
    c.stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    c
}

struct Stats {
    median: Duration,
    p90: Duration,
    p99: Duration,
}

fn measure(iterations: usize, mut run: impl FnMut()) -> Stats {
    for _ in 0..iterations.min(20) {
        run();
    }
    let mut times: Vec<Duration> = (0..iterations)
        .map(|_| {
            let start = Instant::now();
            run();
            start.elapsed()
        })
        .collect();
    times.sort();
    let at = |q: f64| times[((times.len() - 1) as f64 * q).round() as usize];
    Stats {
        median: at(0.5),
        p90: at(0.9),
        p99: at(0.99),
    }
}

fn spawn_in(cage: &Cage) {
    let mut child = cage.spawn(&mut command(), &Grants::new()).expect("spawn");
    child.wait().expect("wait");
}

fn host() -> String {
    let os = |args: &[&str]| {
        Command::new(args[0])
            .args(&args[1..])
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
            .unwrap_or_default()
    };
    if cfg!(target_os = "macos") {
        format!(
            "{} | macOS {} ({}) | {}",
            os(&["/usr/sbin/sysctl", "-n", "machdep.cpu.brand_string"]),
            os(&["/usr/bin/sw_vers", "-productVersion"]),
            os(&["/usr/bin/sw_vers", "-buildVersion"]),
            std::env::consts::ARCH
        )
    } else {
        format!(
            "{} | Linux {} | {}",
            std::fs::read_to_string("/proc/cpuinfo")
                .ok()
                .and_then(|c| c
                    .lines()
                    .find(|l| l.starts_with("model name") || l.starts_with("CPU part"))
                    .map(|l| l.split(':').nth(1).unwrap_or("").trim().to_string()))
                .unwrap_or_default(),
            os(&["uname", "-r"]),
            std::env::consts::ARCH
        )
    }
}

fn main() {
    let quick = std::env::args().any(|a| a == "--quick");
    let n = if quick { 30 } else { 300 };
    #[cfg(target_os = "macos")]
    if procage::macos::is_sandboxed().unwrap_or(false) {
        eprintln!("refusing to measure inside another sandbox: run from a plain terminal");
        std::process::exit(2);
    }
    let policy: Policy = presets::minimal::v3();
    let mut rows: Vec<(String, Stats)> = Vec::new();
    rows.push((
        "plain spawn".into(),
        measure(n, || {
            command().status().expect("plain");
        }),
    ));
    #[cfg(target_os = "linux")]
    let tiers: Vec<procage::policy::Tier> = match procage::linux::probe().tier {
        Some(procage::policy::Tier::T1) => {
            vec![procage::policy::Tier::T1, procage::policy::Tier::T2]
        }
        Some(t) => vec![t],
        None => vec![],
    };
    #[cfg(target_os = "macos")]
    let tiers: Vec<()> = vec![()];
    for tier in tiers {
        #[cfg(target_os = "linux")]
        let (label, options) = (format!(" ({tier})"), CageOptions::default().with_tier(tier));
        #[cfg(target_os = "macos")]
        let (label, options) = {
            let () = tier;
            (String::new(), CageOptions::default())
        };
        let cage = Cage::with_options(&policy, &options).expect("cage");
        rows.push((
            format!("procage, cached cage{label}"),
            measure(n, || spawn_in(&cage)),
        ));
        let unchecked = Cage::with_options(
            &policy,
            &options.clone().with_link_audit(procage::LinkAudit::Off),
        )
        .expect("cage");
        rows.push((
            format!("procage, cached cage, link check off{label}"),
            measure(n, || spawn_in(&unchecked)),
        ));
        // A policy no earlier spawn had: the profile is compiled (macOS) or
        // the plan lowered anew for every spawn.
        let mut fresh = 0u64;
        rows.push((
            format!("procage, new policy per spawn{label}"),
            measure(n / 3, || {
                fresh += 1;
                let mut p = policy.clone();
                let dir = std::env::temp_dir()
                    .join(format!("procage-bench-{}-{fresh}", std::process::id()));
                std::fs::create_dir_all(&dir).expect("bench directory");
                p.fs.push(procage::policy::FsRule::new(
                    procage::policy::Access::Read,
                    procage::policy::FsTarget::Subpath(
                        procage::policy::AbsPath::new(dir.to_str().unwrap()).unwrap(),
                    ),
                ));
                let cage = Cage::with_options(&p, &options).expect("cage");
                spawn_in(&cage);
                let _ = std::fs::remove_dir(&dir);
            }),
        ));
        let reporting = Cage::with_options(&policy, &options.clone().with_violations())
            .expect("cage with reporting");
        rows.push((
            format!("procage, with violation reporting{label}"),
            measure(n, || spawn_in(&reporting)),
        ));
    }
    #[cfg(target_os = "macos")]
    {
        let cage = Cage::new(&policy).expect("cage");
        let profile = cage.plan().profile.clone();
        rows.push((
            "sandbox-exec -p (same profile)".into(),
            measure(n, || {
                Command::new("/usr/bin/sandbox-exec")
                    .args(["-p", &profile, TRUE])
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status()
                    .expect("sandbox-exec");
            }),
        ));
    }
    #[cfg(target_os = "linux")]
    {
        let bwrap = ["/usr/bin/bwrap", "/bin/bwrap"]
            .into_iter()
            .find(|p| std::path::Path::new(p).exists());
        match bwrap {
            Some(bwrap) => {
                let ok = Command::new(bwrap)
                    .args(["--ro-bind", "/", "/", "--unshare-all", TRUE])
                    .status()
                    .is_ok_and(|s| s.success());
                if ok {
                    rows.push((
                        "bwrap --ro-bind / / --unshare-all".into(),
                        measure(n, || {
                            Command::new(bwrap)
                                .args(["--ro-bind", "/", "/", "--unshare-all", TRUE])
                                .stdin(Stdio::null())
                                .stdout(Stdio::null())
                                .stderr(Stdio::null())
                                .status()
                                .expect("bwrap");
                        }),
                    ));
                } else {
                    println!("bwrap cannot run here (no user namespaces): skipped");
                }
            }
            None => println!("bwrap is not installed: skipped"),
        }
    }
    let plain = rows[0].1.median;
    println!("{}", host());
    println!(
        "{n} iterations per case{}",
        if quick { " (quick)" } else { "" }
    );
    println!("| case | median | p90 | p99 | overhead (median) |");
    println!("|---|---|---|---|---|");
    for (name, s) in &rows {
        let overhead = s.median.saturating_sub(plain);
        println!(
            "| {name} | {:.3} ms | {:.3} ms | {:.3} ms | {:.3} ms |",
            s.median.as_secs_f64() * 1e3,
            s.p90.as_secs_f64() * 1e3,
            s.p99.as_secs_f64() * 1e3,
            overhead.as_secs_f64() * 1e3
        );
    }
}
