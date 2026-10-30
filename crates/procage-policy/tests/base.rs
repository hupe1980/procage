//! Base profile V1: its content is pinned (it is frozen), it lands in the
//! allow block, it names a terminal only when asked, and it grants nothing
//! personal.

mod common;

use common::*;
use procage_policy::linux::RuleTarget;
use procage_policy::*;

const MACOS_V1: &[&str] = &[
    r#"(allow file-read* (literal "/"))"#,
    r#"(allow file-read* (require-any (literal "/dev/random") (literal "/dev/urandom")))"#,
    r#"(allow file-read* (require-any (subpath "/Library/Preferences/Logging") (subpath "/private/etc") (subpath "/private/var/db/timezone") (subpath "/private/var/select") (subpath "/usr/share")))"#,
    r#"(allow file-read* file-write-data (require-any (literal "/dev/dtracehelper") (literal "/dev/null") (literal "/dev/zero")))"#,
    r#"(allow file-read* file-write-data (subpath "/dev/fd"))"#,
    r#"(allow file-read* process-exec* file-map-executable (require-any (subpath "/System") (subpath "/bin") (subpath "/sbin") (subpath "/usr/bin") (subpath "/usr/lib") (subpath "/usr/libexec") (subpath "/usr/sbin")))"#,
    r#"(allow file-read-metadata (require-any (literal "/Library") (literal "/etc") (literal "/private") (literal "/private/var") (literal "/tmp") (literal "/usr") (literal "/var")))"#,
    r#"(allow ipc-posix-shm-read* (ipc-posix-name "apple.shm.notification_center"))"#,
    r#"(allow mach-lookup (require-any (global-name "com.apple.SystemConfiguration.configd") (global-name "com.apple.oahd") (global-name "com.apple.system.notification_center") (global-name "com.apple.system.opendirectoryd.libinfo") (global-name "com.apple.trustd") (global-name "com.apple.trustd.agent")))"#,
    r#"(allow sysctl-read)"#,
];

const MACOS_TTY: &str = r#"(allow file-read* file-write-data file-ioctl (require-any (literal "/dev/tty") (regex "^/dev/ttys[0-9]+$")))"#;

const LINUX_V1_ABI6: &[(&str, &str, u64)] = &[
    ("path", "/dev/null", 0x6),
    ("path", "/dev/random", 0x4),
    ("path", "/dev/urandom", 0x4),
    ("path", "/dev/zero", 0x6),
    ("path", "/etc", 0xc),
    ("if-exists", "/bin", 0xd),
    ("if-exists", "/lib", 0xd),
    ("if-exists", "/lib32", 0xd),
    ("if-exists", "/lib64", 0xd),
    ("if-exists", "/sbin", 0xd),
    ("if-exists", "/usr", 0xd),
];

fn base(tty: Tty) -> Policy {
    let mut p = Policy::default();
    p.base = Base::V1;
    p.tty = tty;
    p
}

fn allows(p: &Policy) -> Vec<String> {
    seatbelt_plan(p, &LowerOptions::default())
        .profile
        .lines()
        .filter(|l| l.starts_with("(allow"))
        .map(String::from)
        .collect()
}

#[test]
fn macos_content_is_pinned() {
    assert_eq!(allows(&base(Tty::None)), MACOS_V1);
    let mut with_tty: Vec<&str> = MACOS_V1.to_vec();
    with_tty.insert(5, MACOS_TTY);
    assert_eq!(allows(&base(Tty::Inherit)), with_tty);
}

#[test]
fn linux_content_is_pinned() {
    let target = Target::Linux {
        tier: Tier::T2,
        landlock_abi: 6,
    };
    let Ok(Plan::Linux(plan)) = lower(&base(Tty::None), target, &LowerOptions::default()) else {
        panic!("no Linux plan");
    };
    let got: Vec<(&str, String, u64)> = plan
        .landlock
        .rules
        .iter()
        .map(|r| match &r.target {
            RuleTarget::Path(p) => ("path", p.to_string(), r.access.0),
            RuleTarget::PathIfExists(p) => ("if-exists", p.to_string(), r.access.0),
            other => panic!("unexpected base target {other:?}"),
        })
        .collect();
    let want: Vec<(&str, String, u64)> = LINUX_V1_ABI6
        .iter()
        .map(|(k, p, a)| (*k, p.to_string(), *a))
        .collect();
    assert_eq!(got, want);
}

#[test]
fn base_allows_come_before_every_deny() {
    let mut p = base(Tty::Inherit);
    p.fs.push(subpath(Access::Write, "/work"));
    p.fs.push(subpath(Access::Protect, "/work/.git"));
    let profile = seatbelt_plan(&p, &LowerOptions::default()).profile;
    let lines: Vec<&str> = profile.lines().skip(2).collect();
    let last_allow = lines.iter().rposition(|l| l.starts_with("(allow")).unwrap();
    let first_deny = lines.iter().position(|l| l.starts_with("(deny")).unwrap();
    assert!(last_allow < first_deny, "{profile}");
    let tty = lines.iter().position(|l| *l == MACOS_TTY).unwrap();
    let tiocsti = lines
        .iter()
        .position(|l| *l == "(deny file-ioctl (ioctl-command #x80017472))")
        .unwrap();
    assert!(tty < tiocsti);
}

#[test]
fn a_terminal_only_with_inherit() {
    for tty in [Tty::None, Tty::NewPty] {
        assert!(
            allows(&base(tty)).iter().all(|l| !l.contains("/dev/tty")),
            "{tty:?}"
        );
    }
    let target = Target::Linux {
        tier: Tier::T1,
        landlock_abi: 8,
    };
    let tty_rules = |tty| match lower(&base(tty), target, &LowerOptions::default()) {
        Ok(Plan::Linux(plan)) => plan
            .landlock
            .rules
            .iter()
            .filter(|r| {
                format!("{:?}", r.target).contains("/dev/pts")
                    || format!("{:?}", r.target).contains("/dev/tty")
            })
            .count(),
        other => panic!("{other:?}"),
    };
    assert_eq!(tty_rules(Tty::None), 0);
    assert_eq!(tty_rules(Tty::Inherit), 2);
}

#[test]
fn base_services_are_not_hard_denied_services() {
    let hard: Vec<String> = seatbelt_plan(&Policy::default(), &LowerOptions::default())
        .profile
        .lines()
        .filter(|l| l.starts_with("(deny mach-lookup"))
        .map(String::from)
        .collect();
    for service in procage_policy::base::MACOS_SERVICES {
        for line in &hard {
            assert!(!line.contains(service), "{service} is hard-denied: {line}");
        }
        for prefix in [
            "com.apple.lsd.",
            "com.apple.coreservices.",
            "com.apple.pasteboard",
        ] {
            assert!(
                !service.starts_with(prefix),
                "{service} is a handoff service"
            );
        }
    }
}

#[test]
fn base_names_nothing_personal() {
    for p in [base(Tty::None), base(Tty::Inherit)] {
        for line in allows(&p) {
            for personal in [
                "/Users",
                "/private/var/folders",
                "/private/tmp",
                "/Volumes",
                "network",
            ] {
                assert!(!line.contains(personal), "{personal} in {line}");
            }
        }
    }
    assert!(allows(&Policy::default()).is_empty());
}
