//! The base profiles: their content is pinned (each is frozen), they land in
//! the allow block, they name a terminal only when asked, and they grant
//! nothing personal.

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

/// What base V2 adds to V1, rendered (frozen).
const MACOS_V2_ADDED: &[&str] = &[
    r#"(allow file-read* (require-any (subpath "/Library/Perl") (subpath "/Library/Ruby") (literal "/Library/Preferences/.GlobalPreferences.plist") (literal "/Library/Preferences/com.apple.dt.Xcode.plist") (literal "/dev/autofs_nowait") (literal "/private/var/db/xcode_select_link") (regex "^/Users/[^/]+/\\.CFUserTextEncoding$") (regex "^/(opt/homebrew|usr/local)/etc/(openssl@[0-9.]+/(openssl\\.cnf|cert\\.pem|certs(/.*)?)|ca-certificates/cert\\.pem)$")))"#,
    r#"(allow file-read* process-exec* file-map-executable (require-any (subpath "/Library/Developer/CommandLineTools") (subpath "/opt/homebrew/Caskroom") (subpath "/opt/homebrew/Cellar") (subpath "/opt/homebrew/Frameworks") (subpath "/opt/homebrew/bin") (subpath "/opt/homebrew/include") (subpath "/opt/homebrew/lib") (subpath "/opt/homebrew/libexec") (subpath "/opt/homebrew/opt") (subpath "/opt/homebrew/sbin") (subpath "/opt/homebrew/share") (subpath "/usr/local/Cellar") (subpath "/usr/local/Frameworks") (subpath "/usr/local/bin") (subpath "/usr/local/include") (subpath "/usr/local/lib") (subpath "/usr/local/libexec") (subpath "/usr/local/opt") (subpath "/usr/local/sbin") (subpath "/usr/local/share") (regex "^/Applications/Xcode[^/]*\\.app/Contents/")))"#,
    r#"(allow file-read-metadata (require-any (literal "/Applications") (literal "/Library/Developer") (literal "/Users") (literal "/opt") (literal "/opt/homebrew") (literal "/opt/homebrew/etc") (literal "/private/var/db") (literal "/usr/local") (literal "/usr/local/etc") (regex "^/private/var/folders(/[^/]+){0,3}$") (regex "^/Users/[^/]+$") (regex "^/Applications/Xcode[^/]*\\.app(/Contents)?$")))"#,
];

fn v2(tty: Tty) -> Policy {
    let mut p = base(tty);
    p.base = Base::V2;
    p
}

#[test]
fn macos_v2_is_v1_plus_its_pinned_additions() {
    for tty in [Tty::None, Tty::Inherit] {
        let v1 = allows(&base(tty));
        let v2 = allows(&v2(tty));
        assert!(v1.iter().all(|l| v2.contains(l)), "V2 must contain V1");
        let added: Vec<&str> = v2
            .iter()
            .filter(|l| !v1.contains(l))
            .map(String::as_str)
            .collect();
        let mut expected = MACOS_V2_ADDED.to_vec();
        expected.sort_unstable();
        let mut added_sorted = added.clone();
        added_sorted.sort_unstable();
        assert_eq!(added_sorted, expected, "{tty:?}");
    }
    // V1 itself is unchanged by V2's existence.
    assert_eq!(allows(&base(Tty::None)), MACOS_V1);
}

/// An SBPL rule with no filter applies everywhere: no base rule may lack
/// one, except V1's unconditional `sysctl-read`.
#[test]
fn every_base_rule_has_a_filter() {
    for p in [
        base(Tty::None),
        base(Tty::Inherit),
        v2(Tty::None),
        v2(Tty::Inherit),
    ] {
        for line in allows(&p) {
            if line == "(allow sysctl-read)" {
                continue;
            }
            assert!(
                line.matches('(').count() > 1,
                "unfiltered base rule: {line}"
            );
        }
    }
    let rules = procage_policy::base::macos_v2(Tty::Inherit);
    assert!(
        rules
            .iter()
            .all(|r| !r.filters.is_empty() || r.ops == ["sysctl-read"])
    );
}

/// V2 looks up no Mach service beyond V1: `com.apple.bsd.dirhelper` and
/// `com.apple.system.opendirectoryd.membership` would make tools use the
/// user's shared temporary directory.
#[test]
fn v2_adds_no_service() {
    let services = |p: &Policy| -> Vec<String> {
        allows(p)
            .into_iter()
            .filter(|l| l.contains("mach-lookup") || l.contains("global-name"))
            .collect()
    };
    assert_eq!(services(&v2(Tty::None)), services(&base(Tty::None)));
    for line in allows(&v2(Tty::None)) {
        assert!(
            !line.contains("dirhelper") && !line.contains("membership"),
            "{line}"
        );
    }
}

#[test]
fn linux_v2_is_linux_v1() {
    for target in [
        Target::Linux {
            tier: Tier::T1,
            landlock_abi: 6,
        },
        Target::Linux {
            tier: Tier::T2,
            landlock_abi: 6,
        },
    ] {
        let rules = |p: &Policy| match lower(p, target, &LowerOptions::default()) {
            Ok(Plan::Linux(plan)) => plan.landlock.rules,
            other => panic!("{other:?}"),
        };
        assert_eq!(rules(&v2(Tty::None)), rules(&base(Tty::None)));
        assert_eq!(rules(&v2(Tty::Inherit)), rules(&base(Tty::Inherit)));
    }
}

/// Under V2 the directories on the way to the policy's own paths can be
/// examined (not listed), so resolving a granted path works; V1 does not.
#[test]
fn v2_allows_metadata_of_the_policys_ancestors() {
    let rule = r#"(allow file-read-metadata (require-any (literal "/Users") (literal "/Users/a") (literal "/Users/a/proj")))"#;
    let mut p = v2(Tty::None);
    p.fs.push(FsRule::new(
        Access::Write,
        FsTarget::Subpath(AbsPath::new("/Users/a/proj/ws").unwrap()),
    ));
    assert!(allows(&p).iter().any(|l| l == rule), "{:#?}", allows(&p));
    p.base = Base::V1;
    assert!(!allows(&p).iter().any(|l| l == rule));
    // A policy without paths below the root adds nothing.
    assert_eq!(
        allows(&v2(Tty::None)).len(),
        MACOS_V1.len() + MACOS_V2_ADDED.len()
    );
}

fn macos_profile(p: &Policy) -> String {
    match lower(p, Target::MacOs, &allow_all()) {
        Ok(Plan::Seatbelt(plan)) => plan.profile,
        other => panic!("{other:?}"),
    }
}

/// V3 allows nothing V2 does not: removing its quiet lines gives the
/// V2 profile of the same policy, for every reference policy.
#[test]
fn v3_is_v2_plus_quiet_denies() {
    for (name, mut policy) in reference_policies() {
        policy.base = Base::V2;
        let v2 = macos_profile(&policy);
        policy.base = Base::V3;
        let v3 = macos_profile(&policy);
        let stripped: String = v3
            .lines()
            .filter(|l| !l.ends_with(" (with no-report))"))
            .map(|l| format!("{l}\n"))
            .collect();
        assert_eq!(stripped, v2, "{name}");
        assert_eq!(v3.lines().count() - v2.lines().count(), 3, "{name}");
    }
}

/// No quiet target is the target of a hard-deny or data-class rule,
/// so silencing never hides an attempt on them.
#[test]
fn quiet_targets_are_not_hard_deny_targets() {
    let mut policy = hard_deny_base();
    policy.base = Base::V3;
    let hard: Vec<String> = macos_profile(&hard_deny_base())
        .lines()
        .filter(|l| l.starts_with("(deny") && !l.starts_with("(deny default"))
        .map(String::from)
        .collect();
    for service in base::MACOS_V3_QUIET_SERVICES {
        assert!(hard.iter().all(|l| !l.contains(service)), "{service}");
    }
    for path in ["/dev/dtracehelper", "/dev/tty"] {
        assert!(
            hard.iter().all(|l| !l.contains(&format!("\"{path}\""))),
            "{path}"
        );
    }
    let quiet: Vec<String> = macos_profile(&policy)
        .lines()
        .filter(|l| l.ends_with(" (with no-report))"))
        .map(String::from)
        .collect();
    assert_eq!(quiet.len(), 3, "{quiet:?}");
}

/// On Linux, V3 is V2.
#[test]
fn v3_lowers_like_v2_on_linux() {
    for (name, mut policy) in reference_policies() {
        for target in targets().into_iter().filter(|t| *t != Target::MacOs) {
            policy.base = Base::V2;
            let v2 = lower(&policy, target, &allow_all());
            policy.base = Base::V3;
            let v3 = lower(&policy, target, &allow_all());
            assert_eq!(v2, v3, "{name} on {target}");
        }
    }
}
