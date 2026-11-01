//! The socket hard-deny classes: `service-handoff` on Linux and
//! `container-engines` on both targets.

use procage_policy::presets;
use procage_policy::*;

const TARGETS: [Target; 2] = [
    Target::Linux {
        tier: Tier::T1,
        landlock_abi: 8,
    },
    Target::Linux {
        tier: Tier::T2,
        landlock_abi: 8,
    },
];

const SOCKET_CLASSES: [HardDenyClass; 2] = [
    HardDenyClass::ServiceHandoff,
    HardDenyClass::ContainerEngines,
];

fn linux_plan(p: &Policy, target: Target) -> LinuxPlan {
    match lower(p, target, &LowerOptions::default()) {
        Ok(Plan::Linux(plan)) => plan,
        other => panic!("{target}: {other:?}"),
    }
}

/// Every setting that leaves the child a Unix connect hands the socket
/// classes to the backend; with the network off and no Unix sockets seccomp
/// refuses every socket, so the plan carries none. A waived class is never
/// carried.
#[test]
fn the_backend_gets_the_classes_exactly_when_a_unix_connect_is_possible() {
    let networks = [
        (Network::None, false),
        (Network::All, true),
        (Network::Loopback(Ports::Any), true),
        (
            Network::Proxy {
                http: Some(Port::new(3128).unwrap()),
                socks: None,
            },
            true,
        ),
    ];
    for target in TARGETS {
        for (net, net_reaches) in &networks {
            for sockets in [false, true] {
                for waived in [false, true] {
                    let mut p = Policy::default();
                    p.net = net.clone();
                    if sockets {
                        p.ipc.unix_sockets.push(AbsPath::new("/work/run").unwrap());
                    }
                    if waived {
                        p.waive.extend(SOCKET_CLASSES);
                    }
                    let options = LowerOptions::default()
                        .accept_spawn_snapshot()
                        .allow(Construct::NetLoopback)
                        .allow(Construct::NetProxy);
                    let carried: Vec<HardDenyClass> = match lower(&p, target, &options) {
                        Ok(Plan::Linux(plan)) => {
                            plan.service_sockets.iter().map(|s| s.class).collect()
                        }
                        // Loopback and proxy are refused on Linux, and Unix
                        // sockets on T2 below ABI 9: no plan, so nothing
                        // reaches a socket.
                        Err(LowerError::Gaps(gaps)) => {
                            let t2 = matches!(target, Target::Linux { tier: Tier::T2, .. });
                            assert!(
                                gaps.iter().all(|g| match g.construct {
                                    Construct::NetLoopback | Construct::NetProxy => true,
                                    Construct::IpcUnixSockets => t2 && sockets,
                                    _ => false,
                                }),
                                "{target} {net:?} sockets={sockets}: {gaps:?}"
                            );
                            continue;
                        }
                        other => panic!("{other:?}"),
                    };
                    let expected = if (*net_reaches || sockets) && !waived {
                        SOCKET_CLASSES.to_vec()
                    } else {
                        Vec::new()
                    };
                    assert_eq!(
                        carried, expected,
                        "{target} {net:?} sockets={sockets} waived={waived}"
                    );
                }
            }
        }
    }
}

/// The classes are exact at lowering on every target; whether a socket
/// exists is the backend's question.
#[test]
fn the_socket_classes_lower_exactly() {
    let mut p = Policy::default();
    p.net = Network::All;
    for target in TARGETS {
        let plan = linux_plan(&p, target);
        assert!(plan.degradations.is_empty(), "{target}");
        assert_eq!(plan.service_sockets.len(), 2, "{target}");
    }
    let Ok(Plan::Seatbelt(plan)) = lower(&p, Target::MacOs, &LowerOptions::default()) else {
        panic!("no macOS plan");
    };
    let profile = plan.profile.clone();
    let engines: Vec<&str> = profile
        .lines()
        .filter(|l| l.starts_with("(deny network-outbound"))
        .collect();
    assert_eq!(engines.len(), 1, "{profile}");
    assert!(
        engines[0].contains("[dD][oO][cC][kK][eE][rR]"),
        "{}",
        engines[0]
    );
}

/// Waiving `container-engines` removes exactly its rule on macOS; the
/// service-handoff rules stay.
#[test]
fn a_waiver_removes_exactly_its_class() {
    let mut p = Policy::default();
    p.net = Network::All;
    let mut waived = p.clone();
    waived.waive.insert(HardDenyClass::ContainerEngines);
    let text = |p: &Policy| match lower(p, Target::MacOs, &LowerOptions::default()) {
        Ok(Plan::Seatbelt(plan)) => plan.profile.clone(),
        other => panic!("{other:?}"),
    };
    let (full, without) = (text(&p), text(&waived));
    let removed: Vec<&str> = full.lines().filter(|l| !without.contains(l)).collect();
    assert_eq!(removed.len(), 1, "{removed:?}");
    assert!(removed[0].starts_with("(deny network-outbound"));
    assert!(without.contains("com.apple.coreservices.launchservicesd"));
}

/// The socket lists: absolute or relative as documented, sorted, without
/// duplicates; the class name round-trips.
#[test]
fn the_socket_lists_are_well_formed() {
    for class in SOCKET_CLASSES {
        let paths = presets::linux_socket_paths(class).unwrap();
        assert_eq!(paths.class, class);
        for rel in paths.runtime.iter().chain(&paths.runtime_dirs) {
            assert!(!rel.starts_with('/') && !rel.contains(".."), "{rel}");
        }
        assert!(!paths.system.is_empty() || !paths.runtime.is_empty());
        assert_eq!(class.as_str().parse::<HardDenyClass>().unwrap(), class);
    }
    for list in [
        presets::ENGINE_HOME,
        presets::ENGINE_SYSTEM,
        presets::SERVICE_SOCKETS_LINUX,
        presets::SERVICE_SOCKET_DIRS_LINUX,
        presets::SERVICE_RUNTIME_LINUX,
        presets::SERVICE_RUNTIME_DIRS_LINUX,
        presets::ENGINE_SOCKETS_LINUX,
        presets::ENGINE_SOCKET_DIRS_LINUX,
        presets::ENGINE_RUNTIME_LINUX,
        presets::ENGINE_RUNTIME_DIRS_LINUX,
    ] {
        let mut sorted = list.to_vec();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted, list, "sorted and unique");
    }
    assert!(presets::linux_socket_paths(HardDenyClass::Secrets).is_none());
    assert!(!presets::patterns(HardDenyClass::ContainerEngines).is_empty());
}

/// Every macOS engine entry matches a socket at its documented place, and
/// nothing beside it.
#[test]
fn every_engine_entry_matches_its_socket() {
    use procage_policy::linux::may_overlap;
    let samples = [
        "/Users/u/.colima/default/containerd.sock",
        "/Users/u/.colima/default/docker.sock",
        "/Users/u/.docker/run/docker.sock",
        "/Users/u/.lima/vm/sock/docker.sock",
        "/Users/u/.local/share/containers/podman/machine/qemu/podman.sock",
        "/Users/u/.orbstack/run/docker.sock",
        "/Users/u/.rd/docker.sock",
    ];
    assert_eq!(samples.len(), presets::ENGINE_HOME.len());
    for (rel, sample) in presets::ENGINE_HOME.iter().zip(samples) {
        let pattern = format!("/Users/*/{rel}");
        assert!(
            may_overlap(&pattern, sample.as_bytes()),
            "{pattern} {sample}"
        );
    }
    assert!(
        !presets::ENGINE_HOME
            .iter()
            .any(|rel| may_overlap(&format!("/Users/*/{rel}"), b"/Users/u/work/app.sock"))
    );
}

/// The site's hard-deny page names every entry of the socket lists, so the
/// published list and the enforced one cannot drift apart.
#[test]
fn the_docs_list_every_socket() {
    let page = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../site/content/docs/hard-deny.md");
    let Ok(page) = std::fs::read_to_string(&page) else {
        // Outside the repository (a packaged crate) there is no site.
        return;
    };
    for list in [
        presets::ENGINE_HOME,
        presets::ENGINE_SYSTEM,
        presets::SERVICE_SOCKETS_LINUX,
        presets::SERVICE_SOCKET_DIRS_LINUX,
        presets::SERVICE_RUNTIME_LINUX,
        presets::SERVICE_RUNTIME_DIRS_LINUX,
        presets::SERVICE_ABSTRACT_LINUX,
        presets::ENGINE_SOCKETS_LINUX,
        presets::ENGINE_SOCKET_DIRS_LINUX,
        presets::ENGINE_RUNTIME_LINUX,
        presets::ENGINE_RUNTIME_DIRS_LINUX,
    ] {
        for entry in list {
            assert!(
                page.contains(&format!("`{entry}")),
                "{entry} is not on the hard-deny page"
            );
        }
    }
}
