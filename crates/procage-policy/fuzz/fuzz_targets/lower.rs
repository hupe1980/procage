//! Lowering never panics, for any policy and target, and is deterministic.

#![no_main]

use libfuzzer_sys::fuzz_target;
use procage_policy::*;

/// Builds a policy from bytes: each byte picks an action, following bytes
/// supply its arguments.
fn build(data: &[u8]) -> (Policy, LowerOptions, Vec<Target>) {
    let mut p = Policy::default();
    let mut options = LowerOptions::default();
    let mut bytes = data.iter().copied();
    let mut next = move || bytes.next();
    let text = |next: &mut dyn FnMut() -> Option<u8>| -> Vec<u8> {
        let len = next().unwrap_or(0) % 12;
        let mut out = vec![b'/'];
        for _ in 0..len {
            out.push(next().unwrap_or(b'a'));
        }
        out
    };
    let mut targets = vec![Target::MacOs];
    while let Some(op) = next() {
        match op % 12 {
            0..=3 => {
                let access = [Access::Read, Access::Write, Access::Exec, Access::Protect, Access::Hide]
                    [usize::from(next().unwrap_or(0)) % 5];
                let raw = text(&mut next);
                let target = match next().unwrap_or(0) % 3 {
                    0 => AbsPath::new(raw).ok().map(FsTarget::Subpath),
                    1 => AbsPath::new(raw).ok().map(FsTarget::Literal),
                    _ => String::from_utf8(raw).ok().and_then(|t| Glob::new(&t).ok()).map(FsTarget::Glob),
                };
                if let Some(target) = target {
                    p.fs.push(FsRule::new(access, target));
                }
            }
            4 => {
                let port = Port::new(u16::from(next().unwrap_or(1)).max(1)).unwrap();
                p.net = match next().unwrap_or(0) % 5 {
                    0 => Network::None,
                    1 => Network::Loopback(Ports::List([port].into())),
                    2 => Network::Proxy { http: Some(port), socks: None },
                    3 => Network::Ip,
                    _ => Network::All,
                };
            }
            5 => {
                p.process.exec = [Exec::Granted, Exec::Any, Exec::Never][usize::from(next().unwrap_or(0)) % 3];
                p.process.fork = next().unwrap_or(0) % 2 == 0;
                p.process.signals = if next().unwrap_or(0) % 2 == 0 { Signals::None } else { Signals::SelfAndChildren };
            }
            6 => {
                p.ipc.posix_shm = next().unwrap_or(0) % 2 == 0;
                p.ipc.sysv = next().unwrap_or(0) % 2 == 0;
                p.ipc.unix_sockets.extend(AbsPath::new(text(&mut next)));
            }
            7 => {
                let name = format!("g{}", next().unwrap_or(0) % 4);
                let access = [Access::Read, Access::Write, Access::Exec, Access::Hide][usize::from(next().unwrap_or(0)) % 4];
                p.grants.push(Grant { name: GrantName::new(&name).unwrap(), access });
            }
            8 => {
                let class = HardDenyClass::ALL[usize::from(next().unwrap_or(0)) % HardDenyClass::ALL.len()];
                p.waive.insert(class);
            }
            9 => {
                let construct = Construct::ALL[usize::from(next().unwrap_or(0)) % Construct::ALL.len()];
                options = options.allow(construct);
            }
            10 => {
                let tier = if next().unwrap_or(0) % 2 == 0 { Tier::T1 } else { Tier::T2 };
                targets.push(Target::Linux { tier, landlock_abi: next().unwrap_or(0) % 16 });
            }
            _ => options = options.with_max_rules(usize::from(next().unwrap_or(0))),
        }
    }
    (p, options, targets)
}

fuzz_target!(|data: &[u8]| {
    let (policy, options, targets) = build(data);
    for target in targets {
        let first = lower(&policy, target, &options);
        assert_eq!(first, lower(&policy, target, &options));
    }
});
