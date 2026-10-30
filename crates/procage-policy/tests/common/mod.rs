//! Shared test helpers: a deterministic generator, a strict SBPL string
//! decoder, reference policies and a reference evaluator for SBPL rules.

#![allow(dead_code)]

use procage_policy::linux;
use procage_policy::sbpl::{Filter, Rule};
use procage_policy::seatbelt::{self, Effect, Operation};
use procage_policy::*;

/// Cases per generated-input property.
pub const CASES: usize = 10_000;

/// xorshift64*: deterministic, seeded, good enough for test inputs.
pub struct Rng(u64);

impl Rng {
    pub fn new(seed: u64) -> Self {
        Self(seed.max(1))
    }

    pub fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    pub fn below(&mut self, n: usize) -> usize {
        (self.next_u64() % n as u64) as usize
    }

    pub fn chance(&mut self, percent: usize) -> bool {
        self.below(100) < percent
    }

    pub fn pick<'a, T>(&mut self, items: &'a [T]) -> &'a T {
        &items[self.below(items.len())]
    }

    pub fn shuffle<T>(&mut self, items: &mut [T]) {
        for i in (1..items.len()).rev() {
            items.swap(i, self.below(i + 1));
        }
    }

    /// Bytes biased toward characters that matter to SBPL, regexes and
    /// paths, plus control bytes and invalid UTF-8.
    pub fn nasty_bytes(&mut self, max_len: usize) -> Vec<u8> {
        const SPECIAL: &[u8] = b"\"\\()*?[]{}.^$|+/ #;'`\n\t\r\x00\x7f\xff\xc3\xa9";
        let len = self.below(max_len + 1);
        (0..len)
            .map(|_| {
                if self.chance(50) {
                    *self.pick(SPECIAL)
                } else {
                    (self.next_u64() & 0xff) as u8
                }
            })
            .collect()
    }

    /// A string of printable characters biased toward glob and regex syntax.
    pub fn nasty_text(&mut self, max_len: usize) -> String {
        const CHARS: &[char] = &[
            '/', '/', '/', 'a', 'b', 'z', '0', '.', '*', '*', '?', '\\', '[', ']', '{', '}', '(',
            ')', '^', '$', '|', '+', '"', ' ', 'é', '-', '_',
        ];
        let len = self.below(max_len + 1);
        let mut s = String::from("/");
        for _ in 0..len {
            s.push(*self.pick(CHARS));
        }
        s
    }
}

/// Reads one SBPL string literal (`"…"`), knowing only the escapes `\\` and
/// `\"`. Returns `None` for anything else, including trailing text.
pub fn decode_sbpl_string(text: &str) -> Option<Vec<u8>> {
    let inner = text.strip_prefix('"')?.strip_suffix('"')?;
    let mut out = Vec::new();
    let mut chars = inner.chars();
    while let Some(c) = chars.next() {
        match c {
            '\\' => match chars.next()? {
                '\\' => out.push(b'\\'),
                '"' => out.push(b'"'),
                _ => return None,
            },
            '"' => return None,
            c => {
                let mut buf = [0; 4];
                out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
            }
        }
    }
    Some(out)
}

/// Every quoted string in a profile line, decoded; `None` if any is
/// malformed or a quote is unbalanced.
pub fn quoted_strings(line: &str) -> Option<Vec<Vec<u8>>> {
    let mut out = Vec::new();
    let bytes = line.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'"' {
            let start = i;
            i += 1;
            while i < bytes.len() && bytes[i] != b'"' {
                if bytes[i] == b'\\' {
                    i += 1;
                }
                i += 1;
            }
            if i >= bytes.len() {
                return None;
            }
            out.push(decode_sbpl_string(&line[start..=i])?);
        }
        i += 1;
    }
    Some(out)
}

pub fn path(s: &str) -> AbsPath {
    AbsPath::new(s).unwrap()
}

pub fn glob(s: &str) -> Glob {
    Glob::new(s).unwrap()
}

pub fn subpath(access: Access, p: &str) -> FsRule {
    FsRule::new(access, FsTarget::Subpath(path(p)))
}

pub fn port(n: u16) -> Port {
    Port::new(n).unwrap()
}

pub fn ports(list: &[u16]) -> Ports {
    Ports::List(list.iter().map(|&n| port(n)).collect())
}

pub fn grant(name: &str, access: Access) -> Grant {
    Grant {
        name: GrantName::new(name).unwrap(),
        access,
    }
}

/// A policy with a writable root, so that every hard-deny class (rename
/// anchors included) has input on every target.
pub fn hard_deny_base() -> Policy {
    let mut p = Policy::default();
    p.fs.push(subpath(Access::Write, "/work"));
    p
}

/// The smallest policy that exercises `construct`.
pub fn reference_policy(construct: Construct) -> Policy {
    let mut p = Policy::default();
    match construct {
        Construct::FsReadSubpath => p.fs.push(subpath(Access::Read, "/work")),
        Construct::FsWriteSubpath => p.fs.push(subpath(Access::Write, "/work")),
        Construct::FsExecSubpath => p.fs.push(subpath(Access::Exec, "/usr/bin")),
        Construct::FsLiteral => p.fs.push(FsRule::new(
            Access::Read,
            FsTarget::Literal(path("/etc/hosts")),
        )),
        Construct::FsGlob => p.fs.push(FsRule::new(
            Access::Read,
            FsTarget::Glob(glob("/work/**/*.rs")),
        )),
        Construct::FsProtect => {
            p.fs.push(subpath(Access::Write, "/work"));
            p.fs.push(subpath(Access::Protect, "/work/.git"));
        }
        Construct::FsHide => {
            p.fs.push(subpath(Access::Read, "/work"));
            p.fs.push(subpath(Access::Hide, "/work/secret"));
        }
        Construct::Grant => p.grants.push(grant("scratch", Access::Write)),
        Construct::NetNone => p.net = Network::None,
        Construct::NetLoopback => p.net = Network::Loopback(ports(&[8080])),
        Construct::NetUnixSockets => p.net = Network::UnixSockets(vec![path("/tmp/agent.sock")]),
        Construct::NetProxy => {
            p.net = Network::Proxy {
                http: Some(port(3128)),
                socks: None,
            }
        }
        Construct::NetAll => p.net = Network::All,
        Construct::ExecAny => p.process.exec = Exec::Any,
        Construct::ExecNever => p.process.exec = Exec::Never,
        Construct::ForkDenied => p.process.fork = false,
        Construct::SignalsSelfAndChildren => p.process.signals = Signals::SelfAndChildren,
        Construct::SignalsNone => p.process.signals = Signals::None,
        Construct::PosixShm => p.ipc.posix_shm = true,
        Construct::SysvIpc => p.ipc.sysv = true,
        Construct::SeatbeltLayer => {
            p.seatbelt = Some(seatbelt::Layer {
                rules: vec![seatbelt::Rule {
                    effect: Effect::Allow,
                    ops: vec![Operation::SysctlRead],
                    filters: vec![],
                }],
            })
        }
        Construct::LinuxLayer => {
            p.linux = Some(linux::Layer {
                syscalls_deny: vec![linux::Syscall::from_name("acct").unwrap()],
                landlock_extra: vec![],
            })
        }
        Construct::Hygiene => {
            p.env = EnvPolicy::Allowlist(vec!["PATH".into(), "HOME".into()]);
            p.limits.nofile = Some(1024);
            p.tty = Tty::None;
        }
        _ => p = hard_deny_base(),
    }
    p
}

/// The class of a hard-deny construct.
pub fn class_of(construct: Construct) -> Option<HardDenyClass> {
    HardDenyClass::ALL
        .iter()
        .copied()
        .find(|&c| Construct::of_class(c) == construct)
}

/// A coding-agent workspace.
pub fn agent_workspace() -> Policy {
    let mut p = Policy::default();
    p.fs.push(subpath(Access::Write, "/work"));
    p.fs.push(subpath(Access::Protect, "/work/.git"));
    p.fs.push(subpath(Access::Hide, "/work/.env"));
    p.fs.push(subpath(Access::Read, "/usr"));
    p.fs.push(subpath(Access::Exec, "/usr/bin"));
    p.fs.push(FsRule::new(
        Access::Read,
        FsTarget::Literal(path("/etc/hosts")),
    ));
    p.grants.push(grant("scratch", Access::Write));
    p.net = Network::Proxy {
        http: Some(port(3128)),
        socks: Some(port(1080)),
    };
    p.process.fork = true;
    p.process.signals = Signals::SelfAndChildren;
    p.env = EnvPolicy::Allowlist(vec!["PATH".into()]);
    p
}

/// A build.
pub fn build() -> Policy {
    let mut p = Policy::default();
    p.fs.push(subpath(Access::Write, "/work"));
    p.fs.push(subpath(Access::Read, "/usr"));
    p.fs.push(subpath(Access::Exec, "/usr/bin"));
    p.fs.push(FsRule::new(
        Access::Read,
        FsTarget::Glob(glob("/opt/**/*.so")),
    ));
    p.net = Network::Loopback(Ports::Any);
    p.process.fork = true;
    p.ipc.posix_shm = true;
    p
}

/// Read-only access to a tree.
pub fn read_only() -> Policy {
    let mut p = Policy::default();
    p.fs.push(subpath(Access::Read, "/work"));
    p
}

/// One reference policy per construct plus the composites.
pub fn reference_policies() -> Vec<(String, Policy)> {
    let mut out: Vec<(String, Policy)> = Construct::ALL
        .iter()
        .map(|c| (c.as_str().to_string(), reference_policy(*c)))
        .collect();
    out.push(("agent-workspace".into(), agent_workspace()));
    out.push(("build".into(), build()));
    out.push(("read-only".into(), read_only()));
    out
}

/// Every target the tests lower for.
pub fn targets() -> Vec<Target> {
    let mut out = vec![Target::MacOs];
    for abi in [1, 4, 6, 8, 9, 12] {
        out.push(Target::Linux {
            tier: Tier::T1,
            landlock_abi: abi,
        });
    }
    for abi in [4, 5, 6, 8, 9, 12] {
        out.push(Target::Linux {
            tier: Tier::T2,
            landlock_abi: abi,
        });
    }
    out
}

/// Options that accept every approximation.
pub fn allow_all() -> LowerOptions {
    Construct::ALL
        .iter()
        .fold(LowerOptions::default(), |o, &c| o.allow(c))
}

/// Shuffles every order-free list of a policy.
pub fn shuffled(policy: &Policy, rng: &mut Rng) -> Policy {
    let mut p = policy.clone();
    rng.shuffle(&mut p.fs);
    rng.shuffle(&mut p.grants);
    if let Network::UnixSockets(paths) = &mut p.net {
        rng.shuffle(paths);
    }
    if let Some(layer) = &mut p.seatbelt {
        rng.shuffle(&mut layer.rules);
    }
    if let Some(layer) = &mut p.linux {
        rng.shuffle(&mut layer.syscalls_deny);
        rng.shuffle(&mut layer.landlock_extra);
    }
    p
}

pub fn seatbelt_plan(policy: &Policy, options: &LowerOptions) -> SeatbeltPlan {
    match lower(policy, Target::MacOs, options) {
        Ok(Plan::Seatbelt(plan)) => plan,
        other => panic!("expected a Seatbelt plan, got {other:?}"),
    }
}

/// A request for the reference evaluator.
#[derive(Debug, Clone)]
pub struct Request {
    pub op: &'static str,
    pub path: Vec<u8>,
    pub extension: Option<String>,
}

fn op_matches(rule_op: &str, op: &str) -> bool {
    match rule_op.strip_suffix('*') {
        Some(prefix) => op.starts_with(prefix),
        None => rule_op == op,
    }
}

fn filter_matches(filter: &Filter, req: &Request) -> bool {
    match filter {
        Filter::Literal(p) => *p == req.path,
        Filter::Subpath(p) => {
            req.path.starts_with(p)
                && (req.path.len() == p.len() || p == b"/" || req.path[p.len()] == b'/')
        }
        Filter::Extension(class) => req.extension.as_deref() == Some(class.as_str()),
        other => panic!("the reference evaluator does not model {other:?}"),
    }
}

/// Last match wins, default deny; filters are alternatives, no filter
/// matches everything.
pub fn eval(rules: &[Rule], req: &Request) -> Effect {
    let mut decision = Effect::Deny;
    for rule in rules {
        let op = rule.ops.iter().any(|o| op_matches(o, req.op));
        let filter = rule.filters.is_empty() || rule.filters.iter().any(|f| filter_matches(f, req));
        if op && filter {
            decision = rule.effect;
        }
    }
    decision
}
