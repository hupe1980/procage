//! A cage's own proxy (feature `proxy`): each run reaches the hosts its
//! allowlist names through its own listener, and no other route. The test
//! binary runs itself as the caged child (`child_entry`), selected by
//! `PROCAGE_CHILD`.

use std::io::{Read, Write};
use std::net::{IpAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use procage::native::{Cage, CageOptions, Grants};
use procage::policy::{AbsPath, Access, FsRule, FsTarget, Network, Policy, Port};
use procage::proxy::{Allowlist, Proxy, Resolve};

fn abs(p: impl AsRef<Path>) -> AbsPath {
    AbsPath::new(p.as_ref().as_os_str().as_encoded_bytes()).unwrap()
}

fn exe() -> PathBuf {
    std::fs::canonicalize(std::env::current_exe().unwrap()).unwrap()
}

/// A policy that runs this test binary with the network through a proxy
/// (HTTP and SOCKS5; the ports are the policy's, not the run's).
fn policy() -> Policy {
    let mut p = Policy::default();
    #[cfg(target_os = "macos")]
    {
        use procage::policy::seatbelt;
        for dir in ["/usr/lib", "/System", "/bin", "/usr/bin"] {
            p.fs.push(FsRule::new(Access::Exec, FsTarget::Subpath(abs(dir))));
        }
        p.fs.push(FsRule::new(Access::Read, FsTarget::Literal(abs("/"))));
        p.fs.push(FsRule::new(Access::Exec, FsTarget::Literal(abs(exe()))));
        p.seatbelt
            .get_or_insert_with(Default::default)
            .rules
            .push(seatbelt::Rule {
                effect: seatbelt::Effect::Allow,
                ops: vec![seatbelt::Operation::SysctlRead],
                filters: vec![],
            });
    }
    #[cfg(target_os = "linux")]
    {
        p.base = procage::policy::Base::V1;
        p.fs.push(FsRule::new(
            Access::Exec,
            FsTarget::Subpath(abs(exe().parent().unwrap())),
        ));
    }
    p.net = Network::Proxy {
        http: Some(Port::new(3128).unwrap()),
        socks: Some(Port::new(1080).unwrap()),
    };
    p
}

/// `allowed.test` is the loopback echo host; nothing else resolves.
#[derive(Clone)]
struct Local;

impl Resolve for Local {
    fn resolve(&self, name: &str) -> std::io::Result<Vec<IpAddr>> {
        match name {
            "allowed.test" | "other.test" => Ok(vec!["127.0.0.1".parse().unwrap()]),
            _ => Err(std::io::Error::other("no such name")),
        }
    }
}

fn proxy(entries: &[&str]) -> Proxy {
    Proxy::new(Allowlist::new(entries).unwrap()).with_resolver(Local)
}

fn options(proxy: Proxy) -> CageOptions {
    #[cfg(target_os = "linux")]
    let options = CageOptions::default().with_tier(procage::policy::Tier::T1);
    #[cfg(target_os = "macos")]
    let options = CageOptions::default();
    options.with_proxy(proxy)
}

/// Whether this host can run the proxy tier (always on macOS; T1 on Linux).
fn supported() -> bool {
    #[cfg(target_os = "linux")]
    {
        let t1 = procage::linux::probe().tier == Some(procage::policy::Tier::T1);
        if !t1 {
            println!("proxy-only cages need tier T1 on Linux; not applicable here");
        }
        t1
    }
    #[cfg(target_os = "macos")]
    true
}

/// An echo host on loopback; its port.
fn echo() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for s in l.incoming().flatten() {
            std::thread::spawn(move || {
                let (mut r, mut w) = (s.try_clone().unwrap(), s);
                let _ = std::io::copy(&mut r, &mut w);
            });
        }
    });
    port
}

fn run(cage: &Cage, action: &str) -> (Vec<String>, procage::Violations) {
    let mut cmd = Command::new(exe());
    cmd.args(["--exact", "child_entry", "--nocapture", "--test-threads=1"])
        .env("PROCAGE_CHILD", action)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = cage.spawn(&mut cmd, &Grants::new()).unwrap();
    let mut out = String::new();
    child
        .stdout
        .take()
        .unwrap()
        .read_to_string(&mut out)
        .unwrap();
    child.wait().unwrap();
    let results = out
        .lines()
        .filter_map(|l| l.split_once("procage-result: ").map(|(_, r)| r.to_string()))
        .collect();
    let _ = child.kill_all();
    (results, child.violations())
}

#[test]
fn child_entry() {
    let Ok(action) = std::env::var("PROCAGE_CHILD") else {
        return;
    };
    for step in action.split(';') {
        let (verb, arg) = step.split_once(':').unwrap_or((step, ""));
        let result = match verb {
            "via-http" => via_http(&proxy_addr("HTTPS_PROXY"), arg),
            "via-http-at" => {
                let (at, target) = arg.split_once('|').unwrap();
                via_http(at, target)
            }
            "via-socks" => via_socks(arg),
            "env" => std::env::var(arg).unwrap_or_default(),
            "tcp" => errno(TcpStream::connect_timeout(
                &arg.parse().unwrap(),
                Duration::from_secs(2),
            )),
            "udp" => errno(
                std::net::UdpSocket::bind("0.0.0.0:0")
                    .and_then(|s| s.send_to(b"x", arg.parse::<std::net::SocketAddr>().unwrap())),
            ),
            #[cfg(target_os = "linux")]
            "net" => {
                let (kind, port) = arg.split_once('|').unwrap();
                code(procage::linux::testing::net_errno(
                    kind,
                    port.parse().unwrap(),
                ))
            }
            _ => format!("unknown action {step}"),
        };
        println!("procage-result: {result}");
    }
}

fn errno<T>(r: std::io::Result<T>) -> String {
    match r {
        Ok(_) => "ok".into(),
        Err(e) => e.raw_os_error().map_or(e.to_string(), |n| n.to_string()),
    }
}

#[cfg(target_os = "linux")]
fn code(n: i32) -> String {
    if n == 0 { "ok".into() } else { n.to_string() }
}

/// The proxy's address from a proxy variable (`scheme://host:port`).
fn proxy_addr(var: &str) -> String {
    let url = std::env::var(var).unwrap_or_default();
    url.split_once("://")
        .map_or(url.clone(), |(_, a)| a.to_string())
}

/// `CONNECT host:port` through the proxy at `at`, then an echo round trip.
fn via_http(at: &str, target: &str) -> String {
    let mut s = match TcpStream::connect(at) {
        Ok(s) => s,
        Err(e) => return format!("proxy-{}", errno::<()>(Err(e))),
    };
    write!(s, "CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n").unwrap();
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") && s.read(&mut byte).unwrap_or(0) == 1 {
        head.push(byte[0]);
    }
    let status = String::from_utf8_lossy(&head)
        .split(' ')
        .nth(1)
        .unwrap_or("none")
        .to_string();
    if status != "200" {
        return status;
    }
    echoed(&mut s)
}

/// SOCKS5 `CONNECT` by name through `ALL_PROXY`, then an echo round trip.
fn via_socks(target: &str) -> String {
    let (host, port) = target.rsplit_once(':').unwrap();
    let mut s = match TcpStream::connect(proxy_addr("ALL_PROXY")) {
        Ok(s) => s,
        Err(e) => return format!("proxy-{}", errno::<()>(Err(e))),
    };
    s.write_all(&[5, 1, 0]).unwrap();
    let mut greeting = [0u8; 2];
    s.read_exact(&mut greeting).unwrap();
    let mut req = vec![5, 1, 0, 3, u8::try_from(host.len()).unwrap()];
    req.extend_from_slice(host.as_bytes());
    req.extend_from_slice(&port.parse::<u16>().unwrap().to_be_bytes());
    s.write_all(&req).unwrap();
    let mut reply = [0u8; 10];
    s.read_exact(&mut reply).unwrap();
    if reply[1] != 0 {
        return format!("socks-{}", reply[1]);
    }
    echoed(&mut s)
}

fn echoed(s: &mut TcpStream) -> String {
    s.write_all(b"ping").unwrap();
    let mut back = [0u8; 4];
    match s.read_exact(&mut back) {
        Ok(()) if &back == b"ping" => "ok".into(),
        _ => "no-echo".into(),
    }
}

#[test]
fn only_allowed_hosts_are_reached_and_refusals_are_reported() {
    if !supported() {
        return;
    }
    let port = echo();
    let opts = options(proxy(&["allowed.test", "127.0.0.1"])).with_violations();
    let cage = Cage::with_options(&policy(), &opts).unwrap();
    let (got, record) = run(
        &cage,
        &format!(
            "via-http:allowed.test:{port};via-socks:allowed.test:{port};via-http:other.test:{port};via-socks:evil.test:443"
        ),
    );
    assert_eq!(got, ["ok", "ok", "403", "socks-2"]);
    let refused: Vec<String> = record
        .iter()
        .filter(|v| v.denied_by == procage::DeniedBy::Allowlist)
        .filter_map(|v| v.target.clone())
        .collect();
    assert!(
        refused
            .iter()
            .any(|t| t.starts_with(&format!("other.test:{port}")))
            && refused.iter().any(|t| t.starts_with("evil.test:443")),
        "{record:#?}"
    );
}

#[test]
fn every_direct_route_fails() {
    if !supported() {
        return;
    }
    let port = echo();
    // A datagram that leaves the run arrives here.
    let host_udp = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    host_udp
        .set_read_timeout(Some(Duration::from_millis(500)))
        .unwrap();
    let udp = host_udp.local_addr().unwrap().port();
    let cage =
        Cage::with_options(&policy(), &options(proxy(&["allowed.test", "127.0.0.1"]))).unwrap();
    // Linux adds the routes only raw system calls reach.
    #[cfg_attr(target_os = "macos", allow(unused_mut))]
    let mut attempts: Vec<String> = [
        format!("tcp:127.0.0.1:{port}"),
        format!("tcp:[::1]:{port}"),
        "tcp:1.1.1.1:443".to_string(),
        "udp:8.8.8.8:53".to_string(),
    ]
    .into();
    #[cfg(target_os = "linux")]
    attempts.extend(
        ["fastopen", "mptcp", "raw", "tcp6"]
            .iter()
            .map(|k| format!("net:{k}|{port}")),
    );
    let (got, _) = run(&cage, &attempts.join(";"));
    for (attempt, result) in attempts.iter().zip(&got) {
        assert_ne!(result, "ok", "{attempt} reached the network directly");
    }
    assert_eq!(got.len(), attempts.len(), "{got:?}");
    // UDP to the host's loopback: the send may succeed inside the run's own
    // network namespace (Linux T1), but nothing arrives.
    let _ = run(&cage, &format!("udp:127.0.0.1:{udp}"));
    let mut buf = [0u8; 16];
    assert!(host_udp.recv(&mut buf).is_err(), "a datagram left the run");
    // The control: the same echo host through the proxy.
    let (got, _) = run(&cage, &format!("via-http:allowed.test:{port}"));
    assert_eq!(got, ["ok"]);
}

#[test]
fn a_run_reaches_only_its_own_listener() {
    if !supported() {
        return;
    }
    let port = echo();
    let narrow = Cage::with_options(
        &policy(),
        &options(proxy(&["other.test"])).with_violations(),
    )
    .unwrap();
    let wide = Cage::with_options(
        &policy(),
        &options(proxy(&["allowed.test", "127.0.0.1"])).with_violations(),
    )
    .unwrap();
    // A run of the wide cage holds its listener open.
    let mut cmd = Command::new(exe());
    cmd.args(["--exact", "child_entry", "--nocapture", "--test-threads=1"])
        .env("PROCAGE_CHILD", "env:HTTPS_PROXY")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    let mut holder = wide.spawn(&mut cmd, &Grants::new()).unwrap();
    let mut out = String::new();
    holder
        .stdout
        .take()
        .unwrap()
        .read_to_string(&mut out)
        .unwrap();
    let wide_addr = out
        .lines()
        .find_map(|l| {
            l.split_once("procage-result: http://")
                .map(|(_, a)| a.to_string())
        })
        .unwrap();
    // The narrow run cannot use the wide run's listener: macOS refuses the
    // connect; on Linux T1 the address is the narrow run's own listener, in
    // its own network namespace, which refuses the host.
    let (got, _) = run(
        &narrow,
        &format!("via-http-at:{wide_addr}|allowed.test:{port}"),
    );
    assert_ne!(got[0], "ok", "reached another run's proxy at {wide_addr}");
    let (got, record) = run(&narrow, &format!("via-http:allowed.test:{port}"));
    assert_eq!(got, ["403"]);
    // The refusal is the narrow run's; the wide run recorded nothing.
    let refused = |r: &procage::Violations| {
        r.iter()
            .filter(|v| v.denied_by == procage::DeniedBy::Allowlist)
            .count()
    };
    assert!(refused(&record) >= 1, "{record:#?}");
    let _ = holder.kill_all();
    let held = holder.violations();
    assert_eq!(refused(&held), 0, "{held:#?}");
}

#[test]
fn a_cage_without_its_proxy_policy_is_refused() {
    let mut p = policy();
    p.net = Network::None;
    assert!(Cage::with_options(&p, &options(proxy(&["allowed.test"]))).is_err());
}

#[cfg(target_os = "linux")]
#[test]
fn tier_t2_refuses_a_proxy_only_cage() {
    let opts = CageOptions::default()
        .with_tier(procage::policy::Tier::T2)
        .with_proxy(proxy(&["allowed.test"]));
    match Cage::with_options(&policy(), &opts) {
        Err(procage::linux::SpawnError::Lower(procage::policy::LowerError::Gaps(gaps))) => {
            assert!(
                gaps.iter()
                    .any(|g| g.construct == procage::policy::Construct::NetProxy),
                "{gaps:?}"
            );
        }
        other => panic!("expected the proxy gap, got {other:?}"),
    }
}
