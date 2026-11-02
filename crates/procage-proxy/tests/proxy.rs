//! The proxy end to end on loopback: a local echo host, a scripted resolver
//! that counts queries, HTTP and SOCKS5 clients.

use std::io::{Read, Write};
use std::net::{IpAddr, Shutdown, TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use procage_proxy::{Allowlist, Limits, Protocol, Proxy, Reason, Refusal, Resolve};

/// A name and its addresses.
type Answer = (String, Vec<IpAddr>);

/// Answers from a script and counts every query.
#[derive(Clone, Default)]
struct Script {
    answers: Arc<Mutex<Vec<Answer>>>,
    queries: Arc<AtomicUsize>,
}

impl Script {
    fn with(self, name: &str, addrs: &[&str]) -> Self {
        self.answers.lock().unwrap().push((
            name.into(),
            addrs.iter().map(|a| a.parse().unwrap()).collect(),
        ));
        self
    }
    fn queries(&self) -> usize {
        self.queries.load(Ordering::SeqCst)
    }
}

impl Resolve for Script {
    fn resolve(&self, name: &str) -> std::io::Result<Vec<IpAddr>> {
        self.queries.fetch_add(1, Ordering::SeqCst);
        self.answers
            .lock()
            .unwrap()
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, a)| a.clone())
            .ok_or_else(|| std::io::Error::other("no such name"))
    }
}

/// An echo host on loopback: returns its port.
fn echo() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for s in l.incoming().flatten() {
            std::thread::spawn(move || {
                let mut r = s.try_clone().unwrap();
                let mut w = s;
                let _ = std::io::copy(&mut r, &mut w);
            });
        }
    });
    port
}

struct Served {
    run: procage_proxy::Run,
    refusals: Arc<Mutex<Vec<Refusal>>>,
}

fn serve(proxy: &Proxy) -> Served {
    let refusals = Arc::new(Mutex::new(Vec::new()));
    let sink = refusals.clone();
    let listeners = vec![
        (Protocol::Http, TcpListener::bind("127.0.0.1:0").unwrap()),
        (Protocol::Socks5, TcpListener::bind("127.0.0.1:0").unwrap()),
    ];
    let run = proxy
        .serve(listeners, move |r| sink.lock().unwrap().push(r))
        .unwrap();
    Served { run, refusals }
}

impl Served {
    fn http(&self) -> TcpStream {
        connect(self.run.addr(Protocol::Http).unwrap().port())
    }
    fn socks(&self) -> TcpStream {
        connect(self.run.addr(Protocol::Socks5).unwrap().port())
    }
    fn refusals(&self) -> Vec<Refusal> {
        // A refusal is recorded right after the answer is written.
        std::thread::sleep(Duration::from_millis(50));
        self.refusals.lock().unwrap().clone()
    }
}

fn connect(port: u16) -> TcpStream {
    let s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    s
}

/// Sends a CONNECT and returns the status line.
fn http_connect(s: &mut TcpStream, authority: &str) -> String {
    write!(
        s,
        "CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n"
    )
    .unwrap();
    head(s)
}

fn head(s: &mut TcpStream) -> String {
    let mut buf = Vec::new();
    let mut byte = [0u8; 1];
    while !buf.ends_with(b"\r\n\r\n") {
        match s.read(&mut byte) {
            Ok(1) => buf.push(byte[0]),
            _ => break,
        }
    }
    String::from_utf8_lossy(&buf)
        .lines()
        .next()
        .unwrap_or("")
        .to_string()
}

/// A SOCKS5 CONNECT to a domain; the reply code.
fn socks_domain(s: &mut TcpStream, name: &[u8], port: u16) -> u8 {
    s.write_all(&[5, 1, 0]).unwrap();
    let mut greeting = [0u8; 2];
    s.read_exact(&mut greeting).unwrap();
    assert_eq!(greeting, [5, 0]);
    let mut req = vec![5, 1, 0, 3, u8::try_from(name.len()).unwrap()];
    req.extend_from_slice(name);
    req.extend_from_slice(&port.to_be_bytes());
    s.write_all(&req).unwrap();
    let mut reply = [0u8; 10];
    s.read_exact(&mut reply).unwrap();
    reply[1]
}

/// Sends random bytes and checks they come back unchanged.
fn round_trip(s: &mut TcpStream) {
    let data: Vec<u8> = (0..65_536u32)
        .map(|i| (i.wrapping_mul(2_654_435_761) >> 13) as u8)
        .collect();
    let mut w = s.try_clone().unwrap();
    let sent = data.clone();
    let writer = std::thread::spawn(move || w.write_all(&sent).unwrap());
    let mut got = vec![0u8; data.len()];
    s.read_exact(&mut got).unwrap();
    writer.join().unwrap();
    assert!(got == data, "the relay changed the bytes");
}

fn allowed(script: &Script) -> Proxy {
    Proxy::new(Allowlist::new(["allowed.test", "*.allowed.test", "127.0.0.1"]).unwrap())
        .with_resolver(script.clone())
}

#[test]
fn an_allowed_host_is_reached_unchanged_over_both_protocols() {
    let port = echo();
    let script = Script::default()
        .with("allowed.test", &["127.0.0.1"])
        .with("api.allowed.test", &["127.0.0.1"]);
    let served = serve(&allowed(&script));
    let mut s = served.http();
    assert_eq!(
        http_connect(&mut s, &format!("ALLOWED.TEST.:{port}")),
        "HTTP/1.1 200 Connection established"
    );
    round_trip(&mut s);
    let mut s = served.socks();
    assert_eq!(socks_domain(&mut s, b"api.allowed.test", port), 0);
    round_trip(&mut s);
    assert_eq!(script.queries(), 2, "one query per request");
    assert!(served.refusals().is_empty());
}

#[test]
fn a_host_not_on_the_list_is_refused_without_a_query() {
    let script = Script::default().with("evil.test", &["127.0.0.1"]);
    let served = serve(&allowed(&script));
    let mut s = served.http();
    assert_eq!(
        http_connect(&mut s, "evil.test:443"),
        "HTTP/1.1 403 Forbidden"
    );
    let mut s = served.socks();
    assert_eq!(socks_domain(&mut s, b"allowed.test\0.evil.test", 443), 2);
    let mut s = served.socks();
    assert_eq!(socks_domain(&mut s, b"evilallowed.test", 443), 2);
    assert_eq!(script.queries(), 0);
    let refusals = served.refusals();
    assert_eq!(refusals.len(), 3, "{refusals:?}");
    assert_eq!(refusals[0].host, "evil.test");
    assert_eq!(refusals[0].reason, Reason::NotAllowed);
    assert!(
        matches!(refusals[1].reason, Reason::Malformed(_)),
        "{refusals:?}"
    );
    assert_eq!(refusals[1].host, "allowed.test\\0.evil.test");
}

#[test]
fn literals_are_refused_unless_a_range_holds_them() {
    let port = echo();
    let script = Script::default();
    let proxy = Proxy::new(Allowlist::new(["allowed.test"]).unwrap()).with_resolver(script.clone());
    let served = serve(&proxy);
    for literal in [
        "2130706433",
        "0x7f.1",
        "017700000001",
        "[::ffff:127.0.0.1]",
        "127.1",
        "127.0.0.1",
    ] {
        let mut s = served.http();
        assert_eq!(
            http_connect(&mut s, &format!("{literal}:{port}")),
            "HTTP/1.1 403 Forbidden",
            "{literal}"
        );
    }
    let ranged = Proxy::new(Allowlist::new(["127.0.0.0/8"]).unwrap());
    let served = serve(&ranged);
    for literal in ["2130706433", "127.0.0.1"] {
        let mut s = served.http();
        assert_eq!(
            http_connect(&mut s, &format!("{literal}:{port}")),
            "HTTP/1.1 200 Connection established",
            "{literal}"
        );
        round_trip(&mut s);
    }
    assert_eq!(script.queries(), 0);
}

#[test]
fn an_allowed_name_that_resolves_inward_is_refused() {
    let script = Script::default()
        .with("allowed.test", &["127.0.0.1"])
        .with("meta.allowed.test", &["169.254.169.254"])
        .with("mapped.allowed.test", &["::ffff:10.0.0.1"]);
    let proxy = Proxy::new(Allowlist::new(["allowed.test", "*.allowed.test"]).unwrap())
        .with_resolver(script.clone());
    let served = serve(&proxy);
    for name in ["allowed.test", "meta.allowed.test", "mapped.allowed.test"] {
        let mut s = served.http();
        assert_eq!(
            http_connect(&mut s, &format!("{name}:80")),
            "HTTP/1.1 403 Forbidden"
        );
    }
    let reasons: Vec<Reason> = served.refusals().into_iter().map(|r| r.reason).collect();
    assert_eq!(
        reasons,
        [
            Reason::Address("127.0.0.1".parse().unwrap()),
            Reason::Address("169.254.169.254".parse().unwrap()),
            Reason::Address("::ffff:10.0.0.1".parse().unwrap()),
        ]
    );
}

#[test]
fn the_checked_address_is_the_one_connected_to() {
    let port = echo();
    // The first answer is refused, the second checked and used; a later
    // query would get only the refused one.
    let script = Script::default().with("allowed.test", &["10.0.0.1", "127.0.0.1"]);
    let proxy = Proxy::new(Allowlist::new(["allowed.test", "127.0.0.1"]).unwrap())
        .with_resolver(script.clone());
    let served = serve(&proxy);
    let mut s = served.http();
    assert_eq!(
        http_connect(&mut s, &format!("allowed.test:{port}")),
        "HTTP/1.1 200 Connection established"
    );
    round_trip(&mut s);
    assert_eq!(script.queries(), 1);
}

#[test]
fn plain_http_is_forwarded_only_for_the_host_it_names() {
    let port = echo();
    let script = Script::default().with("allowed.test", &["127.0.0.1"]);
    let served = serve(&allowed(&script));
    let mut s = served.http();
    let request =
        format!("GET http://allowed.test:{port}/x HTTP/1.1\r\nHost: allowed.test:{port}\r\n\r\n");
    s.write_all(request.as_bytes()).unwrap();
    // The echo host returns the request unchanged, in absolute form.
    let mut got = vec![0u8; request.len()];
    s.read_exact(&mut got).unwrap();
    assert_eq!(got, request.as_bytes());
    let mut s = served.http();
    write!(
        s,
        "GET http://allowed.test:{port}/ HTTP/1.1\r\nHost: evil.test\r\n\r\n"
    )
    .unwrap();
    assert_eq!(head(&mut s), "HTTP/1.1 400 Bad Request");
}

#[test]
fn a_run_is_bounded_and_ends_its_connections() {
    let port = echo();
    let script = Script::default().with("allowed.test", &["127.0.0.1"]);
    let proxy = allowed(&script).with_limits(Limits {
        connections: 2,
        timeout: Duration::from_millis(300),
    });
    let served = serve(&proxy);
    let mut open = served.http();
    assert_eq!(
        http_connect(&mut open, &format!("allowed.test:{port}")),
        "HTTP/1.1 200 Connection established"
    );
    // Never finishes its handshake: closed after the timeout.
    let mut stalled = served.http();
    let start = Instant::now();
    let mut byte = [0u8; 1];
    assert!(matches!(stalled.read(&mut byte), Ok(0) | Err(_)));
    assert!(start.elapsed() < Duration::from_secs(3));
    // Beyond the limit: closed at once.
    std::thread::sleep(Duration::from_millis(100));
    let _second = served.http();
    std::thread::sleep(Duration::from_millis(100));
    let mut third = served.http();
    assert!(matches!(third.read(&mut byte), Ok(0) | Err(_)));
    assert!(served.refusals().iter().any(|r| r.reason == Reason::Busy));
    // The run ends: the open relay is closed.
    drop(served);
    let start = Instant::now();
    assert!(matches!(open.read(&mut byte), Ok(0) | Err(_)));
    assert!(start.elapsed() < Duration::from_secs(3));
    let _ = open.shutdown(Shutdown::Both);
}

#[test]
fn a_refused_host_is_recorded_escaped() {
    let served = serve(&allowed(&Script::default()));
    let mut s = served.socks();
    assert_eq!(socks_domain(&mut s, b"a\x1b[31m.test\nx", 443), 2);
    let refusals = served.refusals();
    assert_eq!(refusals.len(), 1);
    assert!(
        refusals[0].host.chars().all(|c| !c.is_control()),
        "{:?}",
        refusals[0].host
    );
}

/// What holds a proxy (a cage, a child handle) stays unwind safe and
/// thread safe.
#[test]
fn a_proxy_and_its_run_are_unwind_and_thread_safe() {
    fn check<T: Send + Sync + std::panic::UnwindSafe + std::panic::RefUnwindSafe>() {}
    check::<Proxy>();
    check::<procage_proxy::Run>();
    check::<Allowlist>();
}
