//! Linux tier T1's transparent relay: TPROXY original destinations, the
//! helper's exact UDP source, local DNS REFUSED, and the fail-closed control
//! channel. The test binary runs itself as the caged child (`PROCAGE_CHILD`).

#![cfg(target_os = "linux")]

use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use procage::native::{Cage, CageOptions, Grants};
use procage::policy::{AbsPath, Access, Base, FsRule, FsTarget, Network, Policy, Tier};
use procage::proxy::relay::Relay;

fn abs(p: impl AsRef<Path>) -> AbsPath {
    AbsPath::new(p.as_ref().as_os_str().as_encoded_bytes()).unwrap()
}

fn exe() -> PathBuf {
    std::fs::canonicalize(std::env::current_exe().unwrap()).unwrap()
}

fn policy() -> Policy {
    let mut p = Policy::default();
    p.base = Base::V1;
    p.fs.push(FsRule::new(
        Access::Exec,
        FsTarget::Subpath(abs(exe().parent().unwrap())),
    ));
    p.net = Network::Relay;
    p
}

fn supported() -> bool {
    let t1 = procage::linux::probe().tier == Some(Tier::T1);
    if !t1 {
        println!("the relay needs tier T1 on Linux; not applicable here");
    }
    t1
}

/// A non-loopback local IPv4 address the parent can serve and the app
/// namespace can route to.
fn local_ip() -> Option<Ipv4Addr> {
    let probe = UdpSocket::bind("0.0.0.0:0").ok()?;
    probe.connect("1.1.1.1:53").ok()?;
    match probe.local_addr().ok()?.ip() {
        std::net::IpAddr::V4(ip) if !ip.is_loopback() => Some(ip),
        _ => None,
    }
}

// ------------------------------------------------------------- fake control

#[derive(Debug, Clone)]
enum Verdict {
    Allow,
    Deny(&'static str),
}

struct Server {
    path: PathBuf,
    stop: Arc<AtomicBool>,
    handle: Option<std::thread::JoinHandle<()>>,
}

const RUN: u64 = 0xfeed_1234_5678_9abc;

impl Server {
    /// The plugin's server: one connection, HELLO with RUN, then a verdict
    /// from `decide`.
    fn start(decide: impl Fn(&str) -> Verdict + Send + 'static) -> Server {
        let path = std::env::temp_dir().join(format!(
            "procage-relay-test-{}-{}.sock",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_file(&path);
        let listener = UnixListener::bind(&path).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let stop2 = stop.clone();
        let handle = std::thread::spawn(move || {
            listener.set_nonblocking(true).ok();
            while !stop2.load(Ordering::Relaxed) {
                let (stream, _) = match listener.accept() {
                    Ok(pair) => pair,
                    Err(_) => {
                        std::thread::sleep(Duration::from_millis(5));
                        continue;
                    }
                };
                stream.set_read_timeout(Some(Duration::from_secs(5))).ok();
                serve(stream, &decide);
            }
        });
        Server {
            path,
            stop,
            handle: Some(handle),
        }
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        let _ = std::fs::remove_file(&self.path);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

fn read_frame(stream: &mut UnixStream) -> Option<(u8, Vec<u8>)> {
    let mut head = [0u8; 4];
    stream.read_exact(&mut head).ok()?;
    let len = u32::from_be_bytes(head) as usize;
    if len == 0 || len > 4096 {
        return None;
    }
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf).ok()?;
    let kind = buf.remove(0);
    Some((kind, buf))
}

fn write_frame(stream: &mut UnixStream, kind: u8, body: &[u8]) {
    let mut frame = Vec::with_capacity(5 + body.len());
    frame.extend_from_slice(&((1 + body.len()) as u32).to_be_bytes());
    frame.push(kind);
    frame.extend_from_slice(body);
    stream.write_all(&frame).ok();
}

fn serve(mut stream: UnixStream, decide: &impl Fn(&str) -> Verdict) {
    let Some((kind, hello)) = read_frame(&mut stream) else {
        return;
    };
    if kind != 3 || hello.len() != 13 || hello[0] != 1 {
        return;
    }
    if u64::from_be_bytes(hello[1..9].try_into().unwrap()) != RUN {
        return;
    }
    let mut ack = Vec::new();
    ack.push(1);
    ack.extend_from_slice(&1u32.to_be_bytes());
    ack.extend_from_slice(&64u32.to_be_bytes());
    ack.extend_from_slice(&RUN.to_be_bytes());
    write_frame(&mut stream, 4, &ack);
    while let Some((kind, body)) = read_frame(&mut stream) {
        if kind != 1 || body.len() < 12 {
            return;
        }
        let id = u64::from_be_bytes(body[0..8].try_into().unwrap());
        let len = u16::from_be_bytes([body[8], body[9]]) as usize;
        if 10 + len + 3 > body.len() {
            return;
        }
        let resource = String::from_utf8_lossy(&body[10..10 + len]).to_string();
        let verdict = decide(&resource);
        let mut out = Vec::new();
        out.extend_from_slice(&id.to_be_bytes());
        match verdict {
            Verdict::Allow => {
                out.push(1);
                out.extend_from_slice(&4u16.to_be_bytes());
                out.extend_from_slice(b"okay");
            }
            Verdict::Deny(reason) => {
                out.push(0);
                out.extend_from_slice(&(reason.len() as u16).to_be_bytes());
                out.extend_from_slice(reason.as_bytes());
            }
        }
        write_frame(&mut stream, 2, &out);
    }
}

// ------------------------------------------------------------------ servers

fn tcp_echo() -> u16 {
    let listener = TcpListener::bind("0.0.0.0:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            std::thread::spawn(move || {
                let mut stream = stream;
                let mut buf = [0u8; 64];
                if let Ok(n) = stream.read(&mut buf) {
                    let _ = stream.write_all(b"UP:");
                    let _ = stream.write_all(&buf[..n]);
                }
            });
        }
    });
    port
}

fn udp_echo() -> u16 {
    let socket = UdpSocket::bind("0.0.0.0:0").unwrap();
    let port = socket.local_addr().unwrap().port();
    std::thread::spawn(move || {
        let mut buf = [0u8; 256];
        while let Ok((n, from)) = socket.recv_from(&mut buf) {
            let mut reply = b"UP:".to_vec();
            reply.extend_from_slice(&buf[..n]);
            let _ = socket.send_to(&reply, from);
        }
    });
    port
}

/// A DNS server that answers every query `NOERROR` with no records.
fn dns_server() -> SocketAddr {
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    let addr = socket.local_addr().unwrap();
    std::thread::spawn(move || {
        let mut buf = [0u8; 512];
        while let Ok((n, from)) = socket.recv_from(&mut buf) {
            if n < 12 {
                continue;
            }
            let mut reply = vec![buf[0], buf[1], 0x81, 0x80, 0, 1, 0, 0, 0, 0, 0, 0];
            reply.extend_from_slice(&buf[12..n]);
            let _ = socket.send_to(&reply, from);
        }
    });
    addr
}

// ---------------------------------------------------------------- the child

fn query(name: &str) -> Vec<u8> {
    let mut out = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
    for label in name.split('.') {
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    out.extend_from_slice(&1u16.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes());
    out
}

#[test]
fn child_entry() {
    let Ok(action) = std::env::var("PROCAGE_CHILD") else {
        return;
    };
    for step in action.split(';') {
        let (verb, arg) = step.split_once(':').unwrap_or((step, ""));
        let result = match verb {
            "tcp" => {
                let mut out = String::new();
                match TcpStream::connect_timeout(&arg.parse().unwrap(), Duration::from_secs(3)) {
                    Ok(mut stream) => {
                        stream.set_read_timeout(Some(Duration::from_secs(3))).ok();
                        let _ = stream.write_all(b"ping");
                        let _ = stream.read_to_string(&mut out);
                        if out.is_empty() { "eof".into() } else { out }
                    }
                    Err(e) => format!("connect-error:{:?}", e.kind()),
                }
            }
            "udp" => {
                let target: SocketAddr = arg.parse().unwrap();
                match UdpSocket::bind("0.0.0.0:0") {
                    Ok(socket) => {
                        socket.set_read_timeout(Some(Duration::from_secs(3))).ok();
                        let _ = socket.send_to(b"ping", target);
                        let mut buf = [0u8; 64];
                        match socket.recv_from(&mut buf) {
                            Ok((n, from)) => {
                                format!("{}|from={from}", String::from_utf8_lossy(&buf[..n]))
                            }
                            Err(_) => "timeout".into(),
                        }
                    }
                    Err(_) => "socket-error".into(),
                }
            }
            "dns" => {
                let target: SocketAddr = arg.parse().unwrap();
                match UdpSocket::bind("0.0.0.0:0") {
                    Ok(socket) => {
                        socket.set_read_timeout(Some(Duration::from_secs(3))).ok();
                        let _ = socket.send_to(&query("c2.example"), target);
                        let mut buf = [0u8; 512];
                        match socket.recv_from(&mut buf) {
                            Ok((n, _)) => {
                                let rcode = if n >= 4 { buf[3] & 0x0f } else { 255 };
                                format!("rcode={rcode}")
                            }
                            Err(e) => format!("timeout:{:?}", e.kind()),
                        }
                    }
                    Err(_) => "socket-error".into(),
                }
            }
            "dnsq" => {
                let (target, name) = arg.split_once('|').unwrap();
                let target: SocketAddr = target.parse().unwrap();
                match UdpSocket::bind("0.0.0.0:0") {
                    Ok(socket) => {
                        socket.set_read_timeout(Some(Duration::from_secs(3))).ok();
                        let _ = socket.send_to(&query(name), target);
                        let mut buf = [0u8; 512];
                        match socket.recv_from(&mut buf) {
                            Ok((n, _)) => {
                                let rcode = if n >= 4 { buf[3] & 0x0f } else { 255 };
                                format!("rcode={rcode}")
                            }
                            Err(e) => format!("timeout:{:?}", e.kind()),
                        }
                    }
                    Err(_) => "socket-error".into(),
                }
            }
            "direct" => {
                match TcpStream::connect_timeout(&arg.parse().unwrap(), Duration::from_secs(1)) {
                    Ok(_) => "connected".into(),
                    Err(e) => format!("{:?}", e.kind()),
                }
            }
            other => format!("unknown:{other}"),
        };
        println!("procage-result: {result}");
    }
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
        .filter_map(|line| {
            line.split_once("procage-result: ")
                .map(|(_, r)| r.to_string())
        })
        .collect();
    let _ = child.kill_all();
    (results, child.violations())
}

#[test]
fn t2_refuses_the_relay() {
    let policy = policy();
    let options = CageOptions::default()
        .with_tier(Tier::T2)
        .with_relay(Relay::new("/nonexistent/control.sock").with_run_id(RUN));
    match Cage::with_options(&policy, &options) {
        Ok(_) => panic!("tier T2 must refuse Network::Relay"),
        Err(e) => {
            let text = e.to_string();
            assert!(
                text.contains("net-relay") || text.contains("relay"),
                "{text}"
            );
        }
    }
}

#[test]
fn relay_needs_a_control_socket() {
    let policy = policy();
    let options = CageOptions::default().with_tier(Tier::T1);
    match Cage::with_options(&policy, &options) {
        Ok(_) => panic!("Network::Relay without CageOptions::with_relay must fail"),
        Err(e) => assert!(e.to_string().contains("with_relay"), "{e}"),
    }
}

#[test]
fn tcp_and_udp_reach_the_original_destination() {
    if !supported() {
        return;
    }
    let Some(ip) = local_ip() else {
        println!("no non-loopback IPv4 address; not applicable here");
        return;
    };
    let tcp_port = tcp_echo();
    let udp_port = udp_echo();
    let server = Server::start(move |resource| {
        if resource == ip.to_string() {
            Verdict::Allow
        } else {
            Verdict::Deny("not this destination")
        }
    });
    let options = CageOptions::default().with_tier(Tier::T1).with_relay(
        Relay::new(&server.path)
            .with_run_id(RUN)
            .with_timeout(Duration::from_secs(5)),
    );
    let cage = Cage::with_options(&policy(), &options).unwrap();
    let action = format!(
        "tcp:{ip}:{tcp_port};udp:{ip}:{udp_port}",
        ip = ip,
        tcp_port = tcp_port,
        udp_port = udp_port
    );
    let (results, _) = run(&cage, &action);
    assert_eq!(results[0], "UP:ping", "TCP through TPROXY: {results:?}");
    assert!(
        results[1].starts_with("UP:ping|from=")
            && results[1].ends_with(&format!("{ip}:{udp_port}")),
        "UDP reply must come from the original destination: {results:?}"
    );
}

#[test]
fn denied_tcp_is_closed_and_dns_is_refused() {
    if !supported() {
        return;
    }
    let Some(ip) = local_ip() else {
        return;
    };
    let tcp_port = tcp_echo();
    let server = Server::start(move |resource| {
        if resource == "c2.example" || resource == ip.to_string() {
            Verdict::Deny("policy")
        } else {
            Verdict::Allow
        }
    });
    let options = CageOptions::default()
        .with_tier(Tier::T1)
        .with_violations()
        .with_relay(
            Relay::new(&server.path)
                .with_run_id(RUN)
                .with_timeout(Duration::from_secs(5)),
        );
    let cage = Cage::with_options(&policy(), &options).unwrap();
    // The loopback resolver stub is redirected to the app namespace's DNS
    // listener; a denied QNAME is answered REFUSED (5), not timed out.
    let action =
        format!("tcp:{ip}:{tcp_port};dns:127.0.0.1:5353;dns:127.0.0.53:53;dns:127.0.0.1:53");
    let (results, violations) = run(&cage, &action);
    assert!(
        results[0] == "eof" || results[0].starts_with("connect-error"),
        "denied TCP must be closed: {results:?}"
    );
    assert_eq!(results[1], "rcode=5", "direct DNS listener: {results:?}");
    assert_eq!(results[2], "rcode=5", "denied QNAME: {results:?}");
    assert_eq!(
        results[3], "rcode=5",
        "denied QNAME on 127.0.0.1: {results:?}"
    );
    assert!(
        violations
            .iter()
            .any(|v| v.to_string().contains("c2.example")),
        "the refusal must be visible: {violations:?}"
    );
}

#[test]
fn dns_allow_and_deny_map() {
    if !supported() {
        return;
    }
    let upstream = dns_server();
    let server = Server::start(|resource| {
        if resource == "allowed.example" {
            Verdict::Allow
        } else {
            Verdict::Deny("not on the map")
        }
    });
    let options = CageOptions::default().with_tier(Tier::T1).with_relay(
        Relay::new(&server.path)
            .with_run_id(RUN)
            .with_dns_upstream(upstream)
            .with_timeout(Duration::from_secs(5)),
    );
    let cage = Cage::with_options(&policy(), &options).unwrap();
    let action = "dnsq:127.0.0.53:53|allowed.example;dnsq:127.0.0.53:53|c2.example";
    let (results, _) = run(&cage, action);
    assert_eq!(results[0], "rcode=0", "allowed QNAME: {results:?}");
    assert_eq!(results[1], "rcode=5", "denied QNAME: {results:?}");
}

#[test]
fn a_broken_control_channel_fails_closed() {
    if !supported() {
        return;
    }
    let Some(ip) = local_ip() else {
        return;
    };
    let tcp_port = tcp_echo();
    let path = std::env::temp_dir().join(format!("procage-relay-dead-{}.sock", std::process::id()));
    let _ = std::fs::remove_file(&path);
    let listener = UnixListener::bind(&path).unwrap();
    std::thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            let mut head = [0u8; 4];
            let _ = stream.read_exact(&mut head);
            // Close without HELLO_ACK.
        }
    });
    let options = CageOptions::default().with_tier(Tier::T1).with_relay(
        Relay::new(&path)
            .with_run_id(RUN)
            .with_timeout(Duration::from_secs(2)),
    );
    // The handshake happens before the fork: no child runs without a control.
    match Cage::with_options(&policy(), &options) {
        Ok(cage) => {
            let mut cmd = Command::new(exe());
            cmd.args(["--exact", "child_entry", "--nocapture", "--test-threads=1"])
                .env("PROCAGE_CHILD", format!("tcp:{ip}:{tcp_port}"))
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
            assert!(cage.spawn(&mut cmd, &Grants::new()).is_err());
        }
        Err(e) => assert!(e.to_string().contains("control"), "{e}"),
    }
    let _ = std::fs::remove_file(&path);
}
