//! Linux tier T1's transparent relay: TPROXY original destinations, the
//! helper's exact UDP source, local DNS REFUSED, and the fail-closed control
//! channel. The test binary runs itself as the caged child (`PROCAGE_CHILD`).

#![cfg(target_os = "linux")]

use std::io::{Read, Write};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, TcpStream, UdpSocket};
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

fn tcp_echo6(ip: Ipv6Addr) -> u16 {
    let listener = TcpListener::bind(SocketAddr::from((ip, 0))).unwrap();
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

fn udp_echo6(ip: Ipv6Addr) -> u16 {
    let socket = UdpSocket::bind(SocketAddr::from((ip, 0))).unwrap();
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

/// A UDP sink on `[ip]:443` that counts datagrams.
fn quic_sink6(ip: Ipv6Addr) -> Arc<std::sync::atomic::AtomicUsize> {
    let socket = UdpSocket::bind(SocketAddr::from((ip, 443))).unwrap();
    let count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let seen = count.clone();
    std::thread::spawn(move || {
        let mut buf = [0u8; 2048];
        while let Ok((_n, _)) = socket.recv_from(&mut buf) {
            seen.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
    });
    count
}

/// Re-execs `test` in a fresh user+net namespace and gives its inner run a
/// ULA on loopback. `true`: run the inner body.
fn ipv6_userns_inner(test: &str) -> bool {
    if std::env::var("PROCAGE_IPV6_INNER").is_err() {
        let Ok(exe) = std::env::current_exe() else {
            return false;
        };
        match Command::new("unshare")
            .args(["-Urn"])
            .arg(exe)
            .args(["--exact", test, "--nocapture", "--test-threads=1"])
            .env("PROCAGE_IPV6_INNER", "1")
            .status()
        {
            Ok(status) => assert!(status.success(), "{test} inner run failed"),
            Err(_) => println!("unshare is unavailable; {test} skipped"),
        }
        return false;
    }
    let added = Command::new("ip")
        .args(["-6", "addr", "add", "fd00::1/128", "dev", "lo"])
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    let up = Command::new("ip")
        .args(["link", "set", "lo", "up"])
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if !added || !up {
        println!("cannot configure an IPv6 address; {test} skipped");
        return false;
    }
    true
}

static QUIC_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// A DNS server that answers every query `NOERROR`; known names get one A
/// record with a 60 s TTL.
fn dns_server_for(answers: Vec<(&'static str, Ipv4Addr)>) -> SocketAddr {
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    let addr = socket.local_addr().unwrap();
    std::thread::spawn(move || {
        let mut buf = [0u8; 512];
        while let Ok((n, from)) = socket.recv_from(&mut buf) {
            if n < 12 {
                continue;
            }
            let mut at = 12;
            let mut labels = Vec::new();
            while let Some(&len) = buf.get(at) {
                at += 1;
                if len == 0 {
                    break;
                }
                let len = len as usize;
                if at + len > n {
                    break;
                }
                labels.push(String::from_utf8_lossy(&buf[at..at + len]).to_ascii_lowercase());
                at += len;
            }
            let question_end = at + 4;
            if question_end > n {
                continue;
            }
            let name = labels.join(".");
            let answer = answers
                .iter()
                .find(|(known, _)| known.eq_ignore_ascii_case(&name))
                .map(|(_, ip)| *ip);
            let mut reply = vec![buf[0], buf[1], 0x81, 0x80, 0, 1];
            reply.extend_from_slice(&u16::from(answer.is_some()).to_be_bytes());
            reply.extend_from_slice(&0u16.to_be_bytes());
            reply.extend_from_slice(&0u16.to_be_bytes());
            reply.extend_from_slice(&buf[12..question_end]);
            if let Some(ip) = answer {
                reply.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1]);
                reply.extend_from_slice(&60u32.to_be_bytes());
                reply.extend_from_slice(&4u16.to_be_bytes());
                reply.extend_from_slice(&ip.octets());
            }
            let _ = socket.send_to(&reply, from);
        }
    });
    addr
}

fn dns_server() -> SocketAddr {
    dns_server_for(Vec::new())
}

/// A TCP DNS stub with the same answers as `dns_server_for`.
fn dns_tcp_server_for(answers: Vec<(&'static str, Ipv4Addr)>) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let answers = answers.clone();
            std::thread::spawn(move || {
                let mut stream = stream;
                let mut head = [0u8; 2];
                if stream.read_exact(&mut head).is_err() {
                    return;
                }
                let len = u16::from_be_bytes(head) as usize;
                let mut buf = vec![0u8; len];
                if stream.read_exact(&mut buf).is_err() || len < 12 {
                    return;
                }
                let mut at = 12;
                let mut labels = Vec::new();
                while let Some(&label_len) = buf.get(at) {
                    at += 1;
                    if label_len == 0 {
                        break;
                    }
                    let label_len = label_len as usize;
                    if at + label_len > len {
                        return;
                    }
                    labels.push(
                        String::from_utf8_lossy(&buf[at..at + label_len]).to_ascii_lowercase(),
                    );
                    at += label_len;
                }
                let question_end = at + 4;
                if question_end > len {
                    return;
                }
                let name = labels.join(".");
                let answer = answers
                    .iter()
                    .find(|(known, _)| known.eq_ignore_ascii_case(&name))
                    .map(|(_, ip)| *ip);
                let mut reply = vec![buf[0], buf[1], 0x81, 0x80, 0, 1];
                reply.extend_from_slice(&u16::from(answer.is_some()).to_be_bytes());
                reply.extend_from_slice(&0u16.to_be_bytes());
                reply.extend_from_slice(&0u16.to_be_bytes());
                reply.extend_from_slice(&buf[12..question_end]);
                if let Some(ip) = answer {
                    reply.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1]);
                    reply.extend_from_slice(&60u32.to_be_bytes());
                    reply.extend_from_slice(&4u16.to_be_bytes());
                    reply.extend_from_slice(&ip.octets());
                }
                let _ = stream.write_all(&(reply.len() as u16).to_be_bytes());
                let _ = stream.write_all(&reply);
            });
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
            "ip6" => std::fs::read_to_string("/proc/net/if_inet6")
                .unwrap_or_default()
                .replace('\n', "|"),
            "bind6" => match UdpSocket::bind(arg) {
                Ok(socket) => format!("bound:{}", socket.local_addr().unwrap()),
                Err(e) => format!("bind-error:{e}"),
            },
            "tcpdelay" => {
                let (target, delay) = arg.split_once('|').unwrap();
                let delay: u64 = delay.parse().unwrap();
                let mut out = String::new();
                match TcpStream::connect_timeout(&target.parse().unwrap(), Duration::from_secs(3)) {
                    Ok(mut stream) => {
                        std::thread::sleep(Duration::from_millis(delay));
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
            "udp6" => {
                let target: SocketAddr = arg.parse().unwrap();
                match UdpSocket::bind("[::]:0") {
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
            "tls-partial" => {
                match TcpStream::connect_timeout(&arg.parse().unwrap(), Duration::from_secs(3)) {
                    Ok(mut stream) => {
                        let mut prefix = vec![0x16, 0x03, 0x01, 0x40, 0x00];
                        prefix.extend_from_slice(&[0u8; 100]);
                        let _ = stream.write_all(&prefix);
                        let mut out = String::new();
                        stream.set_read_timeout(Some(Duration::from_secs(2))).ok();
                        let _ = stream.read_to_string(&mut out);
                        if out.is_empty() {
                            "eof".into()
                        } else {
                            "forwarded".into()
                        }
                    }
                    Err(e) => format!("connect-error:{:?}", e.kind()),
                }
            }
            "tls-nosni" => {
                match TcpStream::connect_timeout(&arg.parse().unwrap(), Duration::from_secs(3)) {
                    Ok(mut stream) => {
                        let body_len = 2 + 32 + 1 + 4 + 2;
                        let mut hello = vec![0x16, 0x03, 0x01];
                        hello.extend_from_slice(&((4 + body_len) as u16).to_be_bytes());
                        hello.push(1);
                        hello.extend_from_slice(&((body_len as u32).to_be_bytes()[1..]));
                        hello.extend_from_slice(&[0x03, 0x03]);
                        hello.extend_from_slice(&[7u8; 32]);
                        hello.push(0);
                        hello.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]);
                        hello.extend_from_slice(&[0x01, 0x00]);
                        stream.set_read_timeout(Some(Duration::from_secs(3))).ok();
                        let _ = stream.write_all(&hello);
                        let mut out = String::new();
                        let _ = stream.read_to_string(&mut out);
                        if out.starts_with("UP:") {
                            "forwarded".into()
                        } else {
                            format!("not-forwarded:{out:?}")
                        }
                    }
                    Err(e) => format!("connect-error:{:?}", e.kind()),
                }
            }
            "quic" => {
                let target: SocketAddr = arg.parse().unwrap();
                let first = include_bytes!("fixtures/quic/big-0.bin");
                let second = include_bytes!("fixtures/quic/big-1.bin");
                let bind = if target.is_ipv4() {
                    "0.0.0.0:0"
                } else {
                    "[::]:0"
                };
                match UdpSocket::bind(bind) {
                    Ok(socket) => {
                        let _ = socket.send_to(first, target);
                        std::thread::sleep(Duration::from_millis(10));
                        let _ = socket.send_to(second, target);
                        std::thread::sleep(Duration::from_millis(300));
                        "sent".into()
                    }
                    Err(_) => "socket-error".into(),
                }
            }
            "quic-first-only" => {
                let target: SocketAddr = arg.parse().unwrap();
                let first = include_bytes!("fixtures/quic/big-0.bin");
                let bind = if target.is_ipv4() {
                    "0.0.0.0:0"
                } else {
                    "[::]:0"
                };
                match UdpSocket::bind(bind) {
                    Ok(socket) => {
                        let _ = socket.send_to(first, target);
                        std::thread::sleep(Duration::from_millis(300));
                        "sent".into()
                    }
                    Err(_) => "socket-error".into(),
                }
            }
            "quic-ech" => {
                let target: SocketAddr = arg.parse().unwrap();
                let first = include_bytes!("fixtures/quic/ech-0.bin");
                let second = include_bytes!("fixtures/quic/ech-1.bin");
                let bind = if target.is_ipv4() {
                    "0.0.0.0:0"
                } else {
                    "[::]:0"
                };
                match UdpSocket::bind(bind) {
                    Ok(socket) => {
                        let _ = socket.send_to(first, target);
                        std::thread::sleep(Duration::from_millis(10));
                        let _ = socket.send_to(second, target);
                        std::thread::sleep(Duration::from_millis(300));
                        "sent".into()
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
            "dnstcp" => {
                let (target, name) = arg.split_once('|').unwrap();
                let target: SocketAddr = target.parse().unwrap();
                match TcpStream::connect_timeout(&target, Duration::from_secs(3)) {
                    Ok(mut stream) => {
                        stream.set_read_timeout(Some(Duration::from_secs(3))).ok();
                        let message = query(name);
                        if stream
                            .write_all(&(message.len() as u16).to_be_bytes())
                            .and_then(|()| stream.write_all(&message))
                            .is_err()
                        {
                            "write-error".into()
                        } else {
                            let mut head = [0u8; 2];
                            if stream.read_exact(&mut head).is_err() {
                                "read-error".into()
                            } else {
                                let len = u16::from_be_bytes(head) as usize;
                                let mut reply = vec![0u8; len];
                                if stream.read_exact(&mut reply).is_err() || len < 4 {
                                    "read-error".into()
                                } else {
                                    format!("rcode={}", reply[3] & 0x0f)
                                }
                            }
                        }
                    }
                    Err(e) => format!("connect-error:{:?}", e.kind()),
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
fn an_allowed_dns_answer_maps_a_nameless_flow() {
    if !supported() {
        return;
    }
    let Some(ip) = local_ip() else {
        return;
    };
    let tcp_port = tcp_echo();
    let dns = dns_server_for(vec![("allowed.example", ip)]);
    let server = Server::start(|resource| {
        if resource == "allowed.example" {
            Verdict::Allow
        } else {
            Verdict::Deny("the raw address is not directly allowed")
        }
    });
    let options = CageOptions::default().with_tier(Tier::T1).with_relay(
        Relay::new(&server.path)
            .with_run_id(RUN)
            .with_dns_upstream(dns)
            .with_timeout(Duration::from_secs(5)),
    );
    let cage = Cage::with_options(&policy(), &options).unwrap();
    let action = format!("dnsq:127.0.0.53:53|allowed.example;tcp:{ip}:{tcp_port}");
    let (results, _) = run(&cage, &action);
    assert_eq!(results[0], "rcode=0", "DNS answer: {results:?}");
    assert_eq!(
        results[1], "UP:ping",
        "the raw IP flow must use the previously allowed name: {results:?}"
    );
}

#[test]
fn a_denied_dns_answer_adds_no_mapping() {
    if !supported() {
        return;
    }
    let Some(ip) = local_ip() else {
        return;
    };
    let tcp_port = tcp_echo();
    let dns = dns_server_for(vec![("denied-map.example", ip)]);
    let server = Server::start(move |resource| {
        if resource == ip.to_string() {
            Verdict::Allow
        } else {
            Verdict::Deny("denied QNAME")
        }
    });
    let options = CageOptions::default().with_tier(Tier::T1).with_relay(
        Relay::new(&server.path)
            .with_run_id(RUN)
            .with_dns_upstream(dns)
            .with_timeout(Duration::from_secs(5)),
    );
    let cage = Cage::with_options(&policy(), &options).unwrap();
    let action = format!("dnsq:127.0.0.53:53|denied-map.example;tcp:{ip}:{tcp_port}");
    let (results, _) = run(&cage, &action);
    assert_eq!(results[0], "rcode=5", "denied QNAME: {results:?}");
    assert_eq!(
        results[1], "UP:ping",
        "a denied answer must not authorize its address by name: {results:?}"
    );
}

#[test]
fn a_slow_client_survives_the_sniff_deadline() {
    if !supported() {
        return;
    }
    let Some(ip) = local_ip() else {
        return;
    };
    let tcp_port = tcp_echo();
    let server = Server::start(move |resource| {
        if resource == ip.to_string() {
            Verdict::Allow
        } else {
            Verdict::Deny("only this address")
        }
    });
    let options = CageOptions::default().with_tier(Tier::T1).with_relay(
        Relay::new(&server.path)
            .with_run_id(RUN)
            .with_timeout(Duration::from_secs(5)),
    );
    let cage = Cage::with_options(&policy(), &options).unwrap();
    let action = format!("tcpdelay:{ip}:{tcp_port}|700");
    let (results, _) = run(&cage, &action);
    assert_eq!(
        results[0], "UP:ping",
        "a 700 ms idle client must still be relayed after classification: {results:?}"
    );
}

#[test]
fn tcp_dns_uses_the_same_upstream() {
    if !supported() {
        return;
    }
    let Some(ip) = local_ip() else {
        return;
    };
    let upstream = dns_tcp_server_for(vec![("allowed.example", ip)]);
    let server = Server::start(|resource| {
        if resource == "allowed.example" {
            Verdict::Allow
        } else {
            Verdict::Deny("only this name")
        }
    });
    let options = CageOptions::default().with_tier(Tier::T1).with_relay(
        Relay::new(&server.path)
            .with_run_id(RUN)
            .with_dns_upstream(upstream)
            .with_timeout(Duration::from_secs(5)),
    );
    let cage = Cage::with_options(&policy(), &options).unwrap();
    let (results, _) = run(&cage, "dnstcp:127.0.0.53:53|allowed.example");
    assert_eq!(
        results[0], "rcode=0",
        "TCP DNS through the upstream: {results:?}"
    );
}

#[test]
fn dns_without_a_resolver_servfails() {
    if !supported() {
        return;
    }
    let conf = std::env::temp_dir().join(format!(
        "procage-empty-resolv-{}-{}.conf",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::write(&conf, b"search example\n").unwrap();
    let server = Server::start(|resource| {
        if resource == "allowed.example" {
            Verdict::Allow
        } else {
            Verdict::Deny("only this name")
        }
    });
    let options = CageOptions::default().with_tier(Tier::T1).with_relay(
        Relay::new(&server.path)
            .with_run_id(RUN)
            .with_resolv_conf(&conf)
            .with_timeout(Duration::from_secs(5)),
    );
    let cage = Cage::with_options(&policy(), &options).unwrap();
    let (results, _) = run(&cage, "dnsq:127.0.0.53:53|allowed.example");
    assert_eq!(
        results[0], "rcode=2",
        "no resolver must SERVFAIL, not silently succeed: {results:?}"
    );
    let _ = std::fs::remove_file(&conf);
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
fn ipv6_tcp_and_udp_reach_the_original_destination() {
    if std::env::var("PROCAGE_IPV6_INNER").is_err() {
        // A fresh user+net namespace lets this unprivileged test put a ULA
        // on loopback, so the parent namespace can serve the address the
        // child reaches through the relay.
        let Ok(exe) = std::env::current_exe() else {
            return;
        };
        let status = Command::new("unshare")
            .args(["-Urn"])
            .arg(exe)
            .args([
                "--exact",
                "ipv6_tcp_and_udp_reach_the_original_destination",
                "--nocapture",
                "--test-threads=1",
            ])
            .env("PROCAGE_IPV6_INNER", "1")
            .status();
        match status {
            Ok(status) => assert!(status.success(), "IPv6 inner test failed"),
            Err(_) => println!("unshare is unavailable; IPv6 e2e skipped"),
        }
        return;
    }
    if !supported() {
        return;
    }
    let added = Command::new("ip")
        .args(["-6", "addr", "add", "fd00::1/128", "dev", "lo"])
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    let up = Command::new("ip")
        .args(["link", "set", "lo", "up"])
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if !added || !up {
        println!("cannot configure an IPv6 address; IPv6 e2e skipped");
        return;
    }
    let ip: Ipv6Addr = "fd00::1".parse().unwrap();
    let tcp_port = tcp_echo6(ip);
    let udp_port = udp_echo6(ip);
    let server = Server::start(move |resource| {
        if resource == ip.to_string() {
            Verdict::Allow
        } else {
            Verdict::Deny("only this IPv6 destination")
        }
    });
    let options = CageOptions::default().with_tier(Tier::T1).with_relay(
        Relay::new(&server.path)
            .with_run_id(RUN)
            .with_timeout(Duration::from_secs(5)),
    );
    let cage = Cage::with_options(&policy(), &options).unwrap();
    let action = format!("tcp:[{ip}]:{tcp_port};udp6:[{ip}]:{udp_port}");
    let (results, _) = run(&cage, &action);
    assert_eq!(
        results[0], "UP:ping",
        "IPv6 TCP through TPROXY: {results:?}"
    );
    assert!(
        results[1].starts_with("UP:ping|from=")
            && results[1].ends_with(&format!("[{ip}]:{udp_port}")),
        "IPv6 UDP reply must come from the original destination: {results:?}"
    );
}

#[test]
fn quic_initials_are_buffered_until_the_sni_decides() {
    if !ipv6_userns_inner("quic_initials_are_buffered_until_the_sni_decides") {
        return;
    }
    let _guard = QUIC_TEST_LOCK.lock().unwrap();
    let ip: Ipv6Addr = "fd00::1".parse().unwrap();
    let seen = quic_sink6(ip);
    let decisions = Arc::new(std::sync::Mutex::new(Vec::new()));
    let recorded = decisions.clone();
    let server = Server::start(move |resource| {
        recorded.lock().unwrap().push(resource.to_string());
        if resource == "quic-big.example" {
            Verdict::Allow
        } else {
            Verdict::Deny("only the QUIC SNI")
        }
    });
    let options = CageOptions::default().with_tier(Tier::T1).with_relay(
        Relay::new(&server.path)
            .with_run_id(RUN)
            .with_timeout(Duration::from_secs(5)),
    );
    let cage = Cage::with_options(&policy(), &options).unwrap();
    let (results, _) = run(&cage, &format!("quic:[{ip}]:443"));
    assert_eq!(results[0], "sent");
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(
        seen.load(std::sync::atomic::Ordering::Relaxed),
        2,
        "both Initial datagrams must be forwarded: {decisions:?}"
    );
    let decisions = decisions.lock().unwrap();
    assert_eq!(&*decisions, &["quic-big.example".to_string()]);
}

#[test]
fn a_denied_quic_sni_forwards_nothing() {
    if !ipv6_userns_inner("a_denied_quic_sni_forwards_nothing") {
        return;
    }
    let _guard = QUIC_TEST_LOCK.lock().unwrap();
    let ip: Ipv6Addr = "fd00::1".parse().unwrap();
    let seen = quic_sink6(ip);
    let server = Server::start(|_resource| Verdict::Deny("no QUIC"));
    let options = CageOptions::default().with_tier(Tier::T1).with_relay(
        Relay::new(&server.path)
            .with_run_id(RUN)
            .with_timeout(Duration::from_secs(5)),
    );
    let cage = Cage::with_options(&policy(), &options).unwrap();
    let (results, _) = run(&cage, &format!("quic:[{ip}]:443"));
    assert_eq!(results[0], "sent");
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(
        seen.load(std::sync::atomic::Ordering::Relaxed),
        0,
        "a denied name must forward no Initial"
    );
}

#[test]
fn an_incomplete_quic_initial_is_denied_even_when_the_ip_is_allowed() {
    if !ipv6_userns_inner("an_incomplete_quic_initial_is_denied_even_when_the_ip_is_allowed") {
        return;
    }
    let _guard = QUIC_TEST_LOCK.lock().unwrap();
    let ip: Ipv6Addr = "fd00::1".parse().unwrap();
    let seen = quic_sink6(ip);
    let decisions = Arc::new(std::sync::Mutex::new(Vec::new()));
    let recorded = decisions.clone();
    let server = Server::start(move |resource| {
        recorded.lock().unwrap().push(resource.to_string());
        Verdict::Allow
    });
    let options = CageOptions::default().with_tier(Tier::T1).with_relay(
        Relay::new(&server.path)
            .with_run_id(RUN)
            .with_timeout(Duration::from_secs(5)),
    );
    let cage = Cage::with_options(&policy(), &options).unwrap();
    let (results, _) = run(&cage, &format!("quic-first-only:[{ip}]:443"));
    assert_eq!(results[0], "sent");
    std::thread::sleep(Duration::from_millis(400));
    assert_eq!(
        seen.load(std::sync::atomic::Ordering::Relaxed),
        0,
        "an incomplete Initial must fail closed, not ask for the IP"
    );
    assert!(
        decisions.lock().unwrap().is_empty(),
        "no IP decision may authorize an incomplete Initial: {decisions:?}"
    );
}

#[test]
fn ech_spanning_quic_initials_is_denied_visibly() {
    if !ipv6_userns_inner("ech_spanning_quic_initials_is_denied_visibly") {
        return;
    }
    let _guard = QUIC_TEST_LOCK.lock().unwrap();
    let ip: Ipv6Addr = "fd00::1".parse().unwrap();
    let seen = quic_sink6(ip);
    let decisions = Arc::new(std::sync::Mutex::new(Vec::new()));
    let recorded = decisions.clone();
    let server = Server::start(move |resource| {
        recorded.lock().unwrap().push(resource.to_string());
        Verdict::Allow
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
    let (results, violations) = run(&cage, &format!("quic-ech:[{ip}]:443"));
    assert_eq!(results[0], "sent");
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(
        seen.load(std::sync::atomic::Ordering::Relaxed),
        0,
        "ECH must forward nothing"
    );
    assert!(decisions.lock().unwrap().is_empty(), "no name may be asked");
    assert!(
        violations.iter().any(|v| v.to_string().contains("ECH")),
        "the ECH refusal must be visible: {violations:?}"
    );
}

#[test]
fn an_incomplete_tls_handshake_is_denied_even_when_the_ip_is_allowed() {
    if !supported() {
        return;
    }
    let Some(ip) = local_ip() else {
        return;
    };
    let tcp_port = tcp_echo();
    let decisions = Arc::new(std::sync::Mutex::new(Vec::new()));
    let recorded = decisions.clone();
    let server = Server::start(move |resource| {
        recorded.lock().unwrap().push(resource.to_string());
        Verdict::Allow
    });
    let options = CageOptions::default().with_tier(Tier::T1).with_relay(
        Relay::new(&server.path)
            .with_run_id(RUN)
            .with_timeout(Duration::from_secs(5)),
    );
    let cage = Cage::with_options(&policy(), &options).unwrap();
    let (results, _) = run(&cage, &format!("tls-partial:{ip}:{tcp_port}"));
    assert_eq!(
        results[0], "eof",
        "a TLS-looking partial handshake must fail closed: {results:?}"
    );
    assert!(
        decisions.lock().unwrap().is_empty(),
        "no IP decision may authorize an incomplete TLS handshake: {decisions:?}"
    );
}

#[test]
fn a_valid_tls_handshake_without_sni_uses_the_ip() {
    if !supported() {
        return;
    }
    let Some(ip) = local_ip() else {
        return;
    };
    let tcp_port = tcp_echo();
    let server = Server::start(move |resource| {
        if resource == ip.to_string() {
            Verdict::Allow
        } else {
            Verdict::Deny("only the IP")
        }
    });
    let options = CageOptions::default().with_tier(Tier::T1).with_relay(
        Relay::new(&server.path)
            .with_run_id(RUN)
            .with_timeout(Duration::from_secs(5)),
    );
    let cage = Cage::with_options(&policy(), &options).unwrap();
    let (results, _) = run(&cage, &format!("tls-nosni:{ip}:{tcp_port}"));
    assert_eq!(
        results[0], "forwarded",
        "a valid ClientHello without SNI may use the IP decision: {results:?}"
    );
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
