//! The proxy canaries' shared parts (feature `proxy`): a loopback echo
//! host, a proxy whose resolver knows only test names, and the child's
//! network operations.

use std::io::{Read, Write};
use std::net::{IpAddr, TcpListener, TcpStream};
use std::time::Duration;

use procage::policy::{Network, Policy, Port};
use procage::proxy::{Allowlist, Proxy, Resolve};

/// `allowed.test` names the loopback echo host; nothing else resolves.
struct Local;

impl Resolve for Local {
    fn resolve(&self, name: &str) -> std::io::Result<Vec<IpAddr>> {
        match name {
            "allowed.test" => Ok(vec![IpAddr::from([127, 0, 0, 1])]),
            _ => Err(std::io::Error::other("no such name")),
        }
    }
}

/// A proxy for `entries` with the test resolver.
pub fn proxy(entries: &[&str]) -> Proxy {
    Proxy::new(Allowlist::new(entries).unwrap()).with_resolver(Local)
}

/// `p` with the network through a proxy (HTTP and SOCKS5).
pub fn through_proxy(mut p: Policy) -> Policy {
    p.net = Network::Proxy {
        http: Some(Port::new(3128).unwrap()),
        socks: Some(Port::new(1080).unwrap()),
    };
    p
}

/// An echo host on the host's loopback; its port.
pub fn echo() -> u16 {
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

/// A child's network operation, or `None` for a verb it does not know:
/// `via-http:<authority>` (CONNECT through `HTTPS_PROXY`, then an echo),
/// `via-socks:<hex name>|<port>` (SOCKS5 through `ALL_PROXY`), `tcp:<addr>`
/// and `udp:<addr>` (direct).
pub fn op(verb: &str, arg: &str) -> Option<String> {
    Some(match verb {
        "via-http" => via_http(arg),
        "via-socks" => {
            let (hex, port) = arg.split_once('|').unwrap();
            via_socks(&unhex(hex), port.parse().unwrap())
        }
        "tcp" => errno(TcpStream::connect_timeout(
            &arg.parse().unwrap(),
            Duration::from_secs(2),
        )),
        "udp" => errno(
            std::net::UdpSocket::bind("0.0.0.0:0")
                .and_then(|s| s.send_to(b"x", arg.parse::<std::net::SocketAddr>().unwrap())),
        ),
        _ => return None,
    })
}

/// `bytes` as the hex a `via-socks` step takes.
pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn errno<T>(r: std::io::Result<T>) -> String {
    match r {
        Ok(_) => "ok".into(),
        Err(e) => e.raw_os_error().map_or(e.to_string(), |n| n.to_string()),
    }
}

fn proxy_addr(var: &str) -> String {
    let url = std::env::var(var).unwrap_or_default();
    url.split_once("://")
        .map_or(url.clone(), |(_, a)| a.to_string())
}

fn via_http(target: &str) -> String {
    let mut s = match TcpStream::connect(proxy_addr("HTTPS_PROXY")) {
        Ok(s) => s,
        Err(e) => return format!("proxy-{}", errno::<()>(Err(e))),
    };
    write!(s, "CONNECT {target} HTTP/1.1\r\n\r\n").unwrap();
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

fn via_socks(name: &[u8], port: u16) -> String {
    let mut s = match TcpStream::connect(proxy_addr("ALL_PROXY")) {
        Ok(s) => s,
        Err(e) => return format!("proxy-{}", errno::<()>(Err(e))),
    };
    s.write_all(&[5, 1, 0]).unwrap();
    let mut greeting = [0u8; 2];
    s.read_exact(&mut greeting).unwrap();
    let mut req = vec![5, 1, 0, 3, u8::try_from(name.len()).unwrap()];
    req.extend_from_slice(name);
    req.extend_from_slice(&port.to_be_bytes());
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
