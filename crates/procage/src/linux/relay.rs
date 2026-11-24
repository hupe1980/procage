//! Linux tier T1's transparent relay: the parent's bridge.
//!
//! The child runs in an app network namespace whose only route is a veth to a
//! proxy namespace. In the proxy namespace a relay helper installs nftables
//! TPROXY rules (prerouting, priority -150, mark 1 and a `local` policy
//! route), binds one TCP and one UDP transparent socket, hands them to this
//! parent over `SCM_RIGHTS`, drops `CAP_NET_ADMIN` (keeping only
//! `CAP_NET_RAW`), and serves transparent UDP replies.
//!
//! The parent accepts TCP connections whose local address is the original
//! destination, reads just enough to name the flow (TLS SNI, HTTP `Host`,
//! QUIC SNI, DNS QNAME, else the IP), asks the run's control socket, and
//! only then connects to the original destination. UDP datagrams carry the
//! original destination as ancillary data; replies leave through the helper
//! from that exact address and port. No payload crosses the control channel.

use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::net::{IpAddr, Shutdown, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::os::fd::OwnedFd;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Sender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use procage_proxy::relay::{Control, Decision, Proto, Reason, Relay, Resource, dns, inspect};

use super::sys;

/// The proxy namespace's TCP/UDP TPROXY port.
pub(crate) const PROXY_PORT: u16 = 15_001;
/// The app namespace's local DNS port (nft redirects port 53 here).
pub(crate) const DNS_PORT: u16 = 5_353;
/// The app namespace's point-to-point address pair.
pub(crate) const APP_ADDR: [u8; 4] = [10, 10, 0, 2];
pub(crate) const PROXY_ADDR: [u8; 4] = [10, 10, 0, 1];
pub(crate) const APP_PREFIX: u8 = 24;
pub(crate) const PROXY_IF: &str = "procage-p0";
pub(crate) const APP_IF: &str = "procage-a0";
const POLICY_TABLE: u32 = 100;
const MARK: u32 = 1;
/// How long one decision may wait beyond the relay's own timeout.
const DECISION_GRACE: Duration = Duration::from_millis(50);
/// The most bytes buffered to name a TCP flow.
const MAX_NAME: usize = 64 * 1024;
/// The most concurrent TCP flows a run relays.
const MAX_TCP: usize = 128;
/// How long an idle UDP flow keeps its upstream socket.
const UDP_IDLE: Duration = Duration::from_secs(30);

/// Connects to the harness's control socket.
pub(crate) fn connect(relay: &Relay) -> io::Result<Control> {
    let run_id = match relay.run_id() {
        Some(id) => id,
        None => {
            let mut bytes = [0u8; 8];
            std::fs::File::open("/dev/urandom")?.read_exact(&mut bytes)?;
            u64::from_ne_bytes(bytes)
        }
    };
    Control::connect(relay.control(), run_id, relay.timeout()).map_err(io::Error::other)
}

/// Receives the helper's and the child's descriptors and starts a run.
pub(crate) fn start(
    relay: Relay,
    control: Control,
    helper: OwnedFd,
    dns: OwnedFd,
    violations: Option<crate::violation::Sink>,
) -> io::Result<Run> {
    let (head, fds) =
        sys::recv_with_fds(&helper, 2, 5_000).map_err(io::Error::from_raw_os_error)?;
    if head.first() != Some(&1) || fds.len() != 2 {
        return Err(io::Error::other(
            "relay helper did not hand over its sockets",
        ));
    }
    let mut fds = fds.into_iter();
    let tcp = TcpListener::from(fds.next().expect("checked"));
    let udp = UdpSocket::from(fds.next().expect("checked"));
    let (head, fds) = sys::recv_with_fds(&dns, 2, 5_000).map_err(io::Error::from_raw_os_error)?;
    let (dns_udp, dns_tcp) = if head.first() == Some(&2) && fds.len() == 2 {
        let mut fds = fds.into_iter();
        (
            Some(UdpSocket::from(fds.next().expect("checked"))),
            Some(TcpListener::from(fds.next().expect("checked"))),
        )
    } else {
        // DNS is optional: without its listeners, resolver stubs time out
        // rather than leak.
        (None, None)
    };
    Run::start(
        relay, control, helper, tcp, udp, dns_udp, dns_tcp, violations,
    )
}

/// One run's relay: the control channel, the handed-over listeners and the
/// helper channel.
#[derive(Debug)]
pub(crate) struct Run {
    stop: Arc<AtomicBool>,
    handles: Vec<std::thread::JoinHandle<()>>,
    socket: Arc<Mutex<std::os::unix::net::UnixStream>>,
    control: Arc<Mutex<Control>>,
    relay: Relay,
    violations: Option<crate::violation::Sink>,
}

impl Run {
    /// Starts the bridge from the descriptors the child and helper handed
    /// over. `control` was connected before the spawn.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn start(
        relay: Relay,
        control: Control,
        socket: OwnedFd,
        tcp: TcpListener,
        udp: UdpSocket,
        dns_udp: Option<UdpSocket>,
        dns_tcp: Option<TcpListener>,
        violations: Option<crate::violation::Sink>,
    ) -> io::Result<Run> {
        let stop = Arc::new(AtomicBool::new(false));
        let socket = Arc::new(Mutex::new(std::os::unix::net::UnixStream::from(socket)));
        let control = Arc::new(Mutex::new(control));
        let mut run = Run {
            stop: stop.clone(),
            handles: Vec::new(),
            socket: socket.clone(),
            control: control.clone(),
            relay: relay.clone(),
            violations: violations.clone(),
        };
        tcp.set_nonblocking(true)?;
        let tcp_stop = stop.clone();
        let tcp_control = control.clone();
        let tcp_relay = relay.clone();
        let tcp_socket = socket.clone();
        let tcp_violations = violations.clone();
        let inflight = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        run.handles.push(std::thread::spawn(move || {
            loop {
                if tcp_stop.load(Ordering::Relaxed) {
                    break;
                }
                match tcp.accept() {
                    Ok((stream, _)) => {
                        if inflight.load(Ordering::Relaxed) >= MAX_TCP {
                            let _ = stream.shutdown(Shutdown::Both);
                            continue;
                        }
                        inflight.fetch_add(1, Ordering::Relaxed);
                        let control = tcp_control.clone();
                        let relay = tcp_relay.clone();
                        let socket = tcp_socket.clone();
                        let sink = tcp_violations.clone();
                        let count = inflight.clone();
                        std::thread::spawn(move || {
                            let _ = tcp_flow(stream, &control, &relay, &socket, sink.as_ref());
                            count.fetch_sub(1, Ordering::Relaxed);
                        });
                    }
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(2));
                    }
                    Err(_) => break,
                }
            }
        }));
        // UDP TPROXY and DNS share the decision path but not a socket.
        let udp_stop = stop.clone();
        run.handles.push(std::thread::spawn(move || {
            udp_loop(udp, udp_stop, control, relay, socket, violations);
        }));
        if let Some(dns_udp) = dns_udp {
            let dns_stop = run.stop.clone();
            let dns_control = run.control.clone();
            let dns_relay = run.relay.clone();
            let dns_socket = run.socket.clone();
            let dns_sink = run.violations.clone();
            run.handles.push(std::thread::spawn(move || {
                dns_listener_udp(
                    dns_udp,
                    dns_stop,
                    dns_control,
                    dns_relay,
                    dns_socket,
                    dns_sink,
                );
            }));
        }
        if let Some(dns_tcp) = dns_tcp {
            let dns_stop = run.stop.clone();
            let dns_control = run.control.clone();
            let dns_relay = run.relay.clone();
            let dns_sink = run.violations.clone();
            run.handles.push(std::thread::spawn(move || {
                dns_listener_tcp(dns_tcp, dns_stop, dns_control, dns_relay, dns_sink);
            }));
        }
        Ok(run)
    }
}
impl Drop for Run {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Ok(mut control) = self.control.lock() {
            control.close();
        }
        // Each listener loop notices within one poll interval; the handles
        // are detached rather than joined so ending a run never blocks on a
        // stuck peer.
    }
}

fn record(
    sink: Option<&crate::violation::Sink>,
    operation: &str,
    target: String,
    by: crate::violation::DeniedBy,
) {
    let Some(sink) = sink else {
        return;
    };
    crate::violation::lock(sink).push(crate::violation::Violation {
        pid: 0,
        process: "relay".into(),
        operation: operation.into(),
        target: Some(target),
        denied_by: by,
        received: std::time::SystemTime::now(),
        repeats: 1,
    });
}

/// The local refusals that apply before the control socket is asked.
fn pre_decision(relay: &Relay, resource: &Resource, port: u16) -> Option<Reason> {
    if port == 853 {
        return Some(Reason::Dns);
    }
    if let Resource::Domain(name) = resource
        && procage_proxy::relay::is_known_doh(name)
    {
        return Some(Reason::Dns);
    }
    let _ = relay;
    None
}

fn decide(
    control: &Arc<Mutex<Control>>,
    relay: &Relay,
    resource: &Resource,
    port: u16,
    proto: Proto,
) -> Decision {
    if let Some(reason) = pre_decision(relay, resource, port) {
        return Decision::Deny {
            reason,
            text: "refused before the control socket".into(),
        };
    }
    let Ok(mut control) = control.lock() else {
        return Decision::Deny {
            reason: Reason::ControlLost,
            text: "control channel lock poisoned".into(),
        };
    };
    let _ = DECISION_GRACE;
    control.decide(resource, port, proto)
}

/// Connects to the original destination from the parent's namespace.
fn upstream(addr: SocketAddr) -> io::Result<TcpStream> {
    let stream = TcpStream::connect_timeout(&addr, Duration::from_secs(5))?;
    stream.set_nodelay(true).ok();
    stream.set_read_timeout(Some(Duration::from_secs(30)))?;
    stream.set_write_timeout(Some(Duration::from_secs(30)))?;
    Ok(stream)
}

/// Reads bytes until `sniffer` names the resource, fails, or the deadline or
/// cap is reached. Returns the bytes read and the resource (if any).
fn read_name(
    stream: &mut TcpStream,
    sniffer: &mut dyn NameSniffer,
) -> io::Result<(Vec<u8>, Option<Resource>)> {
    let timeout = Duration::from_millis(400);
    let deadline = Instant::now() + timeout;
    let mut buf = [0u8; 4096];
    loop {
        if sniffer.decided() {
            return Ok((sniffer.bytes().to_vec(), sniffer.resource()));
        }
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Ok((sniffer.bytes().to_vec(), sniffer.resource()));
        }
        stream.set_read_timeout(Some(left))?;
        match stream.read(&mut buf) {
            Ok(0) => return Ok((sniffer.bytes().to_vec(), sniffer.resource())),
            Ok(n) => {
                let sniff = sniffer.push(&buf[..n]);
                if sniff != inspect::Sniff::NeedMore || sniffer.bytes().len() >= MAX_NAME {
                    return Ok((sniffer.bytes().to_vec(), sniffer.resource()));
                }
            }
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                return Ok((sniffer.bytes().to_vec(), sniffer.resource()));
            }
            Err(e) => return Err(e),
        }
    }
}

/// A protocol sniffer behind one object, so the TLS and HTTP paths share the
/// read loop.
trait NameSniffer {
    fn push(&mut self, bytes: &[u8]) -> inspect::Sniff;
    fn bytes(&self) -> &[u8];
    fn decided(&self) -> bool;
    fn resource(&self) -> Option<Resource>;
}

struct TlsName(inspect::TlsSniffer, Option<Resource>, bool);
impl NameSniffer for TlsName {
    fn push(&mut self, bytes: &[u8]) -> inspect::Sniff {
        let sniff = self.0.push(bytes);
        if let inspect::Sniff::Named(resource) = &sniff {
            self.1 = Some(resource.clone());
        }
        if self.0.ech() {
            self.2 = true;
        }
        sniff
    }
    fn bytes(&self) -> &[u8] {
        self.0.buffered()
    }
    fn decided(&self) -> bool {
        false
    }
    fn resource(&self) -> Option<Resource> {
        self.1.clone()
    }
}

struct HttpName(inspect::HttpSniffer, Option<Resource>);
impl NameSniffer for HttpName {
    fn push(&mut self, bytes: &[u8]) -> inspect::Sniff {
        let sniff = self.0.push(bytes);
        if let inspect::Sniff::Named(resource) = &sniff {
            self.1 = Some(resource.clone());
        }
        sniff
    }
    fn bytes(&self) -> &[u8] {
        self.0.buffered()
    }
    fn decided(&self) -> bool {
        false
    }
    fn resource(&self) -> Option<Resource> {
        self.1.clone()
    }
}

/// One accepted TCP flow.
fn tcp_flow(
    mut client: TcpStream,
    control: &Arc<Mutex<Control>>,
    relay: &Relay,
    helper: &Arc<Mutex<std::os::unix::net::UnixStream>>,
    sink: Option<&crate::violation::Sink>,
) -> io::Result<()> {
    let destination = client.local_addr()?;
    let peer = client.peer_addr()?;
    let port = destination.port();
    client.set_read_timeout(Some(Duration::from_millis(400)))?;
    let mut original = Vec::new();
    let mut ech = false;
    let resource = if port == 53 {
        // DNS over TCP: a two-byte length prefix then the query.
        let mut head = [0u8; 2];
        if client.read_exact(&mut head).is_err() {
            return Ok(());
        }
        let len = u16::from_be_bytes(head) as usize;
        if len == 0 || len > procage_proxy::relay::dns::MAX_TCP {
            return Ok(());
        }
        let mut message = vec![0u8; len];
        if client.read_exact(&mut message).is_err() {
            return Ok(());
        }
        original.extend_from_slice(&head);
        original.extend_from_slice(&message);
        let Ok(query) = dns::parse_query(&message) else {
            client.shutdown(Shutdown::Both).ok();
            return Ok(());
        };
        let resource = Resource::Domain(query.name.clone());
        let decision = decide(control, relay, &resource, 53, Proto::Tcp);
        if !decision.allowed() {
            let reply = dns::refused(&query);
            let _ = client.write_all(&dns::frame(&reply));
            record(
                sink,
                "network-outbound",
                format!("{}:53 ({})", query.name, reason_text(decision)),
                crate::violation::DeniedBy::Relay,
            );
            client.shutdown(Shutdown::Both).ok();
            return Ok(());
        }
        // Allowed: forward the framed query to the original destination.
        let mut up = upstream(destination)?;
        up.write_all(&dns::frame(&message))?;
        let mut reply_len = [0u8; 2];
        up.read_exact(&mut reply_len)?;
        let n = u16::from_be_bytes(reply_len) as usize;
        if n == 0 || n > procage_proxy::relay::dns::MAX_TCP {
            return Ok(());
        }
        let mut reply = vec![0u8; n];
        up.read_exact(&mut reply)?;
        client.write_all(&reply_len)?;
        client.write_all(&reply)?;
        return Ok(());
    } else if matches!(port, 443 | 8443 | 9443 | 4443) {
        let mut sniffer = TlsName(inspect::TlsSniffer::new(), None, false);
        let (bytes, resource) = read_name(&mut client, &mut sniffer)?;
        ech = sniffer.2;
        original = bytes;
        resource
    } else if matches!(port, 80 | 8080 | 8000 | 8888 | 3000 | 5000) {
        let mut sniffer = HttpName(inspect::HttpSniffer::new(), None);
        let (bytes, resource) = read_name(&mut client, &mut sniffer)?;
        original = bytes;
        resource
    } else {
        // Try TLS first; if the bytes are not TLS, fall back to the address.
        let mut sniffer = TlsName(inspect::TlsSniffer::new(), None, false);
        let (bytes, resource) = read_name(&mut client, &mut sniffer)?;
        ech = sniffer.2;
        original = bytes;
        resource
    };
    if ech {
        record(
            sink,
            "network-outbound",
            format!("{destination} (ECH hides the name)"),
            crate::violation::DeniedBy::Relay,
        );
        client.shutdown(Shutdown::Both).ok();
        return Ok(());
    }
    let resource = resource.unwrap_or_else(|| Resource::Ip(destination.ip()));
    let decision = decide(control, relay, &resource, port, Proto::Tcp);
    if !decision.allowed() {
        record(
            sink,
            "network-outbound",
            format!(
                "{resource:?}:{port} from {peer} ({})",
                reason_text(decision)
            ),
            crate::violation::DeniedBy::Relay,
        );
        client.shutdown(Shutdown::Both).ok();
        return Ok(());
    }
    let mut up = upstream(destination)?;
    if !original.is_empty() {
        up.write_all(&original)?;
    }
    relay_both(&mut client, &mut up)?;
    let _ = helper;
    Ok(())
}

fn reason_text(decision: Decision) -> String {
    match decision.reason() {
        None => "allowed".into(),
        Some(Reason::Policy) => "refused by the control policy".into(),
        Some(Reason::Timeout) => "control decision timed out".into(),
        Some(Reason::ControlLost) => "control channel lost".into(),
        Some(Reason::Malformed) => "malformed control answer".into(),
        Some(Reason::Busy) => "control channel busy".into(),
        Some(Reason::Ech) => "ECH hides the destination name".into(),
        Some(Reason::Dns) => "encrypted DNS is blocked".into(),
        Some(Reason::Blocked) => "blocked".into(),
        Some(other) => format!("refused ({other:?})"),
    }
}

fn relay_both(client: &mut TcpStream, up: &mut TcpStream) -> io::Result<()> {
    let mut c2 = client.try_clone()?;
    let mut up_reader = up.try_clone()?;
    let mut client_up = client.try_clone()?;
    let up_writer = up.try_clone()?;
    let up_thread = std::thread::spawn(move || {
        let _ = io::copy(&mut up_reader, &mut client_up);
        let _ = up_writer.shutdown(Shutdown::Write);
    });
    let _ = io::copy(&mut c2, up);
    let _ = c2.shutdown(Shutdown::Write);
    up_thread.join().ok();
    Ok(())
}

/// One UDP TPROXY socket's loop.
fn udp_loop(
    socket: UdpSocket,
    stop: Arc<AtomicBool>,
    control: Arc<Mutex<Control>>,
    relay: Relay,
    helper: Arc<Mutex<std::os::unix::net::UnixStream>>,
    violations: Option<crate::violation::Sink>,
) {
    let Some(fd) = owned_fd(&socket) else {
        return;
    };
    type UdpFlows = Arc<Mutex<HashMap<(SocketAddr, SocketAddr), Sender<Vec<u8>>>>>;
    let flows: UdpFlows = Arc::new(Mutex::new(HashMap::new()));
    let mut buf = vec![0u8; 65_535];
    let mut quic = inspect::QuicInspector::new();
    while !stop.load(Ordering::Relaxed) {
        match sys::relay_udp_recv(&fd, &mut buf) {
            Ok((source, destination, n)) => {
                let payload = &buf[..n];
                let key = (source, destination);
                if let Ok(map) = flows.lock()
                    && let Some(tx) = map.get(&key)
                {
                    let _ = tx.send(payload.to_vec());
                    continue;
                }
                let resource = if destination.port() == 53 {
                    match dns::parse_query(payload) {
                        Ok(query) => Resource::Domain(query.name),
                        Err(_) => continue,
                    }
                } else if destination.port() == 443 {
                    match quic.push(payload, source, destination) {
                        inspect::Sniff::Named(resource) => resource,
                        _ => Resource::Ip(destination.ip()),
                    }
                } else {
                    Resource::Ip(destination.ip())
                };
                let decision = decide(&control, &relay, &resource, destination.port(), Proto::Udp);
                if !decision.allowed() {
                    record(
                        violations.as_ref(),
                        "network-outbound",
                        format!(
                            "{:?}:{} from {source} ({})",
                            resource,
                            destination.port(),
                            reason_text(decision)
                        ),
                        crate::violation::DeniedBy::Relay,
                    );
                    if destination.port() == 53
                        && let Ok(query) = dns::parse_query(payload)
                    {
                        let reply = dns::refused(&query);
                        send_reply(&helper, destination, source, &reply);
                    }
                    continue;
                }
                if destination.port() == 53 {
                    if let Ok(query) = dns::parse_query(payload)
                        && let Some(reply) = forward_dns(&relay, payload, destination)
                    {
                        let _ = query;
                        send_reply(&helper, destination, source, &reply);
                    }
                    continue;
                }
                // A flow: one connected upstream socket, replies sent back
                // through the helper with the original destination as source.
                let Ok(up) = UdpSocket::bind("0.0.0.0:0") else {
                    continue;
                };
                if up.connect(destination).is_err() {
                    continue;
                }
                up.set_read_timeout(Some(Duration::from_millis(200))).ok();
                let _ = up.send(payload);
                let (tx, rx) = mpsc::channel::<Vec<u8>>();
                if let Ok(mut map) = flows.lock() {
                    map.insert(key, tx);
                }
                let helper = helper.clone();
                let flows = flows.clone();
                let dest = destination;
                let src = source;
                let stop = stop.clone();
                std::thread::spawn(move || {
                    let mut idle = Instant::now();
                    let mut reply = vec![0u8; 65_535];
                    loop {
                        if stop.load(Ordering::Relaxed) || idle.elapsed() > UDP_IDLE {
                            break;
                        }
                        while let Ok(data) = rx.try_recv() {
                            let _ = up.send(&data);
                            idle = Instant::now();
                        }
                        match up.recv(&mut reply) {
                            Ok(n) => {
                                send_reply(&helper, dest, src, &reply[..n]);
                                idle = Instant::now();
                            }
                            Err(e)
                                if matches!(
                                    e.kind(),
                                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                                ) => {}
                            Err(_) => break,
                        }
                    }
                    if let Ok(mut map) = flows.lock() {
                        map.remove(&(src, dest));
                    }
                });
            }
            Err(e) if e == libc::EINTR => {}
            Err(_) => break,
        }
    }
}

fn owned_fd(socket: &UdpSocket) -> Option<OwnedFd> {
    use std::os::fd::AsFd;
    socket.as_fd().try_clone_to_owned().ok()
}

/// Sends one UDP reply through the helper from `source` to `target`.
fn send_reply(
    helper: &Arc<Mutex<std::os::unix::net::UnixStream>>,
    source: SocketAddr,
    target: SocketAddr,
    payload: &[u8],
) {
    let (IpAddr::V4(src_ip), IpAddr::V4(dst_ip)) = (source.ip(), target.ip()) else {
        return;
    };
    let mut frame = Vec::with_capacity(1 + 4 + 2 + 4 + 2 + 2 + payload.len());
    frame.push(1);
    frame.extend_from_slice(&src_ip.octets());
    frame.extend_from_slice(&source.port().to_be_bytes());
    frame.extend_from_slice(&dst_ip.octets());
    frame.extend_from_slice(&target.port().to_be_bytes());
    frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    frame.extend_from_slice(payload);
    if let Ok(mut helper) = helper.lock() {
        let _ = helper.write_all(&frame);
    }
}

/// Resolves the upstream DNS server for a query redirected from the app
/// namespace, where the original server is not visible.
fn dns_upstream(relay: &Relay) -> Option<SocketAddr> {
    if let Some(upstream) = relay.dns_upstream() {
        return Some(upstream);
    }
    let text = std::fs::read_to_string("/etc/resolv.conf").ok()?;
    for line in text.lines() {
        let line = line.trim();
        if let Some(server) = line.strip_prefix("nameserver") {
            let server = server.trim();
            let Ok(ip) = server.parse::<IpAddr>() else {
                continue;
            };
            if ip.is_loopback() {
                continue;
            }
            return Some(SocketAddr::new(ip, 53));
        }
    }
    None
}

/// Sends one DNS message upstream and reads one reply. `None` on any failure.
fn forward_dns(relay: &Relay, query: &[u8], destination: SocketAddr) -> Option<Vec<u8>> {
    let server = if destination.ip().is_loopback() || destination.port() != 53 {
        dns_upstream(relay)?
    } else {
        destination
    };
    let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect(server).ok()?;
    socket.set_read_timeout(Some(Duration::from_secs(2))).ok()?;
    socket.send(query).ok()?;
    let mut reply = vec![0u8; 4096];
    let n = socket.recv(&mut reply).ok()?;
    reply.truncate(n);
    Some(reply)
}

/// The app namespace's DNS listener (UDP): the resolver stub's queries.
fn dns_listener_udp(
    socket: UdpSocket,
    stop: Arc<AtomicBool>,
    control: Arc<Mutex<Control>>,
    relay: Relay,
    _helper: Arc<Mutex<std::os::unix::net::UnixStream>>,
    violations: Option<crate::violation::Sink>,
) {
    let mut buf = vec![0u8; 65_535];
    socket
        .set_read_timeout(Some(Duration::from_millis(200)))
        .ok();
    while !stop.load(Ordering::Relaxed) {
        let Ok((n, source)) = socket.recv_from(&mut buf) else {
            if stop.load(Ordering::Relaxed) {
                break;
            }
            continue;
        };
        let Ok(query) = dns::parse_query(&buf[..n]) else {
            continue;
        };
        let resource = Resource::Domain(query.name.clone());
        let decision = decide(&control, &relay, &resource, 53, Proto::Udp);
        let reply = if decision.allowed() {
            forward_dns(&relay, &buf[..n], SocketAddr::from(([127, 0, 0, 53], 53)))
                .unwrap_or_else(|| dns::servfail(&query))
        } else {
            record(
                violations.as_ref(),
                "network-outbound",
                format!("{}:53 ({})", query.name, reason_text(decision)),
                crate::violation::DeniedBy::Relay,
            );
            dns::refused(&query)
        };
        let _ = socket.send_to(&reply, source);
    }
}

/// The app namespace's DNS listener (TCP).
fn dns_listener_tcp(
    listener: TcpListener,
    stop: Arc<AtomicBool>,
    control: Arc<Mutex<Control>>,
    relay: Relay,
    violations: Option<crate::violation::Sink>,
) {
    listener.set_nonblocking(true).ok();
    while !stop.load(Ordering::Relaxed) {
        match listener.accept() {
            Ok((mut stream, _)) => {
                let mut head = [0u8; 2];
                if stream.read_exact(&mut head).is_err() {
                    continue;
                }
                let len = u16::from_be_bytes(head) as usize;
                if len == 0 || len > dns::MAX_TCP {
                    continue;
                }
                let mut message = vec![0u8; len];
                if stream.read_exact(&mut message).is_err() {
                    continue;
                }
                let Ok(query) = dns::parse_query(&message) else {
                    continue;
                };
                let resource = Resource::Domain(query.name.clone());
                let decision = decide(&control, &relay, &resource, 53, Proto::Tcp);
                let reply = if decision.allowed() {
                    forward_dns(&relay, &message, SocketAddr::from(([127, 0, 0, 53], 53)))
                        .unwrap_or_else(|| dns::servfail(&query))
                } else {
                    record(
                        violations.as_ref(),
                        "network-outbound",
                        format!("{}:53 ({})", query.name, reason_text(decision)),
                        crate::violation::DeniedBy::Relay,
                    );
                    dns::refused(&query)
                };
                let _ = stream.write_all(&dns::frame(&reply));
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(2));
            }
            Err(_) => break,
        }
    }
}

/// Installs the helper's namespace and sockets. Called in the forked helper:
/// never returns.
pub(crate) fn helper_main(child_socket: c_int, app_ns: OwnedFd, ready: c_int, port: u16) -> ! {
    use std::os::fd::AsRawFd;
    let socket_fd = child_socket;
    let ns_fd = app_ns.as_raw_fd();
    let keep = [socket_fd, ns_fd, ready];
    sys::close_others(&keep, 1024);
    let _ = sys::death_signal();
    let _ = sys::non_dumpable();
    let fail = |code: u8, errno: i32| -> ! {
        eprintln!("procage relay helper: step {code} failed with errno {errno}");
        let _ = sys::signal_and_close(ready, code);
        sys::exit_now(1)
    };
    if let Err(e) = sys::unshare_net() {
        fail(2, e);
    }
    if let Err(e) = sys::link_up("lo") {
        fail(3, e);
    }
    if let Err(e) = sys::create_veth(PROXY_IF, APP_IF) {
        fail(4, e);
    }
    if let Err(e) = sys::link_addr(PROXY_IF, PROXY_ADDR, APP_PREFIX) {
        fail(5, e);
    }
    if let Err(e) = sys::link_up(PROXY_IF) {
        fail(6, e);
    }
    if let Err(e) = sys::move_link(APP_IF, &app_ns) {
        fail(7, e);
    }
    if let Err(e) = sys::local_default_route(POLICY_TABLE) {
        fail(8, e);
    }
    if let Err(e) = sys::fwmark_rule(MARK, POLICY_TABLE) {
        fail(9, e);
    }
    if let Err(e) = sys::nft_install_relay(port) {
        fail(10, e);
    }
    let tcp = match sys::relay_tcp_listener(port) {
        Ok(fd) => fd,
        Err(e) => fail(11, e),
    };
    let udp = match sys::relay_udp_socket(port) {
        Ok(fd) => fd,
        Err(e) => fail(12, e),
    };
    let fds = [
        std::os::fd::AsRawFd::as_raw_fd(&tcp),
        std::os::fd::AsRawFd::as_raw_fd(&udp),
    ];
    if let Err(e) = sys::send_with_fds_fd(socket_fd, &[1], &fds) {
        fail(13, e);
    }
    if let Err(e) = sys::signal_and_close(ready, 1) {
        fail(14, e);
    }
    if sys::keep_only_net_raw().is_err() {
        // The child sees the closed ready pipe and fails the spawn.
        sys::exit_now(1);
    }
    let allow = [
        libc::SYS_recvmsg as u32,
        libc::SYS_read as u32,
        libc::SYS_write as u32,
        libc::SYS_sendmsg as u32,
        libc::SYS_socket as u32,
        libc::SYS_setsockopt as u32,
        libc::SYS_bind as u32,
        libc::SYS_sendto as u32,
        libc::SYS_close as u32,
        libc::SYS_exit as u32,
        libc::SYS_exit_group as u32,
        libc::SYS_rt_sigreturn as u32,
        libc::SYS_getpid as u32,
    ];
    let mut filter = super::seccomp::allowlist(&super::seccomp::NATIVE, &allow);
    let _ = sys::install_filter_here(&mut filter);
    // Reply loop: fixed buffers, no allocation after the filter.
    let mut frame = [0u8; 65_535 + 15];
    let mut at = 0usize;
    loop {
        let n = sys::read_into(socket_fd, &mut frame, at);
        if n <= 0 {
            sys::exit_now(0);
        }
        at += n as usize;
        let mut consumed = 0usize;
        while at - consumed >= 15 {
            let payload_len =
                u16::from_be_bytes([frame[consumed + 13], frame[consumed + 14]]) as usize;
            let total = 15 + payload_len;
            if at - consumed < total {
                break;
            }
            let src_ip = std::net::Ipv4Addr::new(
                frame[consumed + 1],
                frame[consumed + 2],
                frame[consumed + 3],
                frame[consumed + 4],
            );
            let src_port = u16::from_be_bytes([frame[consumed + 5], frame[consumed + 6]]);
            let dst_ip = std::net::Ipv4Addr::new(
                frame[consumed + 7],
                frame[consumed + 8],
                frame[consumed + 9],
                frame[consumed + 10],
            );
            let dst_port = u16::from_be_bytes([frame[consumed + 11], frame[consumed + 12]]);
            let payload = &frame[consumed + 15..consumed + 15 + payload_len];
            let _ = sys::transparent_udp_send(
                SocketAddr::from((src_ip, src_port)),
                SocketAddr::from((dst_ip, dst_port)),
                payload,
            );
            consumed += total;
        }
        if consumed > 0 {
            frame.copy_within(consumed..at, 0);
            at -= consumed;
        }
        if at > frame.len() {
            // A frame longer than the protocol allows: end the helper.
            sys::exit_now(1);
        }
    }
}

use std::ffi::c_int;
