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
/// The IPv6 ULA pair on the same veth; both namespaces get the prefix.
pub(crate) const APP_ADDR6: [u8; 16] = [0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
pub(crate) const PROXY_ADDR6: [u8; 16] = [0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
pub(crate) const APP_PREFIX6: u8 = 64;
pub(crate) const PROXY_IF: &str = "procage-p0";
pub(crate) const APP_IF: &str = "procage-a0";
const POLICY_TABLE: u32 = 100;
const MARK: u32 = 1;
/// How long one decision may wait beyond the relay's own timeout.
const DECISION_GRACE: Duration = Duration::from_millis(50);
/// The most DNS answers one run maps to names.
const DNS_MAP_MAX: usize = 4096;
/// The longest TTL a mapped answer may keep, whatever the record says.
const DNS_TTL_MAX: u64 = 3600;
/// How long a QUIC Initial flow may wait for its ClientHello before the
/// destination address is asked for instead.
const QUIC_DEADLINE: Duration = Duration::from_millis(100);
/// The most Initial datagrams buffered for one QUIC flow.
const QUIC_MAX_PACKETS: usize = 8;
/// The most QUIC flows buffered at once.
const QUIC_MAX_PENDING: usize = 64;
/// The most bytes buffered to name a TCP flow.
const MAX_NAME: usize = 64 * 1024;
/// The most concurrent TCP flows a run relays.
const MAX_TCP: usize = 128;
/// How long an idle UDP flow keeps its upstream socket.
const UDP_IDLE: Duration = Duration::from_secs(30);
/// The most upstream UDP flows one run keeps at once. Beyond it a datagram
/// is dropped (DNS still answers REFUSED through its one-shot path); no
/// socket or thread is created.
const MAX_UDP_FLOWS: usize = 256;

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
        sys::recv_with_fds(&helper, 4, 5_000).map_err(io::Error::from_raw_os_error)?;
    if head.first() != Some(&1) || fds.len() != 4 {
        return Err(io::Error::other(
            "relay helper did not hand over its sockets",
        ));
    }
    let mut fds = fds.into_iter();
    let tcp = TcpListener::from(fds.next().expect("checked"));
    let udp = UdpSocket::from(fds.next().expect("checked"));
    let tcp6 = TcpListener::from(fds.next().expect("checked"));
    let udp6 = UdpSocket::from(fds.next().expect("checked"));
    let (head, fds) = sys::recv_with_fds(&dns, 4, 5_000).map_err(io::Error::from_raw_os_error)?;
    let (dns_udp, dns_tcp, dns_udp6, dns_tcp6) = if head.first() == Some(&2) && fds.len() == 4 {
        let mut fds = fds.into_iter();
        (
            Some(UdpSocket::from(fds.next().expect("checked"))),
            Some(TcpListener::from(fds.next().expect("checked"))),
            Some(UdpSocket::from(fds.next().expect("checked"))),
            Some(TcpListener::from(fds.next().expect("checked"))),
        )
    } else {
        // DNS is optional: without its listeners, resolver stubs time out
        // rather than leak.
        (None, None, None, None)
    };
    Run::start(
        relay, control, helper, tcp, udp, tcp6, udp6, dns_udp, dns_tcp, dns_udp6, dns_tcp6,
        violations,
    )
}

/// One run's relay: the control channel, the handed-over listeners and the
/// helper channel.
#[derive(Debug)]
pub(crate) struct Run {
    stop: Arc<AtomicBool>,
    handles: Vec<std::thread::JoinHandle<()>>,
    socket: Arc<Mutex<std::os::unix::net::UnixStream>>,
    control: Control,
    relay: Relay,
    dns_map: Arc<DnsMap>,
    violations: Option<crate::violation::Sink>,
}

/// The names an allowed DNS answer has authorized, per address, with the
/// record's TTL. A later flow that names no host may use the entry instead of
/// its bare address; an expired or evicted entry authorizes nothing.
#[derive(Debug, Default)]
struct DnsMap {
    entries: Mutex<HashMap<IpAddr, CacheEntry>>,
}

#[derive(Debug, Clone)]
struct CacheEntry {
    name: String,
    expires: Instant,
}

impl DnsMap {
    fn insert(&self, name: &str, answers: &[dns::Answer]) {
        self.insert_at(name, answers, Instant::now());
    }

    fn insert_at(&self, name: &str, answers: &[dns::Answer], now: Instant) {
        let Ok(mut entries) = self.entries.lock() else {
            return;
        };
        if entries.len() >= DNS_MAP_MAX {
            entries.retain(|_, entry| entry.expires > now);
            if entries.len() >= DNS_MAP_MAX {
                // Full: no new name is remembered; the address alone must be
                // authorized, so the limit fails closed.
                return;
            }
        }
        for answer in answers {
            if answer.ttl == 0 {
                continue;
            }
            let ttl = u64::from(answer.ttl).min(DNS_TTL_MAX);
            entries.insert(
                answer.ip,
                CacheEntry {
                    name: name.to_string(),
                    expires: now + Duration::from_secs(ttl),
                },
            );
        }
    }

    fn insert_reply(&self, query: &dns::Query, reply: &[u8]) {
        if let Ok(answers) = dns::parse_answers(reply, &query.name) {
            self.insert(&query.name, &answers);
        }
    }

    fn name_for(&self, ip: IpAddr) -> Option<String> {
        let Ok(mut entries) = self.entries.lock() else {
            return None;
        };
        match entries.get(&ip) {
            Some(entry) if entry.expires > Instant::now() => Some(entry.name.clone()),
            Some(_) => {
                entries.remove(&ip);
                None
            }
            None => None,
        }
    }
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
        tcp6: TcpListener,
        udp6: UdpSocket,
        dns_udp: Option<UdpSocket>,
        dns_tcp: Option<TcpListener>,
        dns_udp6: Option<UdpSocket>,
        dns_tcp6: Option<TcpListener>,
        violations: Option<crate::violation::Sink>,
    ) -> io::Result<Run> {
        let stop = Arc::new(AtomicBool::new(false));
        let socket = Arc::new(Mutex::new(std::os::unix::net::UnixStream::from(socket)));
        let dns_map = Arc::new(DnsMap::default());
        let mut run = Run {
            stop: stop.clone(),
            handles: Vec::new(),
            socket: socket.clone(),
            control: control.clone(),
            relay: relay.clone(),
            dns_map: dns_map.clone(),
            violations: violations.clone(),
        };
        let control6 = control.clone();
        let relay6 = relay.clone();
        let socket6 = socket.clone();
        let violations6 = violations.clone();
        let map6 = dns_map.clone();
        let udp6_map = dns_map.clone();
        let udp6_control = control.clone();
        let udp6_relay = relay.clone();
        let udp6_socket = socket.clone();
        let udp6_violations = violations.clone();
        let inflight6 = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        tcp.set_nonblocking(true)?;
        tcp6.set_nonblocking(true)?;
        let tcp_stop = stop.clone();
        let tcp_control = control.clone();
        let tcp_relay = relay.clone();
        let tcp_socket = socket.clone();
        let tcp_violations = violations.clone();
        let tcp_map = dns_map.clone();
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
                        let map = tcp_map.clone();
                        std::thread::spawn(move || {
                            let _ =
                                tcp_flow(stream, &control, &relay, &socket, sink.as_ref(), &map);
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
        // The IPv6 listener accepts the same flows; the original destination
        // is its local address.
        let tcp6_stop = stop.clone();
        run.handles.push(std::thread::spawn(move || {
            loop {
                if tcp6_stop.load(Ordering::Relaxed) {
                    break;
                }
                match tcp6.accept() {
                    Ok((stream, _)) => {
                        if inflight6.load(Ordering::Relaxed) >= MAX_TCP {
                            let _ = stream.shutdown(Shutdown::Both);
                            continue;
                        }
                        inflight6.fetch_add(1, Ordering::Relaxed);
                        let control = control6.clone();
                        let relay = relay6.clone();
                        let socket = socket6.clone();
                        let sink = violations6.clone();
                        let count = inflight6.clone();
                        let map = map6.clone();
                        std::thread::spawn(move || {
                            let _ =
                                tcp_flow(stream, &control, &relay, &socket, sink.as_ref(), &map);
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
        let udp_map = dns_map.clone();
        run.handles.push(std::thread::spawn(move || {
            udp_loop(udp, udp_stop, control, relay, socket, udp_map, violations);
        }));
        let udp6_stop = stop.clone();
        run.handles.push(std::thread::spawn(move || {
            udp_loop(
                udp6,
                udp6_stop,
                udp6_control,
                udp6_relay,
                udp6_socket,
                udp6_map,
                udp6_violations,
            );
        }));
        if let Some(dns_udp) = dns_udp {
            let dns_stop = run.stop.clone();
            let dns_control = run.control.clone();
            let dns_relay = run.relay.clone();
            let dns_socket = run.socket.clone();
            let dns_sink = run.violations.clone();
            let dns_map = run.dns_map.clone();
            run.handles.push(std::thread::spawn(move || {
                dns_listener_udp(
                    dns_udp,
                    dns_stop,
                    dns_control,
                    dns_relay,
                    dns_socket,
                    dns_map,
                    dns_sink,
                );
            }));
        }
        if let Some(dns_tcp) = dns_tcp {
            let dns_stop = run.stop.clone();
            let dns_control = run.control.clone();
            let dns_relay = run.relay.clone();
            let dns_sink = run.violations.clone();
            let dns_map = run.dns_map.clone();
            run.handles.push(std::thread::spawn(move || {
                dns_listener_tcp(dns_tcp, dns_stop, dns_control, dns_relay, dns_map, dns_sink);
            }));
        }
        if let Some(dns_udp6) = dns_udp6 {
            let dns_stop = run.stop.clone();
            let dns_control = run.control.clone();
            let dns_relay = run.relay.clone();
            let dns_socket = run.socket.clone();
            let dns_sink = run.violations.clone();
            let dns_map = run.dns_map.clone();
            run.handles.push(std::thread::spawn(move || {
                dns_listener_udp(
                    dns_udp6,
                    dns_stop,
                    dns_control,
                    dns_relay,
                    dns_socket,
                    dns_map,
                    dns_sink,
                );
            }));
        }
        if let Some(dns_tcp6) = dns_tcp6 {
            let dns_stop = run.stop.clone();
            let dns_control = run.control.clone();
            let dns_relay = run.relay.clone();
            let dns_sink = run.violations.clone();
            let dns_map = run.dns_map.clone();
            run.handles.push(std::thread::spawn(move || {
                dns_listener_tcp(
                    dns_tcp6,
                    dns_stop,
                    dns_control,
                    dns_relay,
                    dns_map,
                    dns_sink,
                );
            }));
        }
        Ok(run)
    }
}
impl Drop for Run {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        self.control.close();
        // The helper channel closes too: no reply socket keeps servicing a
        // run whose child is gone.
        if let Ok(socket) = self.socket.lock() {
            let _ = socket.shutdown(Shutdown::Both);
        }
        // Listener loops notice within one poll interval and upstream flow
        // threads within their 200 ms read timeout; each drops its socket.
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
    control: &Control,
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
    control: &Control,
    relay: &Relay,
    helper: &Arc<Mutex<std::os::unix::net::UnixStream>>,
    sink: Option<&crate::violation::Sink>,
    dns_map: &DnsMap,
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
        // Allowed: forward the query through the same upstream policy as
        // UDP; no resolver means SERVFAIL, not an open connection.
        let reply =
            forward_dns_tcp(relay, &message, destination).unwrap_or_else(|| dns::servfail(&query));
        dns_map.insert_reply(&query, &reply);
        client.write_all(&dns::frame(&reply))?;
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
    let resource = resource.unwrap_or_else(|| {
        dns_map
            .name_for(destination.ip())
            .map(Resource::Domain)
            .unwrap_or_else(|| Resource::Ip(destination.ip()))
    });
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
    // The sniff deadline must not survive into the relayed stream: a slow
    // client or an idle connection may take much longer than 400 ms.
    client.set_read_timeout(None)?;
    client.set_write_timeout(None)?;
    up.set_read_timeout(None)?;
    up.set_write_timeout(None)?;
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
struct PendingQuic {
    datagrams: Vec<Vec<u8>>,
    bytes: usize,
    started: Instant,
    inspector: inspect::QuicInspector,
}

enum QuicOutcome {
    NeedMore,
    Resource(Resource),
    Ech,
    Overflow,
}

fn feed_quic(
    pending: &mut PendingQuic,
    payload: &[u8],
    source: SocketAddr,
    destination: SocketAddr,
) -> QuicOutcome {
    if pending.datagrams.len() >= QUIC_MAX_PACKETS
        || pending.bytes + payload.len() > inspect::MAX_QUIC_STREAM
    {
        return QuicOutcome::Overflow;
    }
    pending.datagrams.push(payload.to_vec());
    pending.bytes += payload.len();
    match pending.inspector.push(payload, source, destination) {
        inspect::Sniff::Named(resource) => QuicOutcome::Resource(resource),
        inspect::Sniff::Ech => QuicOutcome::Ech,
        inspect::Sniff::NoName | inspect::Sniff::NotThis => {
            QuicOutcome::Resource(Resource::Ip(destination.ip()))
        }
        inspect::Sniff::NeedMore => QuicOutcome::NeedMore,
    }
}

type UdpFlows = Arc<Mutex<HashMap<(SocketAddr, SocketAddr), Sender<Vec<u8>>>>>;

/// Starts one upstream UDP flow and sends `payloads` to it in order.
fn start_udp_flow(
    flows: &UdpFlows,
    key: (SocketAddr, SocketAddr),
    payloads: &[Vec<u8>],
    destination: SocketAddr,
    helper: &Arc<Mutex<std::os::unix::net::UnixStream>>,
    stop: &Arc<AtomicBool>,
) {
    let (source, destination_key) = key;
    {
        let Ok(map) = flows.lock() else {
            return;
        };
        if map.len() >= MAX_UDP_FLOWS {
            // Fail closed: no socket, thread or upstream traffic beyond the
            // fixed per-run bound.
            return;
        }
    }
    let bind = if destination.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let Ok(up) = UdpSocket::bind(bind) else {
        return;
    };
    if up.connect(destination).is_err() {
        return;
    }
    up.set_read_timeout(Some(Duration::from_millis(200))).ok();
    for payload in payloads {
        let _ = up.send(payload);
    }
    let (tx, rx) = mpsc::channel::<Vec<u8>>();
    {
        let Ok(mut map) = flows.lock() else {
            return;
        };
        if map.len() >= MAX_UDP_FLOWS {
            return;
        }
        map.insert(key, tx);
    }
    let helper = helper.clone();
    let flows = flows.clone();
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
                    send_reply(&helper, destination_key, source, &reply[..n]);
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
            map.remove(&key);
        }
    });
}

/// One UDP TPROXY socket's loop. QUIC Initials are buffered per flow until
/// the ClientHello names a host, ECH is seen, the bounded deadline passes or
/// the packet/byte cap is hit; only then is one decision made and the whole
/// buffer forwarded, so the first datagram never leaves before its name.
fn udp_loop(
    socket: UdpSocket,
    stop: Arc<AtomicBool>,
    control: Control,
    relay: Relay,
    helper: Arc<Mutex<std::os::unix::net::UnixStream>>,
    dns_map: Arc<DnsMap>,
    violations: Option<crate::violation::Sink>,
) {
    let Some(fd) = owned_fd(&socket) else {
        return;
    };
    let flows: UdpFlows = Arc::new(Mutex::new(HashMap::new()));
    let mut pending: HashMap<(SocketAddr, SocketAddr), PendingQuic> = HashMap::new();
    let mut buf = vec![0u8; 65_535];
    socket
        .set_read_timeout(Some(Duration::from_millis(50)))
        .ok();
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
                if destination.port() == 443 {
                    let existing = pending.remove(&key);
                    let overflow = existing.as_ref().is_some_and(|entry| {
                        entry.datagrams.len() >= QUIC_MAX_PACKETS
                            || entry.bytes + payload.len() > inspect::MAX_QUIC_STREAM
                    }) || (existing.is_none() && pending.len() >= QUIC_MAX_PENDING);
                    let mut entry = existing.unwrap_or_else(|| PendingQuic {
                        datagrams: Vec::new(),
                        bytes: 0,
                        started: Instant::now(),
                        inspector: inspect::QuicInspector::new(),
                    });
                    let outcome = if overflow {
                        entry.datagrams.push(payload.to_vec());
                        QuicOutcome::Overflow
                    } else {
                        feed_quic(&mut entry, payload, source, destination)
                    };
                    let expired = entry.started.elapsed() >= QUIC_DEADLINE;
                    let resource = match outcome {
                        QuicOutcome::NeedMore if !expired => {
                            pending.insert(key, entry);
                            continue;
                        }
                        QuicOutcome::NeedMore | QuicOutcome::Overflow => {
                            Resource::Ip(destination.ip())
                        }
                        QuicOutcome::Resource(resource) => resource,
                        QuicOutcome::Ech => {
                            record(
                                violations.as_ref(),
                                "network-outbound",
                                format!("{destination} (ECH hides the name)"),
                                crate::violation::DeniedBy::Relay,
                            );
                            continue;
                        }
                    };
                    let decision =
                        decide(&control, &relay, &resource, destination.port(), Proto::Udp);
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
                        continue;
                    }
                    start_udp_flow(&flows, key, &entry.datagrams, destination, &helper, &stop);
                    continue;
                }
                let resource = if destination.port() == 53 {
                    match dns::parse_query(payload) {
                        Ok(query) => Resource::Domain(query.name),
                        Err(_) => continue,
                    }
                } else {
                    dns_map
                        .name_for(destination.ip())
                        .map(Resource::Domain)
                        .unwrap_or_else(|| Resource::Ip(destination.ip()))
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
                        dns_map.insert_reply(&query, &reply);
                        send_reply(&helper, destination, source, &reply);
                    }
                    continue;
                }
                start_udp_flow(
                    &flows,
                    key,
                    &[payload.to_vec()],
                    destination,
                    &helper,
                    &stop,
                );
            }
            Err(e) if e == libc::EINTR => {}
            Err(e) if e == libc::EAGAIN || e == libc::EWOULDBLOCK => {
                flush_quic(
                    &mut pending,
                    &control,
                    &relay,
                    &helper,
                    &flows,
                    &stop,
                    violations.as_ref(),
                );
            }
            Err(e) => {
                let _ = e;
                break;
            }
        }
    }
}

/// Resolves buffered QUIC flows whose deadline passed, asking for the
/// destination address (never forwarding before that decision).
#[allow(clippy::too_many_arguments)]
fn flush_quic(
    pending: &mut HashMap<(SocketAddr, SocketAddr), PendingQuic>,
    control: &Control,
    relay: &Relay,
    helper: &Arc<Mutex<std::os::unix::net::UnixStream>>,
    flows: &UdpFlows,
    stop: &Arc<AtomicBool>,
    violations: Option<&crate::violation::Sink>,
) {
    let expired: Vec<(SocketAddr, SocketAddr)> = pending
        .iter()
        .filter(|(_, entry)| entry.started.elapsed() >= QUIC_DEADLINE)
        .map(|(key, _)| *key)
        .collect();
    for key in expired {
        let Some(entry) = pending.remove(&key) else {
            continue;
        };
        let destination = key.1;
        let resource = Resource::Ip(destination.ip());
        let decision = decide(control, relay, &resource, destination.port(), Proto::Udp);
        if !decision.allowed() {
            record(
                violations,
                "network-outbound",
                format!(
                    "{:?}:{} from {} ({})",
                    resource,
                    destination.port(),
                    key.0,
                    reason_text(decision)
                ),
                crate::violation::DeniedBy::Relay,
            );
            continue;
        }
        start_udp_flow(flows, key, &entry.datagrams, destination, helper, stop);
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
    let mut frame = Vec::with_capacity(39 + payload.len());
    match (source, target) {
        (SocketAddr::V4(source), SocketAddr::V4(target)) => {
            frame.push(1);
            frame.extend_from_slice(&source.ip().octets());
            frame.extend_from_slice(&source.port().to_be_bytes());
            frame.extend_from_slice(&target.ip().octets());
            frame.extend_from_slice(&target.port().to_be_bytes());
        }
        (SocketAddr::V6(source), SocketAddr::V6(target)) => {
            frame.push(2);
            frame.extend_from_slice(&source.ip().octets());
            frame.extend_from_slice(&source.port().to_be_bytes());
            frame.extend_from_slice(&target.ip().octets());
            frame.extend_from_slice(&target.port().to_be_bytes());
        }
        _ => return,
    }
    frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    frame.extend_from_slice(payload);
    if let Ok(mut helper) = helper.lock() {
        let _ = helper.write_all(&frame);
    }
}

/// The first nameserver in `text`, including a loopback stub: in the parent
/// namespace `127.0.0.53` is the host's systemd-resolved listener.
fn resolver_from_conf(text: &str) -> Option<SocketAddr> {
    for line in text.lines() {
        let line = line.trim();
        let Some(server) = line.strip_prefix("nameserver") else {
            continue;
        };
        let server = server.trim();
        if let Ok(ip) = server.parse::<IpAddr>() {
            return Some(SocketAddr::new(ip, 53));
        }
    }
    None
}

/// Resolves the upstream DNS server: the relay's explicit choice, else the
/// chosen resolver configuration or the parent's system resolver (a loopback
/// stub included), else `None` (the caller answers SERVFAIL).
fn dns_upstream(relay: &Relay) -> Option<SocketAddr> {
    if let Some(upstream) = relay.dns_upstream() {
        return Some(upstream);
    }
    if let Some(path) = relay.resolv_conf() {
        let text = std::fs::read_to_string(path).ok()?;
        return resolver_from_conf(&text);
    }
    for path in [
        "/etc/resolv.conf",
        "/run/systemd/resolve/resolv.conf",
        "/run/systemd/resolve/stub-resolv.conf",
    ] {
        if let Ok(text) = std::fs::read_to_string(path)
            && let Some(server) = resolver_from_conf(&text)
        {
            return Some(server);
        }
    }
    None
}

/// The server for a DNS flow: the original destination when it is a real
/// external server, else the parent's resolver. A loopback destination can
/// only be a child stub, so it is never forwarded to in the parent's
/// namespace.
fn dns_server(relay: &Relay, destination: SocketAddr) -> Option<SocketAddr> {
    if destination.ip().is_loopback() || destination.port() != 53 {
        dns_upstream(relay)
    } else {
        Some(destination)
    }
}

/// Sends one DNS message upstream and reads one reply. `None` on any failure.
fn forward_dns(relay: &Relay, query: &[u8], destination: SocketAddr) -> Option<Vec<u8>> {
    let server = dns_server(relay, destination)?;
    let bind = if server.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let socket = UdpSocket::bind(bind).ok()?;
    socket.connect(server).ok()?;
    socket.set_read_timeout(Some(Duration::from_secs(2))).ok()?;
    socket.send(query).ok()?;
    let mut reply = vec![0u8; 4096];
    let n = socket.recv(&mut reply).ok()?;
    reply.truncate(n);
    Some(reply)
}

/// DNS over TCP to the selected upstream, with the same upstream policy as
/// UDP. The reply is the message without its two-byte length prefix.
fn forward_dns_tcp(relay: &Relay, query: &[u8], destination: SocketAddr) -> Option<Vec<u8>> {
    let server = dns_server(relay, destination)?;
    let mut stream = TcpStream::connect_timeout(&server, Duration::from_secs(2)).ok()?;
    stream.set_read_timeout(Some(Duration::from_secs(2))).ok()?;
    stream
        .set_write_timeout(Some(Duration::from_secs(2)))
        .ok()?;
    stream.write_all(&dns::frame(query)).ok()?;
    let mut head = [0u8; 2];
    stream.read_exact(&mut head).ok()?;
    let len = u16::from_be_bytes(head) as usize;
    if len == 0 || len > dns::MAX_TCP {
        return None;
    }
    let mut reply = vec![0u8; len];
    stream.read_exact(&mut reply).ok()?;
    Some(reply)
}

/// The app namespace's DNS listener (UDP): the resolver stub's queries.
fn dns_listener_udp(
    socket: UdpSocket,
    stop: Arc<AtomicBool>,
    control: Control,
    relay: Relay,
    _helper: Arc<Mutex<std::os::unix::net::UnixStream>>,
    dns_map: Arc<DnsMap>,
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
            let reply = forward_dns(&relay, &buf[..n], SocketAddr::from(([127, 0, 0, 53], 53)))
                .unwrap_or_else(|| dns::servfail(&query));
            dns_map.insert_reply(&query, &reply);
            reply
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
    control: Control,
    relay: Relay,
    dns_map: Arc<DnsMap>,
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
                    let reply =
                        forward_dns_tcp(&relay, &message, SocketAddr::from(([127, 0, 0, 53], 53)))
                            .unwrap_or_else(|| dns::servfail(&query));
                    dns_map.insert_reply(&query, &reply);
                    reply
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
    if let Err(e) = sys::link_addr6(PROXY_IF, PROXY_ADDR6, APP_PREFIX6) {
        fail(8, e);
    }
    if let Err(e) = sys::link_up(PROXY_IF) {
        fail(9, e);
    }
    if let Err(e) = sys::local_default_route6(POLICY_TABLE) {
        fail(8, e);
    }
    if let Err(e) = sys::fwmark_rule6(MARK, POLICY_TABLE) {
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
    let tcp6 = match sys::relay_tcp_listener6(port) {
        Ok(fd) => fd,
        Err(e) => fail(11, e),
    };
    let udp6 = match sys::relay_udp_socket6(port) {
        Ok(fd) => fd,
        Err(e) => fail(12, e),
    };
    let fds = [
        std::os::fd::AsRawFd::as_raw_fd(&tcp),
        std::os::fd::AsRawFd::as_raw_fd(&udp),
        std::os::fd::AsRawFd::as_raw_fd(&tcp6),
        std::os::fd::AsRawFd::as_raw_fd(&udp6),
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
    let mut frame = [0u8; 65_535 + 39];
    let mut at = 0usize;
    loop {
        let n = sys::read_into(socket_fd, &mut frame, at);
        if n <= 0 {
            sys::exit_now(0);
        }
        at += n as usize;
        let mut consumed = 0usize;
        while at - consumed >= 15 {
            let kind = frame[consumed];
            let (address_len, header) = match kind {
                1 => (4, 15usize),
                2 => (16, 39usize),
                _ => sys::exit_now(1),
            };
            if at - consumed < header {
                break;
            }
            let src_port_at = 1 + address_len;
            let dst_at = src_port_at + 2;
            let dst_port_at = dst_at + address_len;
            let len_at = dst_port_at + 2;
            let payload_len =
                u16::from_be_bytes([frame[consumed + len_at], frame[consumed + len_at + 1]])
                    as usize;
            let total = header + payload_len;
            if at - consumed < total {
                break;
            }
            let source = if kind == 1 {
                SocketAddr::from((
                    std::net::Ipv4Addr::new(
                        frame[consumed + 1],
                        frame[consumed + 2],
                        frame[consumed + 3],
                        frame[consumed + 4],
                    ),
                    u16::from_be_bytes([
                        frame[consumed + src_port_at],
                        frame[consumed + src_port_at + 1],
                    ]),
                ))
            } else {
                let mut ip = [0u8; 16];
                ip.copy_from_slice(&frame[consumed + 1..consumed + 17]);
                SocketAddr::from((
                    std::net::Ipv6Addr::from(ip),
                    u16::from_be_bytes([
                        frame[consumed + src_port_at],
                        frame[consumed + src_port_at + 1],
                    ]),
                ))
            };
            let target = if kind == 1 {
                SocketAddr::from((
                    std::net::Ipv4Addr::new(
                        frame[consumed + dst_at],
                        frame[consumed + dst_at + 1],
                        frame[consumed + dst_at + 2],
                        frame[consumed + dst_at + 3],
                    ),
                    u16::from_be_bytes([
                        frame[consumed + dst_port_at],
                        frame[consumed + dst_port_at + 1],
                    ]),
                ))
            } else {
                let mut ip = [0u8; 16];
                ip.copy_from_slice(&frame[consumed + dst_at..consumed + dst_at + 16]);
                SocketAddr::from((
                    std::net::Ipv6Addr::from(ip),
                    u16::from_be_bytes([
                        frame[consumed + dst_port_at],
                        frame[consumed + dst_port_at + 1],
                    ]),
                ))
            };
            let payload = &frame[consumed + header..consumed + header + payload_len];
            let _ = sys::transparent_udp_send(source, target, payload);
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn a_loopback_resolver_is_kept() {
        assert_eq!(
            resolver_from_conf("search example\nnameserver 127.0.0.53\n"),
            Some(SocketAddr::from(([127, 0, 0, 53], 53)))
        );
        assert_eq!(
            resolver_from_conf("nameserver ::1\nnameserver 192.0.2.1\n"),
            Some(SocketAddr::new("::1".parse().unwrap(), 53))
        );
        assert_eq!(resolver_from_conf("search example\n"), None);
        assert_eq!(
            resolver_from_conf("nameserver not-an-ip\nnameserver 198.51.100.2\n"),
            Some(SocketAddr::from(([198, 51, 100, 2], 53)))
        );
    }

    #[test]
    fn a_chosen_resolv_conf_is_used_and_empty_fails_closed() {
        use std::io::Write;
        let path = std::env::temp_dir().join(format!(
            "procage-resolv-{}-{}.conf",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::File::create(&path)
            .unwrap()
            .write_all(b"nameserver 127.0.0.53\n")
            .unwrap();
        let relay = Relay::new("/run/control.sock").with_resolv_conf(&path);
        assert_eq!(
            dns_upstream(&relay),
            Some(SocketAddr::from(([127, 0, 0, 53], 53)))
        );
        std::fs::write(&path, b"search example\n").unwrap();
        assert_eq!(dns_upstream(&relay), None);
        let _ = std::fs::remove_file(&path);
    }

    fn answer(ip: [u8; 4], ttl: u32) -> dns::Answer {
        dns::Answer {
            ip: IpAddr::from(ip),
            ttl,
        }
    }

    #[test]
    fn a_mapped_name_expires_with_its_ttl() {
        let map = DnsMap::default();
        let now = Instant::now();
        map.insert_at("expired.example", &[answer([192, 0, 2, 1], 5)], now);
        map.insert_at("live.example", &[answer([192, 0, 2, 2], 60)], now);
        assert_eq!(
            map.name_for(IpAddr::from([192, 0, 2, 2])).as_deref(),
            Some("live.example")
        );
        // An answer inserted with a base older than its TTL is already stale:
        // a lookup must remove it, not keep a stale name.
        map.insert_at(
            "expired.example",
            &[answer([192, 0, 2, 1], 5)],
            now - Duration::from_secs(10),
        );
        assert_eq!(map.name_for(IpAddr::from([192, 0, 2, 1])), None);
        assert_eq!(
            map.name_for(IpAddr::from([192, 0, 2, 2])).as_deref(),
            Some("live.example")
        );
    }

    #[test]
    fn a_full_map_fails_closed() {
        let map = DnsMap::default();
        let now = Instant::now();
        for i in 0..DNS_MAP_MAX {
            let ip = Ipv4Addr::from((i as u32) + 1);
            map.insert_at(
                "full.example",
                &[dns::Answer {
                    ip: IpAddr::V4(ip),
                    ttl: 60,
                }],
                now,
            );
        }
        let extra = Ipv4Addr::new(203, 0, 113, 7);
        map.insert_at(
            "extra.example",
            &[dns::Answer {
                ip: IpAddr::V4(extra),
                ttl: 60,
            }],
            now,
        );
        assert_eq!(map.name_for(IpAddr::V4(extra)), None);
    }

    #[test]
    fn a_zero_ttl_answer_is_not_kept() {
        let map = DnsMap::default();
        map.insert("zero.example", &[answer([192, 0, 2, 9], 0)]);
        assert_eq!(map.name_for(IpAddr::from([192, 0, 2, 9])), None);
    }

    #[test]
    fn udp_flows_are_bounded_and_stop_cleans_up() {
        let sink = UdpSocket::bind("127.0.0.1:0").unwrap();
        let destination = sink.local_addr().unwrap();
        let flows: UdpFlows = Arc::new(Mutex::new(HashMap::new()));
        let (helper, _) = std::os::unix::net::UnixStream::pair().unwrap();
        let helper = Arc::new(Mutex::new(helper));
        let stop = Arc::new(AtomicBool::new(false));
        for i in 0..(MAX_UDP_FLOWS + 8) {
            let source = SocketAddr::from(([127, 0, 0, 1], 30_000 + i as u16));
            start_udp_flow(
                &flows,
                (source, destination),
                &[b"x".to_vec()],
                destination,
                &helper,
                &stop,
            );
        }
        assert_eq!(flows.lock().unwrap().len(), MAX_UDP_FLOWS);
        stop.store(true, Ordering::Relaxed);
        for _ in 0..200 {
            if flows.lock().unwrap().is_empty() {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(
            flows.lock().unwrap().is_empty(),
            "a stopped run must close every upstream flow"
        );
    }
}
