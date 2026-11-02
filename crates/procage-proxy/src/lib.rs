//! An egress proxy with a domain allowlist, for sandboxed processes.
//!
//! [`Proxy`] serves HTTP `CONNECT`, plain HTTP in absolute form and SOCKS5
//! (`CONNECT`, no authentication) on listeners it is given. Each request
//! names one host, which [`Host::parse`] turns into one canonical value: that
//! value is checked against the [`Allowlist`] and is what the proxy
//! connects to. An allowed name is resolved once, after the check, and the
//! proxy connects only to an address it checked: an address that is not
//! public (loopback, private, link-local, cloud metadata, …) needs an
//! allowlisted range. After the reply it relays bytes unchanged; it never
//! terminates TLS and sees no content.
//!
//! ```no_run
//! use std::net::TcpListener;
//! use procage_proxy::{Allowlist, Protocol, Proxy};
//!
//! let allow = Allowlist::new(["crates.io", "*.crates.io", "index.crates.io:443"])?;
//! let proxy = Proxy::new(allow);
//! let listener = TcpListener::bind("127.0.0.1:0")?;
//! let run = proxy.serve(vec![(Protocol::Http, listener)], |refusal| {
//!     eprintln!("proxy: {refusal}");
//! })?;
//! // HTTPS_PROXY=http://{run.addrs()[0].1} for the child; dropping `run`
//! // closes the listener and every connection.
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! The allowlist binds host names, not content: an allowed host that serves
//! other sites (shared hosting, domain fronting through a CDN) is reachable
//! with whatever those sites serve.

mod addr;
mod allow;
mod host;
mod http;
mod resolve;
mod socks;

use std::collections::HashMap;
use std::fmt;
use std::io::{self, Write};
use std::net::{IpAddr, Shutdown, SocketAddr, TcpListener, TcpStream};
use std::panic::{RefUnwindSafe, UnwindSafe};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

pub use addr::is_public;
pub use allow::{Allowlist, AllowlistError};
pub use host::{Host, HostError};
pub use resolve::{Resolve, SystemResolver};

/// The protocol a listener speaks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Protocol {
    /// HTTP `CONNECT` and plain HTTP with an absolute URI.
    Http,
    /// SOCKS5 `CONNECT` without authentication.
    Socks5,
}

impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Protocol::Http => "http",
            Protocol::Socks5 => "socks5",
        })
    }
}

/// A request the proxy refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal {
    /// The host as the request named it, escaped (no control bytes).
    pub host: String,
    /// The port it asked for (0 when the request had none).
    pub port: u16,
    /// The listener's protocol.
    pub protocol: Protocol,
    /// Why it was refused.
    pub reason: Reason,
}

/// Why a request was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Reason {
    /// No allowlist entry names the host (and port), or an address is in no
    /// range. A refused name is never resolved.
    NotAllowed,
    /// The name is allowed but resolved only to addresses that are not
    /// public and in no range (the first is given).
    Address(IpAddr),
    /// The name did not resolve.
    Unresolved,
    /// The request was malformed, or its host is no host (the reason).
    Malformed(String),
    /// The run already has as many connections as its limit.
    Busy,
}

impl fmt::Display for Reason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Reason::NotAllowed => f.write_str("not on the allowlist"),
            Reason::Address(ip) => write!(f, "resolves to {ip}, which is not public"),
            Reason::Unresolved => f.write_str("does not resolve"),
            Reason::Malformed(why) => write!(f, "malformed request: {why}"),
            Reason::Busy => f.write_str("too many connections"),
        }
    }
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {}:{} refused: {}",
            self.protocol, self.host, self.port, self.reason
        )
    }
}

/// The bounds of a run.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    /// Concurrent connections; more are closed at once.
    pub connections: usize,
    /// Time for a request's handshake, and for the connect.
    pub timeout: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            connections: 64,
            timeout: Duration::from_secs(10),
        }
    }
}

/// An allowlist with a resolver and limits; [`Proxy::serve`] runs it on
/// listeners. Cheap to clone.
#[derive(Clone)]
pub struct Proxy {
    allow: Arc<Allowlist>,
    resolver: Arc<dyn Resolve>,
    limits: Limits,
}

impl fmt::Debug for Proxy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Proxy")
            .field("allow", &self.allow)
            .field("limits", &self.limits)
            .finish_non_exhaustive()
    }
}

impl Proxy {
    /// A proxy for `allow`, with the system resolver and default limits.
    pub fn new(allow: Allowlist) -> Proxy {
        Proxy {
            allow: Arc::new(allow),
            resolver: Arc::new(SystemResolver),
            limits: Limits::default(),
        }
    }

    /// The same proxy with `resolver`.
    pub fn with_resolver(mut self, resolver: impl Resolve) -> Proxy {
        self.resolver = Arc::new(resolver);
        self
    }

    /// The same proxy with `limits`.
    pub fn with_limits(mut self, limits: Limits) -> Proxy {
        self.limits = limits;
        self
    }

    /// The allowlist.
    pub fn allowlist(&self) -> &Allowlist {
        &self.allow
    }

    /// Serves `listeners` until the returned [`Run`] is dropped, calling
    /// `on_refusal` for each refused request.
    pub fn serve(
        &self,
        listeners: Vec<(Protocol, TcpListener)>,
        on_refusal: impl Fn(Refusal) + Send + Sync + RefUnwindSafe + UnwindSafe + 'static,
    ) -> io::Result<Run> {
        let shared = Arc::new(Shared {
            proxy: self.clone(),
            on_refusal: Box::new(on_refusal),
            stop: AtomicBool::new(false),
            active: AtomicUsize::new(0),
            next: AtomicU64::new(0),
            conns: Mutex::new(HashMap::new()),
        });
        let mut addrs = Vec::new();
        for (protocol, listener) in listeners {
            listener.set_nonblocking(true)?;
            addrs.push((protocol, listener.local_addr()?));
            let shared = shared.clone();
            std::thread::Builder::new()
                .name(format!("procage-proxy-{protocol}"))
                .spawn(move || accept(&shared, &listener, protocol))?;
        }
        Ok(Run { shared, addrs })
    }

    /// Decides `host:port` and connects: the name check before any query,
    /// one resolution, and only to an address that was checked.
    pub(crate) fn open(&self, host: &Host, port: u16) -> Result<TcpStream, Reason> {
        let target = match host {
            Host::Ip(ip) => {
                if !self.allow.in_range(*ip) {
                    return Err(Reason::NotAllowed);
                }
                *ip
            }
            Host::Name(name) => {
                if !self.allow.allows_name(name, port) {
                    return Err(Reason::NotAllowed);
                }
                let addrs = self
                    .resolver
                    .resolve(name)
                    .map_err(|_| Reason::Unresolved)?;
                let first = *addrs.first().ok_or(Reason::Unresolved)?;
                addrs
                    .into_iter()
                    .find(|&ip| self.allow.address_allowed(ip))
                    .ok_or(Reason::Address(first))?
            }
        };
        TcpStream::connect_timeout(&SocketAddr::new(target, port), self.limits.timeout)
            .map_err(|_| Reason::Unresolved)
    }
}

/// A proxy serving one run's listeners. Dropping it closes the listeners
/// and shuts down every connection of the run.
#[derive(Debug)]
pub struct Run {
    shared: Arc<Shared>,
    addrs: Vec<(Protocol, SocketAddr)>,
}

impl Run {
    /// The listeners' addresses.
    pub fn addrs(&self) -> &[(Protocol, SocketAddr)] {
        &self.addrs
    }

    /// The address of the first listener for `protocol`.
    pub fn addr(&self, protocol: Protocol) -> Option<SocketAddr> {
        self.addrs
            .iter()
            .find(|(p, _)| *p == protocol)
            .map(|(_, a)| *a)
    }

    /// Connections open right now.
    pub fn connections(&self) -> usize {
        self.shared.active.load(Ordering::Acquire)
    }
}

impl Drop for Run {
    fn drop(&mut self) {
        let mut conns = self.shared.lock();
        self.shared.stop.store(true, Ordering::Release);
        for stream in conns.values().flatten() {
            let _ = stream.shutdown(Shutdown::Both);
        }
        conns.clear();
    }
}

struct Shared {
    proxy: Proxy,
    on_refusal: Box<dyn Fn(Refusal) + Send + Sync + RefUnwindSafe + UnwindSafe>,
    stop: AtomicBool,
    active: AtomicUsize,
    next: AtomicU64,
    /// Clones of each connection's sockets, to shut them down at the end.
    conns: Mutex<HashMap<u64, Vec<TcpStream>>>,
}

impl fmt::Debug for Shared {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Shared")
            .field("active", &self.active)
            .finish_non_exhaustive()
    }
}

impl Shared {
    fn lock(&self) -> MutexGuard<'_, HashMap<u64, Vec<TcpStream>>> {
        self.conns.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Keeps a clone of `stream` for the end of the run; `false` (and the
    /// stream shut down) when the run already ended.
    fn register(&self, id: u64, stream: &TcpStream) -> bool {
        let mut conns = self.lock();
        if self.stop.load(Ordering::Acquire) {
            let _ = stream.shutdown(Shutdown::Both);
            return false;
        }
        if let Ok(clone) = stream.try_clone() {
            conns.entry(id).or_default().push(clone);
        }
        true
    }

    pub(crate) fn refuse(&self, refusal: Refusal) {
        (self.on_refusal)(refusal);
    }
}

fn accept(shared: &Arc<Shared>, listener: &TcpListener, protocol: Protocol) {
    while !shared.stop.load(Ordering::Acquire) {
        let stream = match listener.accept() {
            Ok((stream, _)) => stream,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(10));
                continue;
            }
            Err(_) => {
                std::thread::sleep(Duration::from_millis(10));
                continue;
            }
        };
        let limit = shared.proxy.limits.connections;
        if shared.active.fetch_add(1, Ordering::AcqRel) >= limit {
            shared.active.fetch_sub(1, Ordering::AcqRel);
            shared.refuse(Refusal {
                host: String::new(),
                port: 0,
                protocol,
                reason: Reason::Busy,
            });
            continue;
        }
        let shared = shared.clone();
        let spawned = std::thread::Builder::new()
            .name("procage-proxy-conn".into())
            .spawn({
                let shared = shared.clone();
                move || {
                    let id = shared.next.fetch_add(1, Ordering::Relaxed);
                    connection(&shared, id, stream, protocol);
                    shared.lock().remove(&id);
                    shared.active.fetch_sub(1, Ordering::AcqRel);
                }
            });
        if spawned.is_err() {
            shared.active.fetch_sub(1, Ordering::AcqRel);
        }
    }
}

fn connection(shared: &Shared, id: u64, mut client: TcpStream, protocol: Protocol) {
    if client.set_nonblocking(false).is_err() || !shared.register(id, &client) {
        return;
    }
    let timeout = Some(shared.proxy.limits.timeout);
    if client.set_read_timeout(timeout).is_err() || client.set_write_timeout(timeout).is_err() {
        return;
    }
    let opened = match protocol {
        Protocol::Http => http::handshake(shared, &mut client),
        Protocol::Socks5 => socks::handshake(shared, &mut client),
    };
    let Some((mut upstream, pending)) = opened else {
        return;
    };
    if !shared.register(id, &upstream)
        || client.set_read_timeout(None).is_err()
        || client.set_write_timeout(None).is_err()
        || upstream.write_all(&pending).is_err()
    {
        return;
    }
    relay(client, upstream);
}

/// Copies both ways, unchanged, until both directions end.
fn relay(client: TcpStream, upstream: TcpStream) {
    let (Ok(mut client_r), Ok(mut upstream_w)) = (client.try_clone(), upstream.try_clone()) else {
        return;
    };
    let up = std::thread::spawn(move || {
        let _ = io::copy(&mut client_r, &mut upstream_w);
        let _ = upstream_w.shutdown(Shutdown::Write);
    });
    let (mut upstream_r, mut client_w) = (upstream, client);
    let _ = io::copy(&mut upstream_r, &mut client_w);
    let _ = client_w.shutdown(Shutdown::Write);
    let _ = up.join();
}

/// `bytes` as a host for a refusal: escaped and at most 255 characters.
pub(crate) fn shown(bytes: &[u8]) -> String {
    let text: String = String::from_utf8_lossy(bytes).escape_debug().collect();
    text.chars().take(255).collect()
}
