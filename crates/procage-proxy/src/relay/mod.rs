//! The transparent relay's policy side: the control channel, the wire
//! parsers that name a destination, and local DNS answers.
//!
//! This module holds no sockets of its own beyond the control channel: the
//! Linux backend owns the TPROXY listeners and asks here what a flow's
//! resource is and whether the control socket admits it. Keeping the parsers
//! free of descriptor handling makes every bound testable without privileges.

pub mod control;
pub mod dns;
pub mod inspect;

use std::path::PathBuf;
use std::time::Duration;

pub use control::{Control, ControlError, Decision, Proto, Reason, RunId};
pub use inspect::{Inspect, QuicInspector, Sniff};

/// How a relayed flow is named to the control socket.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Resource {
    /// A canonical host name from DNS, TLS SNI, HTTP `Host` or QUIC SNI.
    Domain(String),
    /// A destination address when no protocol named a host.
    Ip(std::net::IpAddr),
}

impl Resource {
    /// The canonical text put in a `DECIDE_REQ`.
    pub fn as_str(&self) -> String {
        match self {
            Resource::Domain(name) => name.clone(),
            Resource::Ip(ip) => ip.to_string(),
        }
    }

    /// The resource for a parsed [`crate::Host`].
    pub fn from_host(host: &crate::Host) -> Resource {
        match host {
            crate::Host::Name(name) => Resource::Domain(name.clone()),
            crate::Host::Ip(ip) => Resource::Ip(*ip),
        }
    }
}

/// A relay of one run: the control socket the harness serves and the
/// deadline for one decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Relay {
    pub(crate) control: PathBuf,
    pub(crate) timeout: Duration,
    pub(crate) dns_upstream: Option<std::net::SocketAddr>,
    pub(crate) resolv_conf: Option<PathBuf>,
    pub(crate) run_id: Option<u64>,
}

impl Relay {
    /// A relay whose every flow is decided by the harness listening at
    /// `control` (an `AF_UNIX` `SOCK_STREAM` server).
    pub fn new(control: impl Into<PathBuf>) -> Relay {
        Relay {
            control: control.into(),
            timeout: Duration::from_secs(65),
            dns_upstream: None,
            resolv_conf: None,
            run_id: None,
        }
    }

    /// This relay with `timeout` for one decision (default 65 s, one minute
    /// of permission prompt plus a grace). A decision that takes longer is a
    /// refusal; the control channel is then unusable and every later flow is
    /// refused.
    pub fn with_timeout(mut self, timeout: Duration) -> Relay {
        self.timeout = timeout;
        self
    }

    /// This relay with the run id the harness's server was created with
    /// (`RelayControlServer.runId`). The server rejects any other id, so this
    /// is required for a harness that fixes its id; without it procage sends
    /// a fresh random id.
    pub fn with_run_id(mut self, run_id: u64) -> Relay {
        self.run_id = Some(run_id);
        self
    }

    /// This relay with `upstream` as the server for an allowed DNS query
    /// that arrived on a loopback resolver stub (where the original server
    /// is not visible). Without it procage reads `/etc/resolv.conf` and the
    /// systemd-resolved paths, and uses the first nameserver **including** a
    /// loopback stub: the parent namespace is outside the child's relay, so
    /// `127.0.0.53` there is the host's resolver, not a recursion.
    pub fn with_dns_upstream(mut self, upstream: std::net::SocketAddr) -> Relay {
        self.dns_upstream = Some(upstream);
        self
    }

    /// This relay with `path` as the only resolver configuration (instead of
    /// `/etc/resolv.conf` and the systemd-resolved paths). An empty or
    /// unreadable file means no upstream, and an allowed query is answered
    /// `SERVFAIL`; it never falls back silently. For a container or a test
    /// whose resolver lives elsewhere.
    pub fn with_resolv_conf(mut self, path: impl Into<PathBuf>) -> Relay {
        self.resolv_conf = Some(path.into());
        self
    }

    /// The control socket path.
    pub fn control(&self) -> &std::path::Path {
        &self.control
    }

    /// The decision deadline.
    pub fn timeout(&self) -> Duration {
        self.timeout
    }

    /// The fixed run id, if one was given.
    pub fn run_id(&self) -> Option<u64> {
        self.run_id
    }

    /// The configured DNS upstream, if any.
    pub fn dns_upstream(&self) -> Option<std::net::SocketAddr> {
        self.dns_upstream
    }

    /// The resolver configuration file, if one was chosen.
    pub fn resolv_conf(&self) -> Option<&std::path::Path> {
        self.resolv_conf.as_deref()
    }
}

/// Well-known DoH endpoints, matched against a canonical host name. Their
/// TLS SNI or HTTP `Host` is denied before the control socket is asked:
/// encrypted DNS would hide every later QNAME from the relay.
pub const DOH_HOSTS: &[&str] = &[
    "cloudflare-dns.com",
    "mozilla.cloudflare-dns.com",
    "dns.google",
    "dns.google.com",
    "doh.opendns.com",
    "dns.quad9.net",
    "doh.pub",
    "dns.adguard-dns.com",
    "dns.nextdns.io",
    "doh.mullvad.net",
];

/// Whether `host` (canonical) is a known DoH endpoint or a subdomain of one.
pub fn is_known_doh(host: &str) -> bool {
    let host = host.trim_end_matches('.');
    DOH_HOSTS.iter().any(|known| {
        host.eq_ignore_ascii_case(known)
            || (host.len() > known.len()
                && host.as_bytes()[host.len() - known.len() - 1] == b'.'
                && host[host.len() - known.len()..].eq_ignore_ascii_case(known))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_doh_matches_exact_and_subdomains_only() {
        assert!(is_known_doh("dns.google"));
        assert!(is_known_doh("DNS.GOOGLE."));
        assert!(is_known_doh("a.dns.google"));
        assert!(!is_known_doh("notdns.google"));
        assert!(!is_known_doh("google.com"));
        assert!(!is_known_doh("dns.google.example"));
    }

    #[test]
    fn relay_defaults_are_bounded() {
        let relay = Relay::new("/run/relay.sock");
        assert_eq!(relay.timeout(), Duration::from_secs(65));
        assert_eq!(relay.control(), std::path::Path::new("/run/relay.sock"));
        assert_eq!(relay.run_id(), None);
        assert_eq!(Relay::new("/x").with_run_id(7).run_id(), Some(7));
    }
}
