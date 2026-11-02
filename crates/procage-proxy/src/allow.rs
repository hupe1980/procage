//! The allowlist: exact hosts, wildcard suffixes, optional ports and
//! address ranges. There is no allow-all.

use std::fmt;
use std::net::IpAddr;

use crate::host::{Host, HostError, canonical};

/// Which hosts a proxy connects to. Built only from at least one entry.
///
/// Entries: `crates.io` (that host), `*.npmjs.org` (every subdomain of a
/// suffix of two or more labels, not the suffix itself), either with
/// `:port`, and address ranges `192.0.2.0/24`, `[2001:db8::]/32` or one
/// address. A name is decided by the name entries before it is resolved;
/// an address, given or resolved, that is not public needs a range.
#[derive(Debug, Clone)]
pub struct Allowlist {
    names: Vec<NameEntry>,
    ranges: Vec<Range>,
}

#[derive(Debug, Clone)]
struct NameEntry {
    /// The host, or for a wildcard the suffix with its leading dot.
    name: String,
    wildcard: bool,
    port: Option<u16>,
}

#[derive(Debug, Clone, Copy)]
struct Range {
    net: IpAddr,
    prefix: u8,
}

impl Range {
    fn contains(&self, ip: IpAddr) -> bool {
        let bits = |a: IpAddr| -> (u128, u8) {
            match a {
                IpAddr::V4(v) => (u128::from(u32::from(v)) << 96, 32),
                IpAddr::V6(v) => (u128::from(v), 128),
            }
        };
        let ((net, width), (addr, other)) = (bits(self.net), bits(canonical(ip)));
        if width != other {
            return false;
        }
        let prefix = u32::from(self.prefix);
        let mask = if prefix == 0 {
            0
        } else {
            u128::MAX << (128 - prefix)
        };
        net & mask == addr & mask
    }
}

/// Why an allowlist was not built.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum AllowlistError {
    /// No entry: a proxy without one would allow nothing or, worse,
    /// everything.
    Empty,
    /// `*` or a wildcard over a single label (`*.com`).
    TooWide(String),
    /// An entry that is no host, wildcard or range.
    Invalid {
        /// The entry, escaped.
        entry: String,
        /// What is wrong with it.
        reason: String,
    },
}

impl fmt::Display for AllowlistError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AllowlistError::Empty => f.write_str("the allowlist is empty"),
            AllowlistError::TooWide(e) => write!(f, "allowlist entry {e} would allow too much"),
            AllowlistError::Invalid { entry, reason } => {
                write!(f, "invalid allowlist entry {entry}: {reason}")
            }
        }
    }
}

impl std::error::Error for AllowlistError {}

impl Allowlist {
    /// Builds an allowlist from its entries; fails on none, on `*` and on a
    /// wildcard over a single label.
    pub fn new<I, S>(entries: I) -> Result<Allowlist, AllowlistError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut list = Allowlist {
            names: Vec::new(),
            ranges: Vec::new(),
        };
        for entry in entries {
            list.add(entry.as_ref())?;
        }
        if list.names.is_empty() && list.ranges.is_empty() {
            return Err(AllowlistError::Empty);
        }
        Ok(list)
    }

    fn add(&mut self, entry: &str) -> Result<(), AllowlistError> {
        let invalid = |reason: String| AllowlistError::Invalid {
            entry: entry.escape_debug().to_string(),
            reason,
        };
        if let Some((net, prefix)) = entry.split_once('/') {
            let ip = match Host::parse(net.as_bytes()).map_err(|e| invalid(e.to_string()))? {
                Host::Ip(ip) => ip,
                Host::Name(_) => return Err(invalid("a range needs an address".into())),
            };
            let max = if ip.is_ipv4() { 32 } else { 128 };
            let prefix: u8 = prefix
                .parse()
                .ok()
                .filter(|&p| p <= max)
                .ok_or_else(|| invalid("invalid prefix length".into()))?;
            if prefix == 0 {
                return Err(AllowlistError::TooWide(entry.escape_debug().to_string()));
            }
            self.ranges.push(Range { net: ip, prefix });
            return Ok(());
        }
        let (host, port) = split_port(entry).map_err(invalid)?;
        let (wildcard, host) = match host.strip_prefix("*.") {
            Some(rest) => (true, rest),
            None if host == "*" => return Err(AllowlistError::TooWide("*".into())),
            None => (false, host),
        };
        match Host::parse(host.as_bytes()).map_err(|e: HostError| invalid(e.to_string()))? {
            Host::Ip(ip) if !wildcard && port.is_none() => {
                let prefix = if ip.is_ipv4() { 32 } else { 128 };
                self.ranges.push(Range { net: ip, prefix });
            }
            Host::Ip(_) => return Err(invalid("an address takes no wildcard or port".into())),
            Host::Name(name) => {
                if wildcard && !name.contains('.') {
                    return Err(AllowlistError::TooWide(entry.escape_debug().to_string()));
                }
                let name = if wildcard { format!(".{name}") } else { name };
                self.names.push(NameEntry {
                    name,
                    wildcard,
                    port,
                });
            }
        }
        Ok(())
    }

    /// Whether a name entry allows `name` at `port`.
    pub fn allows_name(&self, name: &str, port: u16) -> bool {
        self.names.iter().any(|e| {
            let matched = if e.wildcard {
                name.ends_with(&e.name)
            } else {
                name == e.name
            };
            matched && e.port.is_none_or(|p| p == port)
        })
    }

    /// Whether a range contains `ip`.
    pub fn in_range(&self, ip: IpAddr) -> bool {
        self.ranges.iter().any(|r| r.contains(ip))
    }

    /// Whether the proxy may connect to `ip`, given or resolved: a public
    /// address for a name, or one in a range.
    pub fn address_allowed(&self, ip: IpAddr) -> bool {
        crate::addr::is_public(canonical(ip)) || self.in_range(ip)
    }
}

/// `host[:port]`, with an IPv6 host in brackets.
pub(crate) fn split_port(authority: &str) -> Result<(&str, Option<u16>), String> {
    let port_of = |p: &str| -> Result<u16, String> {
        if p.is_empty() || p.len() > 5 || !p.bytes().all(|b| b.is_ascii_digit()) {
            return Err("invalid port".into());
        }
        p.parse::<u16>()
            .ok()
            .filter(|&p| p != 0)
            .ok_or_else(|| "invalid port".into())
    };
    if authority.starts_with('[') {
        let end = authority.find(']').ok_or("unclosed bracket")?;
        let (host, rest) = authority.split_at(end + 1);
        return match rest.strip_prefix(':') {
            Some(p) => Ok((host, Some(port_of(p)?))),
            None if rest.is_empty() => Ok((host, None)),
            None => Err("text after the address".into()),
        };
    }
    match authority.rsplit_once(':') {
        Some((host, p)) => Ok((host, Some(port_of(p)?))),
        None => Ok((authority, None)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn construction_fails_closed() {
        assert_eq!(
            Allowlist::new(Vec::<String>::new()).unwrap_err(),
            AllowlistError::Empty
        );
        for e in ["*", "*.com", "*.com:443", "0.0.0.0/0", "[::]/0"] {
            assert!(
                matches!(Allowlist::new([e]), Err(AllowlistError::TooWide(_))),
                "{e}"
            );
        }
        for e in [
            "",
            "a b",
            "x.com:0",
            "x.com:99999",
            "*.1.2.3.4",
            "1.2.3.4:80",
            "host/8",
        ] {
            assert!(Allowlist::new([e]).is_err(), "{e}");
        }
    }

    #[test]
    fn names_wildcards_and_ports() {
        let a = Allowlist::new(["crates.io", "*.npmjs.org", "api.example.com:443"]).unwrap();
        assert!(a.allows_name("crates.io", 443));
        assert!(!a.allows_name("static.crates.io", 443));
        assert!(a.allows_name("registry.npmjs.org", 443));
        assert!(!a.allows_name("npmjs.org", 443));
        assert!(!a.allows_name("evilnpmjs.org", 443));
        assert!(a.allows_name("api.example.com", 443));
        assert!(!a.allows_name("api.example.com", 80));
    }

    #[test]
    fn ranges_and_addresses() {
        let a = Allowlist::new(["192.0.2.0/24", "[2001:db8::]/32", "10.1.2.3"]).unwrap();
        assert!(a.in_range("192.0.2.10".parse().unwrap()));
        assert!(a.in_range("::ffff:192.0.2.10".parse().unwrap()));
        assert!(!a.in_range("192.0.3.1".parse().unwrap()));
        assert!(a.in_range("2001:db8::1".parse().unwrap()));
        assert!(a.in_range("10.1.2.3".parse().unwrap()));
        assert!(!a.in_range("10.1.2.4".parse().unwrap()));
        assert!(a.address_allowed("93.184.215.14".parse().unwrap()));
        assert!(!a.address_allowed("127.0.0.1".parse().unwrap()));
    }
}
