//! The canonical host of a request: one parser whose result is both checked
//! against the allowlist and connected to.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// A request's host, in its one canonical form.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Host {
    /// A domain name: lower case, without a trailing dot, ASCII labels of
    /// letters, digits, `-` and `_`.
    Name(String),
    /// An address, from any notation (IPv4-mapped IPv6 becomes IPv4).
    Ip(IpAddr),
}

impl fmt::Display for Host {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Host::Name(n) => f.write_str(n),
            Host::Ip(IpAddr::V6(a)) => write!(f, "[{a}]"),
            Host::Ip(a) => write!(f, "{a}"),
        }
    }
}

/// Why a host was refused before any decision.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum HostError {
    /// Nothing, or only a dot.
    Empty,
    /// More than 253 bytes, or a label of more than 63.
    TooLong,
    /// A byte that no host name has (NUL, a control byte, `%`, `@`, `/`,
    /// a space, …), escaped.
    Byte(String),
    /// A byte outside ASCII: hosts are named by their A-labels (punycode).
    NonAscii,
    /// An empty label, or one that starts or ends with `-`.
    Label,
    /// Looks like an address but is none (`1.2.3.999`, `0x`).
    Number,
}

impl fmt::Display for HostError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HostError::Empty => f.write_str("empty host"),
            HostError::TooLong => f.write_str("host name too long"),
            HostError::Byte(b) => write!(f, "invalid byte {b} in host"),
            HostError::NonAscii => f.write_str("non-ASCII host (use its A-labels)"),
            HostError::Label => f.write_str("invalid label in host"),
            HostError::Number => f.write_str("numeric host that is no address"),
        }
    }
}

impl std::error::Error for HostError {}

impl Host {
    /// Parses the host a request names (no port, no brackets except around
    /// an IPv6 address).
    pub fn parse(raw: &[u8]) -> Result<Host, HostError> {
        if let Some(inner) = raw.strip_prefix(b"[").and_then(|r| r.strip_suffix(b"]")) {
            let text = std::str::from_utf8(inner).map_err(|_| HostError::NonAscii)?;
            let addr: Ipv6Addr = text.parse().map_err(|_| HostError::Number)?;
            return Ok(Host::Ip(canonical(IpAddr::V6(addr))));
        }
        if let Some(&b) = raw
            .iter()
            .find(|&&b| !(b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_')))
        {
            return Err(if b.is_ascii() {
                HostError::Byte(char::from(b).escape_debug().to_string())
            } else {
                HostError::NonAscii
            });
        }
        // Only ASCII is left.
        let mut name = String::from_utf8_lossy(raw).to_ascii_lowercase();
        if name.ends_with('.') {
            name.pop();
        }
        if name.is_empty() {
            return Err(HostError::Empty);
        }
        if name.len() > 253 {
            return Err(HostError::TooLong);
        }
        let last = name.rsplit('.').next().unwrap_or("");
        if last.starts_with(|c: char| c.is_ascii_digit()) {
            return ipv4(&name)
                .map(|a| Host::Ip(IpAddr::V4(a)))
                .ok_or(HostError::Number);
        }
        for label in name.split('.') {
            if label.is_empty() || label.starts_with('-') || label.ends_with('-') {
                return Err(HostError::Label);
            }
            if label.len() > 63 {
                return Err(HostError::TooLong);
            }
        }
        Ok(Host::Name(name))
    }
}

/// IPv4-mapped IPv6 as IPv4; everything else as it is.
pub(crate) fn canonical(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(a) => a.to_ipv4_mapped().map_or(IpAddr::V6(a), IpAddr::V4),
        v4 => v4,
    }
}

/// Every notation `inet_aton` accepts: one to four parts, each decimal,
/// `0x` hexadecimal or leading-zero octal; the last part fills the
/// remaining bytes.
fn ipv4(text: &str) -> Option<Ipv4Addr> {
    let parts: Vec<u32> = text.split('.').map(part).collect::<Option<_>>()?;
    if parts.is_empty() || parts.len() > 4 {
        return None;
    }
    let (head, last) = parts.split_at(parts.len() - 1);
    if head.iter().any(|&p| p > 0xff) {
        return None;
    }
    let rest_bits = 8 * (4 - head.len() as u32);
    if rest_bits < 32 && last[0] >> rest_bits != 0 {
        return None;
    }
    let mut value: u32 = 0;
    for (i, &p) in head.iter().enumerate() {
        value |= p << (24 - 8 * i as u32);
    }
    Some(Ipv4Addr::from(value | last[0]))
}

fn part(p: &str) -> Option<u32> {
    if let Some(hex) = p.strip_prefix("0x") {
        if hex.is_empty() {
            return None;
        }
        return u32::from_str_radix(hex, 16).ok();
    }
    if p.len() > 1 && p.starts_with('0') {
        return u32::from_str_radix(&p[1..], 8).ok();
    }
    if p.is_empty() || !p.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    p.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> Host {
        Host::Ip(s.parse().unwrap())
    }

    #[test]
    fn names_have_one_form() {
        let want = Host::Name("allowed.com".into());
        for s in ["allowed.com", "ALLOWED.COM.", "Allowed.Com"] {
            assert_eq!(Host::parse(s.as_bytes()), Ok(want.clone()), "{s}");
        }
    }

    #[test]
    fn every_ipv4_notation_is_one_address() {
        for s in [
            "127.0.0.1",
            "2130706433",
            "0x7f000001",
            "017700000001",
            "0x7f.1",
            "127.1",
            "127.0.1",
            "0177.0.0.01",
            "[::ffff:127.0.0.1]",
            "127.0.0.1.",
        ] {
            assert_eq!(Host::parse(s.as_bytes()), Ok(ip("127.0.0.1")), "{s}");
        }
        assert_eq!(Host::parse(b"[2001:db8::1]"), Ok(ip("2001:db8::1")));
    }

    #[test]
    fn what_no_host_is_is_refused() {
        for s in [
            &b"allowed.com\0.evil.com"[..],
            b"allowed.com%2e",
            b"user@allowed.com",
            b"allowed.com/x",
            b"allowed .com",
            b"allowed..com",
            b"-allowed.com",
            b"",
            b".",
            b"1.2.3.999",
            b"1.2.3.4.5",
            b"0x",
            b"256.1",
            b"[fe80::1%25eth0]",
            "bücher.de".as_bytes(),
            b"allowed.com\r\n",
        ] {
            assert!(
                Host::parse(s).is_err(),
                "{}",
                String::from_utf8_lossy(s).escape_debug()
            );
        }
        assert!(Host::parse("a.".repeat(128).as_bytes()).is_err());
        assert!(Host::parse(format!("{}.com", "a".repeat(64)).as_bytes()).is_err());
    }
}
