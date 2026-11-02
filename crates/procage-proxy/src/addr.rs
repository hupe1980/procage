//! Which resolved addresses are public: everything else needs an
//! allowlisted range.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Whether `ip` is a public unicast address. Loopback, private, shared,
/// link-local (cloud metadata included), unspecified, multicast,
/// broadcast, documentation and benchmarking addresses are not, nor the
/// IPv4 address inside a mapped or translated IPv6 address that is not.
pub fn is_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(a) => public_v4(a),
        IpAddr::V6(a) => public_v6(a),
    }
}

fn public_v4(a: Ipv4Addr) -> bool {
    let [b0, b1, b2, _] = a.octets();
    !(a.is_unspecified()
        || a.is_loopback()
        || a.is_private()
        || a.is_link_local()
        || a.is_multicast()
        || a.is_broadcast()
        || a.is_documentation()
        || b0 == 0
        // Shared address space (carrier-grade NAT).
        || (b0 == 100 && (b1 & 0xc0) == 64)
        // IETF protocol assignments.
        || (b0 == 192 && b1 == 0 && b2 == 0)
        // Benchmarking.
        || (b0 == 198 && (b1 & 0xfe) == 18)
        // Reserved.
        || b0 >= 240)
}

fn public_v6(a: Ipv6Addr) -> bool {
    if let Some(v4) = a.to_ipv4_mapped() {
        return public_v4(v4);
    }
    let s = a.segments();
    // NAT64 (64:ff9b::/96): the IPv4 address it translates to.
    if s[..6] == [0x64, 0xff9b, 0, 0, 0, 0] {
        return public_v4(Ipv4Addr::new(
            (s[6] >> 8) as u8,
            s[6] as u8,
            (s[7] >> 8) as u8,
            s[7] as u8,
        ));
    }
    !(a.is_unspecified()
        || a.is_loopback()
        || a.is_multicast()
        // Unique local (fc00::/7), with the AWS metadata address fd00:ec2::254.
        || (s[0] & 0xfe00) == 0xfc00
        // Link-local.
        || (s[0] & 0xffc0) == 0xfe80
        // Documentation.
        || (s[0] == 0x2001 && s[1] == 0x0db8)
        // IPv4-compatible (deprecated) and other ::/96 forms.
        || s[..6] == [0; 6])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_and_metadata_addresses_are_not_public() {
        for s in [
            "127.0.0.1",
            "10.0.0.1",
            "172.16.0.1",
            "192.168.1.1",
            "169.254.169.254",
            "100.64.0.1",
            "0.0.0.0",
            "0.1.2.3",
            "224.0.0.1",
            "255.255.255.255",
            "192.0.2.10",
            "198.18.0.1",
            "::1",
            "::",
            "::ffff:10.0.0.1",
            "::ffff:127.0.0.1",
            "64:ff9b::a00:1",
            "64:ff9b::7f00:1",
            "fd00:ec2::254",
            "fe80::1",
            "ff02::1",
            "2001:db8::1",
            "::127.0.0.1",
        ] {
            assert!(!is_public(s.parse().unwrap()), "{s}");
        }
        for s in [
            "93.184.215.14",
            "2606:4700::1111",
            "::ffff:8.8.8.8",
            "64:ff9b::808:808",
        ] {
            assert!(is_public(s.parse().unwrap()), "{s}");
        }
    }
}
