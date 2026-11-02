//! SOCKS5 (RFC 1928): no authentication, `CONNECT` only, IPv4, domain and
//! IPv6 addresses.

use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, TcpStream};

use crate::host::canonical;
use crate::{Host, Protocol, Reason, Refusal, Shared, shown};

const SUCCEEDED: u8 = 0;
const NOT_ALLOWED: u8 = 2;
const HOST_UNREACHABLE: u8 = 4;
const COMMAND_NOT_SUPPORTED: u8 = 7;
const ADDRESS_NOT_SUPPORTED: u8 = 8;

/// The greeting, the request, the decision and the connect; the upstream
/// connection on success (nothing to send first).
pub(crate) fn handshake(shared: &Shared, client: &mut TcpStream) -> Option<(TcpStream, Vec<u8>)> {
    let [version, methods] = read::<2>(client)?;
    let mut offered = vec![0u8; usize::from(methods)];
    client.read_exact(&mut offered).ok()?;
    if version != 5 || !offered.contains(&0) {
        let _ = client.write_all(&[5, 0xff]);
        return None;
    }
    client.write_all(&[5, 0]).ok()?;
    let [version, command, _, kind] = read::<4>(client)?;
    if version != 5 {
        return None;
    }
    let (raw, host) = match kind {
        1 => {
            let a = read::<4>(client)?;
            (a.to_vec(), Ok(Host::Ip(IpAddr::V4(Ipv4Addr::from(a)))))
        }
        3 => {
            let [len] = read::<1>(client)?;
            let mut name = vec![0u8; usize::from(len)];
            client.read_exact(&mut name).ok()?;
            let host = Host::parse(&name).map_err(|e| e.to_string());
            (name, host)
        }
        4 => {
            let a = read::<16>(client)?;
            let ip = canonical(IpAddr::V6(Ipv6Addr::from(a)));
            (ip.to_string().into_bytes(), Ok(Host::Ip(ip)))
        }
        _ => {
            reply(client, ADDRESS_NOT_SUPPORTED);
            return None;
        }
    };
    let port = u16::from_be_bytes(read::<2>(client)?);
    let refuse = |client: &mut TcpStream, raw: &[u8], code: u8, reason: Reason| {
        reply(client, code);
        shared.refuse(Refusal {
            host: shown(raw),
            port,
            protocol: Protocol::Socks5,
            reason,
        });
    };
    if command != 1 {
        refuse(
            client,
            &raw,
            COMMAND_NOT_SUPPORTED,
            Reason::Malformed("only CONNECT".into()),
        );
        return None;
    }
    let host = match host {
        Ok(h) => h,
        Err(why) => {
            refuse(client, &raw, NOT_ALLOWED, Reason::Malformed(why));
            return None;
        }
    };
    match shared.proxy.open(&host, port) {
        Ok(upstream) => {
            reply(client, SUCCEEDED);
            Some((upstream, Vec::new()))
        }
        Err(reason) => {
            let code = match reason {
                Reason::Unresolved => HOST_UNREACHABLE,
                _ => NOT_ALLOWED,
            };
            refuse(client, host.to_string().as_bytes(), code, reason);
            None
        }
    }
}

fn read<const N: usize>(client: &mut TcpStream) -> Option<[u8; N]> {
    let mut buf = [0u8; N];
    client.read_exact(&mut buf).ok()?;
    Some(buf)
}

/// A reply with an unspecified bound address.
fn reply(client: &mut TcpStream, code: u8) {
    let _ = client.write_all(&[5, code, 0, 1, 0, 0, 0, 0, 0, 0]);
}
