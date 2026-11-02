//! HTTP: `CONNECT host:port`, and plain requests in absolute form.

use std::io::{Read, Write};
use std::net::TcpStream;

use crate::allow::split_port;
use crate::{Host, Protocol, Reason, Refusal, Shared, shown};

/// The longest request head read.
const MAX_HEAD: usize = 16 * 1024;

/// Reads the request head, decides it and connects. Returns the upstream
/// connection and the bytes to send it first; on refusal the client got the
/// answer and `on_refusal` was called.
pub(crate) fn handshake(shared: &Shared, client: &mut TcpStream) -> Option<(TcpStream, Vec<u8>)> {
    let mut buf = Vec::with_capacity(1024);
    let head_len = loop {
        if let Some(end) = find(&buf, b"\r\n\r\n") {
            break end + 4;
        }
        if buf.len() > MAX_HEAD {
            answer(client, 431, "request head too large");
            return None;
        }
        let mut chunk = [0u8; 4096];
        match client.read(&mut chunk) {
            Ok(0) | Err(_) => return None,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
        }
    };
    let request = match parse(&buf[..head_len]) {
        Ok(r) => r,
        Err((host, why)) => {
            refuse(shared, client, &host, 0, Reason::Malformed(why));
            return None;
        }
    };
    match shared.proxy.open(&request.host, request.port) {
        Ok(upstream) => {
            if request.connect {
                if client
                    .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                    .is_err()
                {
                    return None;
                }
                Some((upstream, buf[head_len..].to_vec()))
            } else {
                // Forwarded unchanged, in absolute form.
                Some((upstream, buf))
            }
        }
        Err(reason) => {
            refuse(
                shared,
                client,
                request.host.to_string().as_bytes(),
                request.port,
                reason,
            );
            None
        }
    }
}

struct Request {
    connect: bool,
    host: Host,
    port: u16,
}

/// The request line and, for absolute form, the `Host` header; on error the
/// host as given (for the record) and why.
fn parse(head: &[u8]) -> Result<Request, (Vec<u8>, String)> {
    let err = |host: &[u8], why: &str| (host.to_vec(), why.to_string());
    let text = std::str::from_utf8(head).map_err(|_| err(b"", "request head is not UTF-8"))?;
    let mut lines = text.split("\r\n");
    let line = lines.next().unwrap_or("");
    let mut parts = line.split(' ');
    let (Some(method), Some(target), Some(version), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(err(b"", "malformed request line"));
    };
    if !version.starts_with("HTTP/1.") || method.is_empty() {
        return Err(err(b"", "malformed request line"));
    }
    let authority_of = |a: &str, default: Option<u16>| -> Result<(Host, u16), (Vec<u8>, String)> {
        let (host, port) = split_port(a).map_err(|why| err(a.as_bytes(), &why))?;
        let port = port
            .or(default)
            .ok_or_else(|| err(a.as_bytes(), "no port"))?;
        let host = Host::parse(host.as_bytes()).map_err(|e| err(a.as_bytes(), &e.to_string()))?;
        Ok((host, port))
    };
    if method == "CONNECT" {
        let (host, port) = authority_of(target, None)?;
        return Ok(Request {
            connect: true,
            host,
            port,
        });
    }
    let rest = target
        .get(..7)
        .filter(|s| s.eq_ignore_ascii_case("http://"))
        .map(|_| &target[7..])
        .ok_or_else(|| err(target.as_bytes(), "only CONNECT and http:// URIs"))?;
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    if authority.contains('@') {
        return Err(err(authority.as_bytes(), "userinfo in URI"));
    }
    let (host, port) = authority_of(authority, Some(80))?;
    let mut hosts = lines
        .take_while(|l| !l.is_empty())
        .filter_map(|l| l.split_once(':'))
        .filter(|(name, _)| name.trim().eq_ignore_ascii_case("host"))
        .map(|(_, value)| value.trim());
    let (Some(header), None) = (hosts.next(), hosts.next()) else {
        return Err(err(authority.as_bytes(), "not exactly one Host header"));
    };
    if authority_of(header, Some(80))? != (host.clone(), port) {
        return Err(err(header.as_bytes(), "Host header differs from the URI"));
    }
    Ok(Request {
        connect: false,
        host,
        port,
    })
}

fn refuse(shared: &Shared, client: &mut TcpStream, host: &[u8], port: u16, reason: Reason) {
    let status = if matches!(reason, Reason::Malformed(_)) {
        400
    } else {
        403
    };
    answer(client, status, &reason.to_string());
    shared.refuse(Refusal {
        host: shown(host),
        port,
        protocol: Protocol::Http,
        reason,
    });
}

fn answer(client: &mut TcpStream, status: u16, text: &str) {
    let phrase = match status {
        400 => "Bad Request",
        403 => "Forbidden",
        _ => "Request Header Fields Too Large",
    };
    let body = format!("procage-proxy: {text}\n");
    let _ = write!(
        client,
        "HTTP/1.1 {status} {phrase}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok(head: &str) -> (bool, Host, u16) {
        let r = parse(head.as_bytes()).unwrap_or_else(|e| panic!("{head}: {}", e.1));
        (r.connect, r.host, r.port)
    }

    #[test]
    fn requests_name_one_host() {
        let name = |s: &str| Host::Name(s.into());
        assert_eq!(
            ok("CONNECT ALLOWED.COM.:443 HTTP/1.1\r\n\r\n"),
            (true, name("allowed.com"), 443)
        );
        assert_eq!(
            ok("GET http://allowed.com/x HTTP/1.1\r\nHost: allowed.com\r\n\r\n"),
            (false, name("allowed.com"), 80)
        );
        assert_eq!(
            ok("GET HTTP://allowed.com:8080?q HTTP/1.1\r\nhost: Allowed.com:8080\r\n\r\n"),
            (false, name("allowed.com"), 8080)
        );
        assert_eq!(
            ok("CONNECT [::ffff:192.0.2.1]:443 HTTP/1.1\r\n\r\n"),
            (true, Host::Ip("192.0.2.1".parse().unwrap()), 443)
        );
    }

    #[test]
    fn what_could_be_read_two_ways_is_refused() {
        for head in [
            "CONNECT allowed.com HTTP/1.1\r\n\r\n",
            "CONNECT allowed.com%00.evil.com:443 HTTP/1.1\r\n\r\n",
            "CONNECT allowed.com:443  HTTP/1.1\r\n\r\n",
            "GET http://allowed.com/ HTTP/1.1\r\nHost: evil.com\r\n\r\n",
            "GET http://allowed.com/ HTTP/1.1\r\n\r\n",
            "GET http://allowed.com/ HTTP/1.1\r\nHost: allowed.com\r\nHost: evil.com\r\n\r\n",
            "GET http://user@allowed.com/ HTTP/1.1\r\nHost: allowed.com\r\n\r\n",
            "GET https://allowed.com/ HTTP/1.1\r\nHost: allowed.com\r\n\r\n",
            "GET /relative HTTP/1.1\r\nHost: allowed.com\r\n\r\n",
            "GET http://allowed.com:0/ HTTP/1.1\r\nHost: allowed.com:0\r\n\r\n",
            "CONNECT allowed.com:443 SPDY/3\r\n\r\n",
        ] {
            assert!(parse(head.as_bytes()).is_err(), "{}", head.escape_debug());
        }
    }
}
