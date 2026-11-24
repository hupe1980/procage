//! Bounds-checked parsers that name a flow's resource before it is relayed.
//!
//! TLS: a ClientHello may arrive in several `read`s and may span several TLS
//! records; the sniffer keeps at most 64 KiB and reports `NeedMore` until a
//! whole ClientHello is present. A missing SNI is not an error: the caller
//! falls back to the destination address. ECH (extension `0xfe0d`) is
//! reported so the relay can refuse visibly: the inner name is unavailable.
//!
//! HTTP: the request head is read up to 16 KiB; `Host` is canonicalized with
//! [`crate::Host::parse`], the same parser the proxy's allowlist uses.
//!
//! QUIC: `quic-parser` parses v1/v2 Initial headers, derives the client
//! Initial keys and decrypts the payload. CRYPTO frames are merged by offset
//! across datagrams (a large ClientHello spans several Initials), then the
//! TLS ClientHello inside the reassembled stream names the SNI.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use crate::Host;

use super::Resource;

/// The most bytes a TLS or HTTP sniffer keeps.
pub const MAX_SNIFF: usize = 64 * 1024;
/// The most bytes an HTTP request head may have.
pub const MAX_HTTP_HEAD: usize = 16 * 1024;
/// The most QUIC Initial datagrams tracked at once.
pub const MAX_QUIC_FLOWS: usize = 256;
/// The most reassembled CRYPTO bytes one QUIC flow keeps.
pub const MAX_QUIC_STREAM: usize = 64 * 1024;
/// The most CRYPTO frames one QUIC flow keeps.
pub const MAX_QUIC_FRAMES: usize = 64;

/// What a sniffer learned from the bytes so far.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Sniff {
    /// A whole unit is not here yet; feed more bytes.
    NeedMore,
    /// The unit named this resource.
    Named(Resource),
    /// The unit is complete but names no host (for example a TLS ClientHello
    /// without SNI, or a request without `Host`).
    NoName,
    /// The bytes look like this protocol but the unit is incomplete at the
    /// deadline/cap; the relay must fail closed rather than fall back to an
    /// address.
    Incomplete,
    /// The bytes look like this protocol but are malformed; fail closed.
    Malformed,
    /// ECH hides the destination name; the relay refuses the flow visibly.
    Ech,
    /// The bytes are not this protocol.
    NotThis,
}

/// A parsed ClientHello's policy-relevant fields.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ClientHello {
    /// The server name, if the client sent one.
    pub sni: Option<String>,
    /// ALPN protocol identifiers.
    pub alpn: Vec<Vec<u8>>,
    /// Whether the outer ECH extension is present.
    pub ech: bool,
}

/// TLS ClientHello accumulation across records and `read`s.
#[derive(Debug, Default)]
pub struct TlsSniffer {
    buf: Vec<u8>,
    done: bool,
}

impl TlsSniffer {
    /// A sniffer with an empty buffer.
    pub fn new() -> TlsSniffer {
        TlsSniffer::default()
    }

    /// The bytes read so far, in order; a relay replays them unchanged.
    pub fn buffered(&self) -> &[u8] {
        &self.buf
    }

    /// Feeds bytes and reports what the buffer now says.
    pub fn push(&mut self, bytes: &[u8]) -> Sniff {
        if self.done {
            return Sniff::NoName;
        }
        if self.buf.len() + bytes.len() > MAX_SNIFF {
            self.done = true;
            return if self.identified() {
                Sniff::Malformed
            } else {
                Sniff::NotThis
            };
        }
        self.buf.extend_from_slice(bytes);
        match parse_client_hello_stream(&self.buf) {
            TlsParse::Incomplete => Sniff::NeedMore,
            TlsParse::NotTls => {
                self.done = true;
                if self.identified() {
                    Sniff::Malformed
                } else {
                    Sniff::NotThis
                }
            }
            TlsParse::Malformed => {
                self.done = true;
                Sniff::Malformed
            }
            TlsParse::Hello(hello) => {
                self.done = true;
                if hello.ech {
                    return Sniff::Ech;
                }
                match hello
                    .sni
                    .as_deref()
                    .and_then(|s| Host::parse(s.as_bytes()).ok())
                {
                    Some(host) => Sniff::Named(Resource::from_host(&host)),
                    None => Sniff::NoName,
                }
            }
        }
    }

    /// Whether the bytes so far identify a TLS handshake: a record
    /// (`0x16`) or a raw ClientHello (`0x01`).
    pub fn identified(&self) -> bool {
        self.buf
            .first()
            .is_some_and(|byte| matches!(byte, 0x16 | 0x01))
    }

    /// Whether the last ClientHello carried ECH.
    pub fn ech(&self) -> bool {
        matches!(parse_client_hello_stream(&self.buf), TlsParse::Hello(h) if h.ech)
    }
}

/// The result of parsing a TLS byte stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TlsParse {
    /// Not enough bytes for a whole ClientHello.
    Incomplete,
    /// The first record is not a TLS handshake record.
    NotTls,
    /// A length or a field is impossible.
    Malformed,
    /// A whole ClientHello.
    Hello(ClientHello),
}

/// Parses one or more TLS records that together hold a ClientHello. A raw
/// handshake message (`0x01 ...`, the shape inside QUIC CRYPTO frames) is
/// accepted too.
pub fn parse_client_hello_stream(data: &[u8]) -> TlsParse {
    if data.is_empty() {
        return TlsParse::Incomplete;
    }
    if data[0] == 0x01 {
        return parse_handshake(data);
    }
    if data[0] != 0x16 {
        return TlsParse::NotTls;
    }
    let mut at = 0usize;
    let mut handshake = Vec::new();
    while at < data.len() {
        if data.len() - at < 5 {
            return TlsParse::Incomplete;
        }
        if data[at] != 0x16 {
            // A later record type ends the handshake flight.
            break;
        }
        let len = u16::from_be_bytes([data[at + 3], data[at + 4]]) as usize;
        if len > MAX_SNIFF {
            return TlsParse::Malformed;
        }
        if data.len() - at - 5 < len {
            return TlsParse::Incomplete;
        }
        handshake.extend_from_slice(&data[at + 5..at + 5 + len]);
        at += 5 + len;
        if handshake.len() >= 4 {
            let hs_len = u24(&handshake, 1);
            if handshake.len() >= 4 + hs_len {
                return parse_handshake(&handshake);
            }
        }
        if handshake.len() > MAX_SNIFF {
            return TlsParse::Malformed;
        }
    }
    TlsParse::Incomplete
}

fn parse_handshake(data: &[u8]) -> TlsParse {
    if data.len() < 4 {
        return TlsParse::Incomplete;
    }
    if data[0] != 0x01 {
        return TlsParse::NotTls;
    }
    let len = u24(data, 1);
    if len > MAX_SNIFF {
        return TlsParse::Malformed;
    }
    if data.len() < 4 + len {
        return TlsParse::Incomplete;
    }
    parse_client_hello(&data[4..4 + len])
        .map(TlsParse::Hello)
        .unwrap_or(TlsParse::Malformed)
}

fn u24(data: &[u8], at: usize) -> usize {
    ((data[at] as usize) << 16) | ((data[at + 1] as usize) << 8) | data[at + 2] as usize
}

fn u16_at(data: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*data.get(at)?, *data.get(at + 1)?]))
}

fn u8_at(data: &[u8], at: usize) -> Option<u8> {
    data.get(at).copied()
}

fn take<'a>(data: &'a [u8], at: &mut usize, n: usize) -> Option<&'a [u8]> {
    let end = at.checked_add(n)?;
    let out = data.get(*at..end)?;
    *at = end;
    Some(out)
}

/// Parses the body of a ClientHello (without the handshake header).
pub fn parse_client_hello(body: &[u8]) -> Option<ClientHello> {
    let mut at = 0usize;
    take(body, &mut at, 2 + 32)?; // legacy_version, random
    let session = u8_at(body, at)? as usize;
    at += 1;
    take(body, &mut at, session)?;
    let ciphers = u16_at(body, at)? as usize;
    at += 2;
    take(body, &mut at, ciphers)?;
    let compression = u8_at(body, at)? as usize;
    at += 1;
    take(body, &mut at, compression)?;
    let mut hello = ClientHello::default();
    if at == body.len() {
        return Some(hello);
    }
    let total = u16_at(body, at)? as usize;
    at += 2;
    let ext_end = at.checked_add(total)?;
    if ext_end > body.len() {
        return None;
    }
    while at < ext_end {
        let kind = u16_at(body, at)?;
        let len = u16_at(body, at + 2)? as usize;
        at += 4;
        let ext = take(body, &mut at, len)?;
        match kind {
            0x0000 => {
                let list = u16_at(ext, 0)? as usize;
                if 2 + list > ext.len() {
                    return None;
                }
                let mut q = 2usize;
                while q < 2 + list {
                    let name_type = u8_at(ext, q)?;
                    let name_len = u16_at(ext, q + 1)? as usize;
                    q += 3;
                    let name = take(ext, &mut q, name_len)?;
                    if name_type == 0 && hello.sni.is_none() {
                        hello.sni = std::str::from_utf8(name).ok().map(str::to_string);
                    }
                }
            }
            0x0010 => {
                let list = u16_at(ext, 0)? as usize;
                if 2 + list > ext.len() {
                    return None;
                }
                let mut q = 2usize;
                while q < 2 + list {
                    let n = u8_at(ext, q)? as usize;
                    q += 1;
                    hello.alpn.push(take(ext, &mut q, n)?.to_vec());
                }
            }
            0xfe0d => hello.ech = true,
            _ => {}
        }
    }
    Some(hello)
}

/// HTTP request-head accumulation.
#[derive(Debug, Default)]
pub struct HttpSniffer {
    buf: Vec<u8>,
    done: bool,
}

impl HttpSniffer {
    /// A sniffer with an empty buffer.
    pub fn new() -> HttpSniffer {
        HttpSniffer::default()
    }

    /// The bytes read so far.
    pub fn buffered(&self) -> &[u8] {
        &self.buf
    }

    /// Feeds bytes until the request head ends.
    pub fn push(&mut self, bytes: &[u8]) -> Sniff {
        if self.done {
            return Sniff::NoName;
        }
        if self.buf.len() + bytes.len() > MAX_HTTP_HEAD {
            self.done = true;
            return if self.looks_like_http() {
                Sniff::Malformed
            } else {
                Sniff::NotThis
            };
        }
        self.buf.extend_from_slice(bytes);
        if let Some(end) = find_head_end(&self.buf) {
            self.done = true;
            return match parse_http_head(&self.buf[..end]) {
                Ok(Some(host)) => Sniff::Named(Resource::from_host(&host)),
                Ok(None) => Sniff::NoName,
                Err(()) => Sniff::Malformed,
            };
        }
        Sniff::NeedMore
    }

    /// Whether the bytes look like an HTTP request line (an uppercase method
    /// at the start).
    pub fn looks_like_http(&self) -> bool {
        self.buf
            .first()
            .is_some_and(|byte| byte.is_ascii_uppercase())
    }
}

fn find_head_end(data: &[u8]) -> Option<usize> {
    data.windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|i| i + 4)
}

/// `Ok(Some(host))` for a request with a valid `Host`, `Ok(None)` for a valid
/// request without one (or a `CONNECT`, whose proxy is the destination), and
/// `Err(())` for a malformed request line or host.
fn parse_http_head(head: &[u8]) -> Result<Option<Host>, ()> {
    let text = std::str::from_utf8(head).map_err(|_| ())?;
    let mut lines = text.split("\r\n");
    let request = lines.next().ok_or(())?;
    let mut parts = request.split(' ');
    let method = parts.next().ok_or(())?;
    let _target = parts.next().ok_or(())?;
    let version = parts.next().ok_or(())?;
    if !method.bytes().all(|b| b.is_ascii_uppercase()) || !version.starts_with("HTTP/") {
        return Err(());
    }
    // An external proxy is a destination, never its CONNECT target: the
    // relay authorizes the proxy address/SNI, not what the proxy will reach.
    if method == "CONNECT" {
        return Ok(None);
    }
    for line in lines {
        if line.is_empty() {
            break;
        }
        let (name, value) = line.split_once(':').ok_or(())?;
        if name.eq_ignore_ascii_case("host") {
            let value = value.trim();
            let host = strip_port(value).ok_or(())?;
            return Host::parse(host.as_bytes()).map(Some).map_err(|_| ());
        }
    }
    Ok(None)
}

fn strip_port(value: &str) -> Option<&str> {
    if let Some(rest) = value.strip_prefix('[') {
        let (inside, after) = rest.split_once(']')?;
        if after.is_empty() || after.starts_with(':') {
            return Some(&value[..=inside.len() + 1]);
        }
        return None;
    }
    match value.rsplit_once(':') {
        Some((host, port)) if port.bytes().all(|b| b.is_ascii_digit()) => Some(host),
        _ => Some(value),
    }
}

/// One QUIC flow's reassembled CRYPTO stream, keyed by client and server
/// addresses.
#[derive(Debug)]
struct QuicFlow {
    frames: Vec<(u64, Vec<u8>)>,
    last: Instant,
    named: Option<Resource>,
}

/// QUIC Initial inspection with per-flow CRYPTO reassembly.
#[derive(Debug, Default)]
pub struct QuicInspector {
    flows: HashMap<(SocketAddr, SocketAddr), QuicFlow>,
}

impl QuicInspector {
    /// An inspector with no flows.
    pub fn new() -> QuicInspector {
        QuicInspector::default()
    }

    /// Forgets flows idle for longer than `idle`.
    pub fn expire(&mut self, idle: Duration) {
        let now = Instant::now();
        self.flows
            .retain(|_, flow| now.duration_since(flow.last) < idle);
    }

    /// Inspects one datagram from `client` to `server`. `Named` once a
    /// ClientHello names a host; `NeedMore` if this Initial carries only part
    /// of one; `NotThis` if it is not a decryptable QUIC v1/v2 Initial.
    pub fn push(&mut self, datagram: &[u8], client: SocketAddr, server: SocketAddr) -> Sniff {
        if datagram.first().is_none_or(|byte| byte & 0x80 == 0) {
            // Short header or empty: no Initial, hence no SNI. Clearly not a
            // Client Initial, so the address may be asked for.
            return Sniff::NotThis;
        }
        if self.flows.len() >= MAX_QUIC_FLOWS && !self.flows.contains_key(&(client, server)) {
            self.expire(Duration::from_secs(30));
            if self.flows.len() >= MAX_QUIC_FLOWS {
                return Sniff::Malformed;
            }
        }
        let header = match quic_parser::parse_initial(datagram) {
            Ok(header) => header,
            Err(quic_parser::Error::BufferTooShort { .. }) => return Sniff::NeedMore,
            Err(quic_parser::Error::NotLongHeader | quic_parser::Error::NotInitialPacket(_)) => {
                return Sniff::NotThis;
            }
            Err(_) => return Sniff::Malformed,
        };
        let plain = match quic_parser::decrypt_initial(&header) {
            Ok(plain) => plain,
            Err(_) => return Sniff::Malformed,
        };
        let frames = match quic_parser::parse_crypto_frames(&plain) {
            Ok(frames) => frames,
            Err(_) => return Sniff::Malformed,
        };
        let flow = self
            .flows
            .entry((client, server))
            .or_insert_with(|| QuicFlow {
                frames: Vec::new(),
                last: Instant::now(),
                named: None,
            });
        flow.last = Instant::now();
        if let Some(named) = &flow.named {
            return Sniff::Named(named.clone());
        }
        for frame in frames {
            let offset = frame.offset;
            let data = frame.data.to_vec();
            if data.len() > MAX_QUIC_STREAM {
                return Sniff::Malformed;
            }
            if flow
                .frames
                .iter()
                .any(|(o, d)| *o == offset && d.as_slice() == data)
            {
                continue;
            }
            if flow.frames.len() >= MAX_QUIC_FRAMES {
                return Sniff::Malformed;
            }
            flow.frames.push((offset, data));
        }
        let stream = reassemble(&flow.frames);
        match parse_client_hello_stream(&stream) {
            TlsParse::Incomplete => Sniff::NeedMore,
            TlsParse::Hello(hello) => {
                if hello.ech {
                    return Sniff::Ech;
                }
                match hello
                    .sni
                    .as_deref()
                    .and_then(|s| Host::parse(s.as_bytes()).ok())
                {
                    Some(host) => {
                        let resource = Resource::from_host(&host);
                        flow.named = Some(resource.clone());
                        Sniff::Named(resource)
                    }
                    None => Sniff::NoName,
                }
            }
            TlsParse::NotTls | TlsParse::Malformed => Sniff::Malformed,
        }
    }
}

fn reassemble(frames: &[(u64, Vec<u8>)]) -> Vec<u8> {
    let mut sorted: Vec<&(u64, Vec<u8>)> = frames.iter().collect();
    sorted.sort_by_key(|(offset, _)| *offset);
    let mut out = Vec::new();
    for (offset, data) in sorted {
        let Ok(offset) = usize::try_from(*offset) else {
            break;
        };
        if offset > out.len() {
            break;
        }
        if offset + data.len() > MAX_QUIC_STREAM {
            break;
        }
        if offset == out.len() {
            out.extend_from_slice(data);
        } else {
            // Overlapping retransmission: extend only the unseen suffix.
            let end = offset + data.len();
            if end > out.len() {
                out.extend_from_slice(&data[out.len() - offset..]);
            }
        }
    }
    out
}

/// Which payload a TCP relay should try to name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Inspect {
    /// TLS ClientHello (port 443, or any port after HTTP failed).
    Tls,
    /// HTTP request head (port 80 and common alternates).
    Http,
    /// No protocol parser: use the destination address.
    Address,
}

impl Inspect {
    /// The parser a destination port starts with.
    pub fn for_port(port: u16) -> Inspect {
        match port {
            443 | 8443 | 9443 | 4443 => Inspect::Tls,
            80 | 8080 | 8000 | 8888 | 3000 | 5000 => Inspect::Http,
            _ => Inspect::Tls,
        }
    }
}

/// The resource for a flow whose parser found no name: its destination IP.
pub fn address_resource(ip: IpAddr) -> Resource {
    Resource::Ip(ip)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tls_hello(sni: &str, ech: bool) -> Vec<u8> {
        let mut ext = Vec::new();
        // server_name
        let name = sni.as_bytes();
        let mut sn = Vec::new();
        sn.extend_from_slice(&((name.len() + 3) as u16).to_be_bytes());
        sn.push(0);
        sn.extend_from_slice(&(name.len() as u16).to_be_bytes());
        sn.extend_from_slice(name);
        ext.extend_from_slice(&0u16.to_be_bytes());
        ext.extend_from_slice(&(sn.len() as u16).to_be_bytes());
        ext.extend_from_slice(&sn);
        if ech {
            ext.extend_from_slice(&0xfe0du16.to_be_bytes());
            ext.extend_from_slice(&4u16.to_be_bytes());
            ext.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
        }
        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]);
        body.extend_from_slice(&[7u8; 32]);
        body.push(0);
        body.extend_from_slice(&2u16.to_be_bytes());
        body.extend_from_slice(&[0x13, 0x01]);
        body.push(1);
        body.push(0);
        body.extend_from_slice(&(ext.len() as u16).to_be_bytes());
        body.extend_from_slice(&ext);
        let mut hs = Vec::new();
        hs.push(1);
        hs.extend_from_slice(&((body.len() as u32).to_be_bytes()[1..]));
        hs.extend_from_slice(&body);
        let mut record = Vec::new();
        record.push(0x16);
        record.extend_from_slice(&[0x03, 0x01]);
        record.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        record.extend_from_slice(&hs);
        record
    }

    #[test]
    fn tls_sni_survives_arbitrary_read_boundaries() {
        let hello = tls_hello("allowed.example", false);
        for chunk in [1, 2, 3, 7, 64] {
            let mut sniffer = TlsSniffer::new();
            let mut saw = Sniff::NeedMore;
            for part in hello.chunks(chunk) {
                saw = sniffer.push(part);
                if saw != Sniff::NeedMore {
                    break;
                }
            }
            assert_eq!(
                saw,
                Sniff::Named(Resource::Domain("allowed.example".into())),
                "chunk {chunk}"
            );
        }
    }

    #[test]
    fn tls_ech_is_reported_not_named() {
        let hello = tls_hello("public.example", true);
        let mut sniffer = TlsSniffer::new();
        assert_eq!(sniffer.push(&hello), Sniff::Ech);
        assert!(sniffer.ech());
    }

    #[test]
    fn tls_looking_partial_and_malformed_are_not_ip_fallbacks() {
        let mut partial = TlsSniffer::new();
        assert_eq!(
            partial.push(&[0x16, 0x03, 0x01, 0x40, 0x00, 0x01]),
            Sniff::NeedMore
        );
        assert!(partial.identified());
        let mut malformed = TlsSniffer::new();
        assert_eq!(
            malformed.push(&[0x16, 0x03, 0x01, 0x00, 0x08, 0x01, 0, 0, 4, 0, 0, 0, 0]),
            Sniff::Malformed
        );
        let mut not_tls = TlsSniffer::new();
        assert_eq!(not_tls.push(b"ping"), Sniff::NotThis);
        assert!(!not_tls.identified());
    }

    #[test]
    fn http_looking_malformed_is_not_an_ip_fallback() {
        let mut sniffer = HttpSniffer::new();
        assert_eq!(
            sniffer.push(b"GET / HTTP/1.1\r\nHost: bad host\r\n\r\n"),
            Sniff::Malformed
        );
        assert_eq!(sniffer.push(b"ping"), Sniff::NoName);
    }

    #[test]
    fn tls_handshake_split_across_records() {
        let hello = tls_hello("split.example", false);
        let split = 20;
        let mut first = vec![0x16, 0x03, 0x01, 0, 0];
        let a = &hello[5..5 + split];
        let b = &hello[5 + split..];
        first[3..5].copy_from_slice(&(a.len() as u16).to_be_bytes());
        first.extend_from_slice(a);
        let mut second = vec![0x16, 0x03, 0x01, 0, 0];
        second[3..5].copy_from_slice(&(b.len() as u16).to_be_bytes());
        second.extend_from_slice(b);
        let mut sniffer = TlsSniffer::new();
        assert_eq!(sniffer.push(&first), Sniff::NeedMore);
        assert_eq!(
            sniffer.push(&second),
            Sniff::Named(Resource::Domain("split.example".into()))
        );
    }

    #[test]
    fn http_host_is_canonical() {
        let mut sniffer = HttpSniffer::new();
        assert_eq!(sniffer.push(b"GET / HTTP/1.1\r\nHo"), Sniff::NeedMore);
        assert_eq!(
            sniffer.push(b"st: ALLOWED.Example:8080\r\n\r\n"),
            Sniff::Named(Resource::Domain("allowed.example".into()))
        );
    }

    #[test]
    fn http_without_host_has_no_name() {
        let mut sniffer = HttpSniffer::new();
        assert_eq!(
            sniffer.push(b"GET / HTTP/1.1\r\nUser-Agent: x\r\n\r\n"),
            Sniff::NoName
        );
    }

    #[test]
    fn connect_target_is_not_the_resource() {
        // The proxy is the destination; its CONNECT target must not be
        // authorized in its place.
        let mut sniffer = HttpSniffer::new();
        assert_eq!(
            sniffer.push(
                b"CONNECT upstream.example:443 HTTP/1.1\r\nHost: upstream.example:443\r\n\r\n"
            ),
            Sniff::NoName
        );
    }

    #[test]
    fn reassembly_handles_gaps_and_overlap() {
        assert_eq!(
            reassemble(&[(0, b"abc".to_vec()), (3, b"def".to_vec())]),
            b"abcdef"
        );
        assert_eq!(
            reassemble(&[(0, b"abcdef".to_vec()), (3, b"defghi".to_vec())]),
            b"abcdefghi"
        );
        assert_eq!(reassemble(&[(3, b"def".to_vec())]), b"");
    }
}
